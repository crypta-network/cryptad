package network.crypta.platform.appcatalog;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CatalogReviewerScopeStoreTest {
  private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");
  private static final String REVIEWER_SET_DIGEST = "7".repeat(64);
  private static final String BUNDLE_DIGEST = "8".repeat(64);
  private static final String REVIEWER_SCOPES = "reviewer-scopes";
  private static final String CATALOG_REVIEWERS_SCOPE_ID = "catalog-reviewers";
  private static final String CATALOG_APP_REVIEWERS_SCOPE_ID = "catalog-app-reviewers";
  private static final String OTHER_CATALOG_REVIEWERS_SCOPE_ID = "other-catalog-reviewers";
  private static final String APP_ID = "federated-app";
  private static final String CATALOG_ID = "independent-catalog";
  private static final String OTHER_CATALOG_ID = "other-catalog";
  private static final String REVIEWER_KEY_ID = "reviewer-2026";
  private static final String SIGNATURE_ALGORITHM = "Ed25519";

  @TempDir private Path tempDir;

  @Test
  void findEffective_whenAppOverrideExists_expectExactScopeAfterRestart() throws Exception {
    KeyPair reviewer = keyPair();
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    CatalogReviewerScope catalogWide = scope(CATALOG_REVIEWERS_SCOPE_ID, null, reviewer);
    CatalogReviewerScope appSpecific = scope(CATALOG_APP_REVIEWERS_SCOPE_ID, APP_ID, reviewer);

    store.put(catalogWide);
    store.put(appSpecific);
    FileCatalogReviewerScopeStore restarted =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));

    assertEquals(appSpecific, restarted.findEffective(CATALOG_ID, APP_ID).orElseThrow());
    assertEquals(catalogWide, restarted.findEffective(CATALOG_ID, "another-app").orElseThrow());
  }

  @Test
  void authorizes_whenCatalogAppDigestOrLifecycleDiffers_expectFailClosed() throws Exception {
    KeyPair reviewer = keyPair();
    CatalogReviewerScope active = scope(CATALOG_APP_REVIEWERS_SCOPE_ID, APP_ID, reviewer);
    String fingerprint = PublicKeyFingerprint.sha256(reviewer.getPublic());

    assertTrue(
        active.authorizes(CATALOG_ID, APP_ID, REVIEWER_KEY_ID, fingerprint, REVIEWER_SET_DIGEST));
    assertFalse(
        active.authorizes(
            OTHER_CATALOG_ID, APP_ID, REVIEWER_KEY_ID, fingerprint, REVIEWER_SET_DIGEST));
    assertFalse(
        active.authorizes(
            CATALOG_ID, "other-app", REVIEWER_KEY_ID, fingerprint, REVIEWER_SET_DIGEST));
    assertFalse(
        active.authorizes(CATALOG_ID, APP_ID, REVIEWER_KEY_ID, fingerprint, "9".repeat(64)));
  }

  @Test
  void policySemanticDigest_whenOnlyLocalScopeIdentityDiffers_expectEquivalentPolicy()
      throws Exception {
    KeyPair reviewer = keyPair();
    CatalogReviewerScope first = scope("catalog-a-reviewers", null, reviewer, "catalog-a");
    CatalogReviewerScope second = scope("catalog-b-app-reviewers", APP_ID, reviewer, "catalog-b");
    CatalogReviewerScope differentReviewers =
        scope("catalog-c-reviewers", null, keyPair(), "catalog-c");

    assertNotEquals(first.selfDigest(), second.selfDigest());
    assertEquals(first.policySemanticDigestSha256(), second.policySemanticDigestSha256());
    assertNotEquals(
        first.policySemanticDigestSha256(), differentReviewers.policySemanticDigestSha256());
  }

  @Test
  void put_whenStableIdMovesToAnotherCatalogOrAppScope_expectRejected() throws Exception {
    KeyPair reviewer = keyPair();
    CatalogReviewerScope original = scope(CATALOG_APP_REVIEWERS_SCOPE_ID, APP_ID, reviewer);
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    store.put(original);
    CatalogReviewerScope otherCatalogScope =
        scope(original.scopeId(), APP_ID, reviewer, OTHER_CATALOG_ID);
    CatalogReviewerScope otherAppScope = scope(original.scopeId(), "other-app", reviewer);

    assertThrows(AppCatalogException.class, () -> store.put(otherCatalogScope));
    assertThrows(AppCatalogException.class, () -> store.put(otherAppScope));
    assertEquals(original, store.find(original.scopeId()).orElseThrow());
  }

  @Test
  void put_whenRevokedScopeMovesToNonRevokedState_expectRejected() throws Exception {
    KeyPair reviewer = keyPair();
    CatalogReviewerScope revoked =
        scope(
            CATALOG_APP_REVIEWERS_SCOPE_ID,
            APP_ID,
            reviewer,
            CATALOG_ID,
            CatalogReviewerScope.Status.REVOKED);
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    store.put(revoked);
    List<CatalogReviewerScope.Status> replacements =
        List.of(
            CatalogReviewerScope.Status.PENDING,
            CatalogReviewerScope.Status.ACTIVE,
            CatalogReviewerScope.Status.SUSPENDED,
            CatalogReviewerScope.Status.REMOVED);

    for (CatalogReviewerScope.Status status : replacements) {
      CatalogReviewerScope replacement =
          scope(CATALOG_APP_REVIEWERS_SCOPE_ID, APP_ID, reviewer, CATALOG_ID, status);
      assertThrows(AppCatalogException.class, () -> store.put(replacement));
    }

    assertEquals(revoked, store.find(revoked.scopeId()).orElseThrow());
  }

  @Test
  void retainAuthorization_whenScopeSuspensionStarts_expectUpdateWaitsForLease() throws Exception {
    KeyPair reviewer = keyPair();
    CatalogReviewerScope active = scope(CATALOG_APP_REVIEWERS_SCOPE_ID, APP_ID, reviewer);
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    store.put(active);
    FileCatalogReviewerScopeStore.AuthorizationLease authorization = store.retainAuthorization();
    FileCatalogReviewerScopeStore independentWriter =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    CompletableFuture<Void> suspension =
        CompletableFuture.runAsync(
            () -> {
              try {
                independentWriter.put(
                    scope(
                        active.scopeId(),
                        active.appId().orElse(null),
                        reviewer,
                        active.catalogId(),
                        CatalogReviewerScope.Status.SUSPENDED));
              } catch (java.io.IOException exception) {
                throw new AssertionError(exception);
              }
            });
    try {
      assertThrows(TimeoutException.class, () -> suspension.get(100, TimeUnit.MILLISECONDS));
    } finally {
      authorization.close();
    }

    suspension.get(5, TimeUnit.SECONDS);
    assertEquals(
        CatalogReviewerScope.Status.SUSPENDED, store.find(active.scopeId()).orElseThrow().status());
  }

  @Test
  void list_whenRecordDigestChanges_expectClosedParsingFailure() throws Exception {
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    CatalogReviewerScope scope = scope(CATALOG_REVIEWERS_SCOPE_ID, null, keyPair());
    store.put(scope);
    Path recordPath =
        tempDir.resolve(REVIEWER_SCOPES).resolve(CATALOG_REVIEWERS_SCOPE_ID + ".properties");
    Files.writeString(
        recordPath,
        Files.readString(recordPath, StandardCharsets.UTF_8)
            .replace("reason=approved", "reason=changed"),
        StandardCharsets.UTF_8);

    AppCatalogException exception = assertThrows(AppCatalogException.class, store::list);

    assertTrue(exception.getMessage().contains("self-digest mismatch"));
    assertThrows(AppCatalogException.class, () -> store.findEffective(CATALOG_ID, APP_ID));
  }

  @Test
  void findEffective_whenAnotherCatalogRecordIsCorrupt_expectScopedIsolation() throws Exception {
    Path root = tempDir.resolve("reviewer-scopes-isolation");
    FileCatalogReviewerScopeStore store = new FileCatalogReviewerScopeStore(root);
    CatalogReviewerScope expected = scope(CATALOG_REVIEWERS_SCOPE_ID, null, keyPair());
    store.put(expected);
    CatalogReviewerScope other =
        scope(OTHER_CATALOG_REVIEWERS_SCOPE_ID, null, keyPair(), OTHER_CATALOG_ID);
    store.put(other);
    String expectedDigest = store.policyDigest(CATALOG_ID);
    Path otherRecord = root.resolve(other.scopeId() + ".properties");
    Files.writeString(
        otherRecord,
        Files.readString(otherRecord, StandardCharsets.UTF_8)
            .replace("reason=approved", "reason=changed"),
        StandardCharsets.UTF_8);

    assertEquals(expected, store.findEffective(CATALOG_ID, APP_ID).orElseThrow());
    assertEquals(expectedDigest, store.policyDigest(CATALOG_ID));
    assertThrows(AppCatalogException.class, store::list);
  }

  @Test
  void policyDigest_whenUnrelatedCatalogChanges_expectCatalogDigestUnchanged() throws Exception {
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    store.put(scope(CATALOG_REVIEWERS_SCOPE_ID, null, keyPair()));
    String originalDigest = store.policyDigest(CATALOG_ID);
    store.put(scope(OTHER_CATALOG_REVIEWERS_SCOPE_ID, null, keyPair(), OTHER_CATALOG_ID));

    assertEquals(originalDigest, store.policyDigest(CATALOG_ID));
  }

  @Test
  void evaluate_whenReceiptAndLocalScopeMatch_expectAuthorized() throws Exception {
    KeyPair reviewer = keyPair();
    AppReviewReceipt receipt = receipt(reviewer);
    AppCatalogEntry entry = entry(receipt);
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    CatalogReviewerScope scope = scope(CATALOG_APP_REVIEWERS_SCOPE_ID, APP_ID, reviewer);
    store.put(scope);
    CatalogScopedReviewerPolicy policy = new CatalogScopedReviewerPolicy(store);
    TrustedReviewerKeys keys =
        TrustedReviewerKeys.of(
            new TrustedReviewerKey(
                REVIEWER_KEY_ID,
                SIGNATURE_ALGORITHM,
                reviewer.getPublic(),
                Optional.empty(),
                TrustedReviewerPolicyConstraint.ANY,
                TrustedReviewerKeyLifecycle.ACTIVE));

    CatalogScopedReviewerPolicy.Verification verification =
        policy.evaluate(CATALOG_ID, entry, REVIEWER_SET_DIGEST, keys, AppReviewPolicy.DEFAULT, NOW);

    assertTrue(verification.authorized());
    assertEquals(scope.selfDigest(), verification.scopeDigestSha256());
    assertEquals(scope.policySemanticDigestSha256(), verification.policySemanticDigestSha256());
    assertEquals("authorized", verification.status());
  }

  @Test
  void retainAuthorization_whenScopeSuspensionStarts_expectDecisionHeldThroughCommit()
      throws Exception {
    KeyPair reviewer = keyPair();
    AppCatalogEntry entry = entry(receipt(reviewer));
    Path root = tempDir.resolve("routine-reviewer-scopes");
    FileCatalogReviewerScopeStore store = new FileCatalogReviewerScopeStore(root);
    CatalogReviewerScope active = scope(CATALOG_APP_REVIEWERS_SCOPE_ID, APP_ID, reviewer);
    store.put(active);
    CatalogScopedReviewerPolicy policy = new CatalogScopedReviewerPolicy(store);
    CatalogScopedReviewerPolicy.RoutineAuthorization authorization =
        policy.retainAuthorization(
            CATALOG_ID, entry, trustedReviewerKeys(reviewer), AppReviewPolicy.DEFAULT, NOW);
    FileCatalogReviewerScopeStore independentWriter = new FileCatalogReviewerScopeStore(root);
    CompletableFuture<Void> suspension =
        CompletableFuture.runAsync(
            () -> {
              try {
                independentWriter.put(
                    scope(
                        active.scopeId(),
                        active.appId().orElse(null),
                        reviewer,
                        active.catalogId(),
                        CatalogReviewerScope.Status.SUSPENDED));
              } catch (java.io.IOException exception) {
                throw new AssertionError(exception);
              }
            });
    try {
      assertTrue(authorization.verification().authorized());
      assertThrows(TimeoutException.class, () -> suspension.get(100, TimeUnit.MILLISECONDS));
    } finally {
      authorization.close();
    }

    suspension.get(5, TimeUnit.SECONDS);
    assertEquals(
        CatalogReviewerScope.Status.SUSPENDED, store.find(active.scopeId()).orElseThrow().status());
  }

  @Test
  void evaluateHistorical_whenScopeIsSuspended_expectOnlyHistoricalAuthorization()
      throws Exception {
    KeyPair reviewer = keyPair();
    AppCatalogEntry entry = entry(receipt(reviewer));
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve("historical-reviewer-scopes"));
    CatalogReviewerScope scope =
        scope(
            "suspended-catalog-app-reviewers",
            APP_ID,
            reviewer,
            CATALOG_ID,
            CatalogReviewerScope.Status.SUSPENDED);
    store.put(scope);
    CatalogScopedReviewerPolicy policy = new CatalogScopedReviewerPolicy(store);
    TrustedReviewerKeys keys = trustedReviewerKeys(reviewer);

    CatalogScopedReviewerPolicy.Verification routine =
        policy.evaluate(CATALOG_ID, entry, REVIEWER_SET_DIGEST, keys, AppReviewPolicy.DEFAULT, NOW);
    CatalogScopedReviewerPolicy.Verification historical =
        policy.evaluateHistorical(
            CATALOG_ID, entry, REVIEWER_SET_DIGEST, keys, AppReviewPolicy.DEFAULT, NOW);

    assertFalse(routine.authorized());
    assertEquals("reviewer_scope_rejected", routine.status());
    assertTrue(historical.authorized());
    assertEquals(scope.selfDigest(), historical.scopeDigestSha256());
  }

  @Test
  void authorizesHistorical_whenScopeIsNotActiveOrSuspended_expectRejected() throws Exception {
    KeyPair reviewer = keyPair();
    String fingerprint = PublicKeyFingerprint.sha256(reviewer.getPublic());

    for (CatalogReviewerScope.Status status :
        List.of(
            CatalogReviewerScope.Status.PENDING,
            CatalogReviewerScope.Status.REVOKED,
            CatalogReviewerScope.Status.REMOVED)) {
      CatalogReviewerScope scope =
          scope(
              "historical-" + status.name().toLowerCase(Locale.ROOT),
              APP_ID,
              reviewer,
              CATALOG_ID,
              status);

      assertFalse(
          scope.authorizesHistorical(
              CATALOG_ID, APP_ID, REVIEWER_KEY_ID, fingerprint, REVIEWER_SET_DIGEST));
    }
  }

  @Test
  void evaluate_whenReviewerIsOnlyScopedToAnotherCatalog_expectRejected() throws Exception {
    KeyPair reviewer = keyPair();
    AppCatalogEntry entry = entry(receipt(reviewer));
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(tempDir.resolve(REVIEWER_SCOPES));
    store.put(scope(OTHER_CATALOG_REVIEWERS_SCOPE_ID, null, reviewer, OTHER_CATALOG_ID));
    CatalogScopedReviewerPolicy policy = new CatalogScopedReviewerPolicy(store);
    TrustedReviewerKeys keys =
        TrustedReviewerKeys.of(
            new TrustedReviewerKey(
                REVIEWER_KEY_ID,
                SIGNATURE_ALGORITHM,
                reviewer.getPublic(),
                Optional.empty(),
                TrustedReviewerPolicyConstraint.ANY,
                TrustedReviewerKeyLifecycle.ACTIVE));

    CatalogScopedReviewerPolicy.Verification verification =
        policy.evaluate(CATALOG_ID, entry, REVIEWER_SET_DIGEST, keys, AppReviewPolicy.DEFAULT, NOW);

    assertFalse(verification.authorized());
    assertEquals("reviewer_scope_missing", verification.status());
  }

  private CatalogReviewerScope scope(String scopeId, String appId, KeyPair reviewer) {
    return scope(scopeId, appId, reviewer, CATALOG_ID);
  }

  private CatalogReviewerScope scope(
      String scopeId, String appId, KeyPair reviewer, String catalogId) {
    return scope(scopeId, appId, reviewer, catalogId, CatalogReviewerScope.Status.ACTIVE);
  }

  private CatalogReviewerScope scope(
      String scopeId,
      String appId,
      KeyPair reviewer,
      String catalogId,
      CatalogReviewerScope.Status status) {
    return CatalogReviewerScope.create(
        scopeId,
        catalogId,
        appId,
        Map.of(REVIEWER_KEY_ID, PublicKeyFingerprint.sha256(reviewer.getPublic())),
        REVIEWER_SET_DIGEST,
        status,
        NOW.minusSeconds(60),
        NOW,
        "approved",
        "local-operator");
  }

  private static TrustedReviewerKeys trustedReviewerKeys(KeyPair reviewer) {
    return TrustedReviewerKeys.of(
        new TrustedReviewerKey(
            REVIEWER_KEY_ID,
            SIGNATURE_ALGORITHM,
            reviewer.getPublic(),
            Optional.empty(),
            TrustedReviewerPolicyConstraint.ANY,
            TrustedReviewerKeyLifecycle.ACTIVE));
  }

  private static AppReviewReceipt receipt(KeyPair reviewer) {
    return AppReviewReceiptSigner.sign(
        new AppReviewReceiptPayload(
            AppReviewReceiptPayload.RECEIPT_VERSION,
            APP_ID,
            "1.0.0",
            BUNDLE_DIGEST,
            42L,
            Optional.empty(),
            "local-review",
            "1",
            AppReviewReceiptStatus.REVIEWED,
            REVIEWER_KEY_ID,
            NOW.minusSeconds(30),
            Optional.of(NOW.plusSeconds(3600)),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty()),
        reviewer.getPrivate());
  }

  private static AppCatalogEntry entry(AppReviewReceipt receipt) {
    return new AppCatalogEntry(
        APP_ID,
        "Federated App",
        "1.0.0",
        "Scoped reviewer test app.",
        null,
        null,
        null,
        List.of(),
        AppCatalogCompatibilityMetadata.EMPTY,
        AppCatalogReviewMetadata.EMPTY,
        receipt,
        AppCatalogChangelog.EMPTY,
        List.of(),
        AppCatalogProductionMetadata.DEFAULT,
        URI.create("https://example.invalid/app.zip"),
        BUNDLE_DIGEST,
        42L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of("queue.read"),
        Map.of());
  }

  private static KeyPair keyPair() throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM).generateKeyPair();
  }
}
