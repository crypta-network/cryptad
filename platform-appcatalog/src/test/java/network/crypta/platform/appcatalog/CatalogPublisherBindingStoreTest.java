package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CatalogPublisherBindingStoreTest {
  private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");
  private static final String CATALOG_ID = "independent-catalog";
  private static final String APP_ID = "federated-app";
  private static final String KEY_ID = "publisher-2026";
  private static final String PUBLISHER_POLICY_ROOT = "publisher-policy";
  private static final String OTHER_CATALOG_ID = "other-catalog";
  private static final String OTHER_APP_ID = "other-app";
  private static final String APPROVED_REASON = "approved";
  private static final String LOCAL_OPERATOR_ID = "local-operator";
  private static final String ED25519 = "Ed25519";

  @TempDir private Path tempDir;

  @Test
  void findAuthorization_whenBindingIsExactAndActive_expectRestartSafeAuthorization()
      throws Exception {
    KeyPair publisher = keyPair();
    CatalogPublisherBinding binding = binding(publisher, CatalogPublisherBinding.Status.ACTIVE);
    FileCatalogPublisherBindingStore first =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));

    first.put(binding);
    FileCatalogPublisherBindingStore restarted =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));

    assertEquals(
        binding,
        restarted
            .findAuthorization(
                CATALOG_ID,
                APP_ID,
                KEY_ID,
                PublicKeyFingerprint.sha256(publisher.getPublic()),
                AppCatalogChannel.BETA,
                NOW)
            .orElseThrow());
    assertTrue(restarted.find(binding.bindingId()).isPresent());
  }

  @Test
  void findAuthorization_whenCatalogAppOrLifecycleDiffers_expectFailClosed() throws Exception {
    KeyPair publisher = keyPair();
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    store.put(binding(publisher, CatalogPublisherBinding.Status.SUSPENDED));
    String fingerprint = PublicKeyFingerprint.sha256(publisher.getPublic());

    assertFalse(
        store
            .findAuthorization(CATALOG_ID, APP_ID, KEY_ID, fingerprint, AppCatalogChannel.BETA, NOW)
            .isPresent());
    assertFalse(
        store
            .findAuthorization(
                OTHER_CATALOG_ID, APP_ID, KEY_ID, fingerprint, AppCatalogChannel.BETA, NOW)
            .isPresent());
    assertFalse(
        store
            .findAuthorization(
                CATALOG_ID, OTHER_APP_ID, KEY_ID, fingerprint, AppCatalogChannel.BETA, NOW)
            .isPresent());
    assertTrue(
        store
            .find("publisher-binding-1")
            .orElseThrow()
            .authorizesHistorical(
                CATALOG_ID, APP_ID, KEY_ID, fingerprint, AppCatalogChannel.BETA, NOW));
  }

  @Test
  void put_whenStableIdMovesToAnotherAuthorizationSubject_expectRejected() throws Exception {
    KeyPair publisher = keyPair();
    CatalogPublisherBinding original = binding(publisher, CatalogPublisherBinding.Status.ACTIVE);
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    store.put(original);
    List<CatalogPublisherBinding> reassigned =
        List.of(
            bindingWithIdentity(original.bindingId(), OTHER_CATALOG_ID, APP_ID, KEY_ID, publisher),
            bindingWithIdentity(original.bindingId(), CATALOG_ID, OTHER_APP_ID, KEY_ID, publisher),
            bindingWithIdentity(
                original.bindingId(), CATALOG_ID, APP_ID, "other-publisher", publisher),
            bindingWithIdentity(original.bindingId(), CATALOG_ID, APP_ID, KEY_ID, keyPair()));

    for (CatalogPublisherBinding replacement : reassigned) {
      assertThrows(AppCatalogException.class, () -> store.put(replacement));
    }

    assertEquals(original, store.find(original.bindingId()).orElseThrow());
  }

  @Test
  void put_whenRevokedBindingMovesToNonRevokedState_expectRejected() throws Exception {
    KeyPair publisher = keyPair();
    CatalogPublisherBinding revoked = binding(publisher, CatalogPublisherBinding.Status.REVOKED);
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    store.put(revoked);
    List<CatalogPublisherBinding.Status> replacements =
        List.of(
            CatalogPublisherBinding.Status.PENDING,
            CatalogPublisherBinding.Status.ACTIVE,
            CatalogPublisherBinding.Status.SUSPENDED,
            CatalogPublisherBinding.Status.REMOVED);

    for (CatalogPublisherBinding.Status status : replacements) {
      CatalogPublisherBinding replacement = binding(publisher, status);
      assertThrows(AppCatalogException.class, () -> store.put(replacement));
    }

    assertEquals(revoked, store.find(revoked.bindingId()).orElseThrow());
  }

  @Test
  void retainHistoricalAuthorization_whenLifecycleUpdateStarts_expectUpdateWaitsForLease()
      throws Exception {
    KeyPair publisher = keyPair();
    CatalogPublisherBinding active = binding(publisher, CatalogPublisherBinding.Status.ACTIVE);
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    store.put(active);
    String policyDigest = store.policyDigest(CATALOG_ID);
    FileCatalogPublisherBindingStore.AuthorizationLease authorization =
        store.retainHistoricalAuthorization(
            CATALOG_ID,
            policyDigest,
            APP_ID,
            KEY_ID,
            PublicKeyFingerprint.sha256(publisher.getPublic()),
            AppCatalogChannel.BETA,
            NOW);
    FileCatalogPublisherBindingStore independentWriter =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    CompletableFuture<Void> suspension =
        CompletableFuture.runAsync(
            () -> {
              try {
                independentWriter.put(binding(publisher, CatalogPublisherBinding.Status.SUSPENDED));
              } catch (IOException exception) {
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
        CatalogPublisherBinding.Status.SUSPENDED,
        store.find(active.bindingId()).orElseThrow().status());
  }

  @Test
  void retainAuthorization_whenRoutineLifecycleUpdateStarts_expectUpdateWaitsForLease()
      throws Exception {
    KeyPair publisher = keyPair();
    CatalogPublisherBinding active = binding(publisher, CatalogPublisherBinding.Status.ACTIVE);
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve("routine-publisher-policy"));
    store.put(active);
    AppCatalogBundleVerificationResult verification =
        new AppCatalogBundleVerificationResult(
            KEY_ID,
            PublicKeyFingerprint.sha256(publisher.getPublic()),
            active.bindingId(),
            active.selfDigest(),
            true,
            "0".repeat(64));
    FileCatalogPublisherBindingStore.AuthorizationLease authorization =
        store.retainAuthorization(
            CATALOG_ID,
            store.policyDigest(CATALOG_ID),
            APP_ID,
            verification,
            AppCatalogChannel.BETA,
            NOW);
    FileCatalogPublisherBindingStore independentWriter =
        new FileCatalogPublisherBindingStore(tempDir.resolve("routine-publisher-policy"));
    CompletableFuture<Void> suspension =
        CompletableFuture.runAsync(
            () -> {
              try {
                independentWriter.put(binding(publisher, CatalogPublisherBinding.Status.SUSPENDED));
              } catch (IOException exception) {
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
        CatalogPublisherBinding.Status.SUSPENDED,
        store.find(active.bindingId()).orElseThrow().status());
  }

  @Test
  void retainAuthorization_whenSelectedBindingIdentityChanges_expectRejected() throws Exception {
    KeyPair publisher = keyPair();
    CatalogPublisherBinding active = binding(publisher, CatalogPublisherBinding.Status.ACTIVE);
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve("routine-binding-substitution"));
    store.put(active);
    String fingerprint = PublicKeyFingerprint.sha256(publisher.getPublic());
    AppCatalogBundleVerificationResult substitutedId =
        new AppCatalogBundleVerificationResult(
            KEY_ID,
            fingerprint,
            "publisher-binding-substituted",
            active.selfDigest(),
            true,
            "0".repeat(64));
    AppCatalogBundleVerificationResult substitutedDigest =
        new AppCatalogBundleVerificationResult(
            KEY_ID, fingerprint, active.bindingId(), "f".repeat(64), true, "0".repeat(64));
    String policyDigest = store.policyDigest(CATALOG_ID);

    assertThrows(
        AppCatalogException.class, () -> retainAuthorization(store, policyDigest, substitutedId));
    assertThrows(
        AppCatalogException.class,
        () -> retainAuthorization(store, policyDigest, substitutedDigest));
  }

  @Test
  void list_whenRecordDigestIsSubstituted_expectClosedParsingFailure() throws Exception {
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    KeyPair publisher = keyPair();
    CatalogPublisherBinding binding = binding(publisher, CatalogPublisherBinding.Status.ACTIVE);
    store.put(binding);
    Path recordPath =
        tempDir.resolve(PUBLISHER_POLICY_ROOT).resolve(binding.bindingId() + ".properties");
    String fingerprint = PublicKeyFingerprint.sha256(publisher.getPublic());
    Files.writeString(
        recordPath,
        Files.readString(recordPath, StandardCharsets.UTF_8)
            .replace("reason=approved", "reason=changed"),
        StandardCharsets.UTF_8);

    AppCatalogException exception = assertThrows(AppCatalogException.class, store::list);

    assertTrue(exception.getMessage().contains("self-digest mismatch"));
    assertThrows(
        AppCatalogException.class,
        () ->
            store.findAuthorization(
                CATALOG_ID, APP_ID, KEY_ID, fingerprint, AppCatalogChannel.BETA, NOW));
  }

  @Test
  void findAuthorization_whenAnotherCatalogRecordIsCorrupt_expectScopedIsolation()
      throws Exception {
    Path root = tempDir.resolve("publisher-policy-isolation");
    FileCatalogPublisherBindingStore store = new FileCatalogPublisherBindingStore(root);
    KeyPair publisher = keyPair();
    CatalogPublisherBinding binding = binding(publisher, CatalogPublisherBinding.Status.ACTIVE);
    store.put(binding);
    CatalogPublisherBinding other = otherBinding(keyPair());
    store.put(other);
    String expectedDigest = store.policyDigest(CATALOG_ID);
    Path otherRecord = root.resolve(other.bindingId() + ".properties");
    Files.writeString(
        otherRecord,
        Files.readString(otherRecord, StandardCharsets.UTF_8)
            .replace("reason=approved", "reason=changed"),
        StandardCharsets.UTF_8);

    assertEquals(
        binding,
        store
            .findAuthorization(
                CATALOG_ID,
                APP_ID,
                KEY_ID,
                PublicKeyFingerprint.sha256(publisher.getPublic()),
                AppCatalogChannel.BETA,
                NOW)
            .orElseThrow());
    assertEquals(expectedDigest, store.policyDigest(CATALOG_ID));
    assertThrows(AppCatalogException.class, store::list);
  }

  @Test
  void policyDigest_whenUnrelatedCatalogChanges_expectCatalogDigestUnchanged() throws Exception {
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    store.put(binding(keyPair(), CatalogPublisherBinding.Status.ACTIVE));
    String originalDigest = store.policyDigest(CATALOG_ID);
    store.put(otherBinding(keyPair()));

    assertEquals(originalDigest, store.policyDigest(CATALOG_ID));
  }

  @Test
  void verify_whenPublisherBindingMatchesContext_expectScopedPolicyIdentity() throws Exception {
    KeyPair publisher = keyPair();
    KeyPair catalog = keyPair();
    KeyPair reviewer = keyPair();
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    CatalogPublisherBinding binding = binding(publisher, CatalogPublisherBinding.Status.ACTIVE);
    store.put(binding);
    CatalogScopedPublisherVerificationPolicy policy = policy(store, publisher, catalog, reviewer);
    Path bundle = signedBundle(publisher);

    AppCatalogBundleVerificationResult result =
        policy.verify(new AppCatalogBundleVerificationContext(CATALOG_ID, entry(APP_ID)), bundle);

    assertTrue(result.catalogScoped());
    assertEquals(binding.bindingId(), result.authorizationPolicyId());
    assertEquals(binding.selfDigest(), result.authorizationPolicyDigestSha256());
    assertEquals(
        PublicKeyFingerprint.sha256(publisher.getPublic()), result.publisherKeyFingerprintSha256());
  }

  @Test
  void verify_whenSamePublisherIsUsedForAnotherScope_expectRejected() throws Exception {
    KeyPair publisher = keyPair();
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    store.put(binding(publisher, CatalogPublisherBinding.Status.ACTIVE));
    CatalogScopedPublisherVerificationPolicy policy =
        policy(store, publisher, keyPair(), keyPair());
    Path bundle = signedBundle(publisher);

    assertThrows(
        IOException.class,
        () ->
            policy.verify(
                new AppCatalogBundleVerificationContext(OTHER_CATALOG_ID, entry(APP_ID)), bundle));
    assertThrows(
        IOException.class,
        () ->
            policy.verify(
                new AppCatalogBundleVerificationContext(CATALOG_ID, entry(OTHER_APP_ID)), bundle));
  }

  @Test
  void verify_whenCatalogOrReviewerReusesPublisherKey_expectRoleSeparationFailure()
      throws Exception {
    KeyPair publisher = keyPair();
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve(PUBLISHER_POLICY_ROOT));
    store.put(binding(publisher, CatalogPublisherBinding.Status.ACTIVE));
    Path bundle = signedBundle(publisher);
    AppCatalogBundleVerificationContext context =
        new AppCatalogBundleVerificationContext(CATALOG_ID, entry(APP_ID));

    CatalogScopedPublisherVerificationPolicy catalogOverlap =
        policy(store, publisher, publisher, keyPair());
    CatalogScopedPublisherVerificationPolicy reviewerOverlap =
        policy(store, publisher, keyPair(), publisher);
    KeyPair catalogAndReviewer = keyPair();
    CatalogScopedPublisherVerificationPolicy catalogReviewerOverlap =
        policy(store, publisher, catalogAndReviewer, catalogAndReviewer);

    assertThrows(IOException.class, () -> catalogOverlap.verify(context, bundle));
    assertThrows(IOException.class, () -> reviewerOverlap.verify(context, bundle));
    assertThrows(IOException.class, () -> catalogReviewerOverlap.verify(context, bundle));
  }

  @Test
  void verify_whenLegacyCatalogRegistrySharesPublisherKeys_expectScopedBindingStillAuthorizes()
      throws Exception {
    KeyPair sharedPublisherAndCatalog = keyPair();
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve("legacy-shared-publisher-policy"));
    CatalogPublisherBinding binding =
        binding(sharedPublisherAndCatalog, CatalogPublisherBinding.Status.ACTIVE);
    store.put(binding);
    CatalogScopedPublisherVerificationPolicy policy =
        policy(
            store,
            sharedPublisherAndCatalog,
            sharedPublisherAndCatalog,
            keyPair(),
            CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode
                .LEGACY_SHARED_APPHOST_REGISTRY);
    Path bundle = signedBundle(sharedPublisherAndCatalog);

    AppCatalogBundleVerificationResult result =
        policy.verify(new AppCatalogBundleVerificationContext(CATALOG_ID, entry(APP_ID)), bundle);

    assertTrue(result.catalogScoped());
    assertEquals(binding.bindingId(), result.authorizationPolicyId());
    assertEquals(binding.selfDigest(), result.authorizationPolicyDigestSha256());
  }

  @Test
  void verify_whenLegacyCatalogRegistryAlsoSharesReviewerKey_expectRoleSeparationFailure()
      throws Exception {
    KeyPair sharedKey = keyPair();
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(tempDir.resolve("legacy-reviewer-overlap-policy"));
    store.put(binding(sharedKey, CatalogPublisherBinding.Status.ACTIVE));
    CatalogScopedPublisherVerificationPolicy policy =
        policy(
            store,
            sharedKey,
            sharedKey,
            sharedKey,
            CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode
                .LEGACY_SHARED_APPHOST_REGISTRY);
    Path bundle = signedBundle(sharedKey);

    assertThrows(
        IOException.class,
        () ->
            policy.verify(
                new AppCatalogBundleVerificationContext(CATALOG_ID, entry(APP_ID)), bundle));
  }

  private CatalogPublisherBinding binding(
      KeyPair publisher, CatalogPublisherBinding.Status status) {
    return CatalogPublisherBinding.create(
        "publisher-binding-1",
        CATALOG_ID,
        APP_ID,
        KEY_ID,
        PublicKeyFingerprint.sha256(publisher.getPublic()),
        status,
        NOW.minusSeconds(60),
        NOW.plusSeconds(3600),
        null,
        null,
        Set.of(AppCatalogChannel.STABLE, AppCatalogChannel.BETA),
        "operator-approved-pr-294",
        "a".repeat(64),
        NOW.minusSeconds(60),
        NOW,
        APPROVED_REASON,
        LOCAL_OPERATOR_ID);
  }

  private static CatalogPublisherBinding bindingWithIdentity(
      String bindingId, String catalogId, String appId, String keyId, KeyPair publisher) {
    return CatalogPublisherBinding.create(
        bindingId,
        catalogId,
        appId,
        keyId,
        PublicKeyFingerprint.sha256(publisher.getPublic()),
        CatalogPublisherBinding.Status.ACTIVE,
        NOW.minusSeconds(60),
        NOW.plusSeconds(3600),
        null,
        null,
        Set.of(AppCatalogChannel.BETA),
        "operator-approved",
        "c".repeat(64),
        NOW.minusSeconds(60),
        NOW,
        APPROVED_REASON,
        LOCAL_OPERATOR_ID);
  }

  private static CatalogPublisherBinding otherBinding(KeyPair publisher) {
    return CatalogPublisherBinding.create(
        "other-publisher-binding",
        OTHER_CATALOG_ID,
        APP_ID,
        "other-publisher-2026",
        PublicKeyFingerprint.sha256(publisher.getPublic()),
        CatalogPublisherBinding.Status.ACTIVE,
        NOW.minusSeconds(60),
        NOW.plusSeconds(3600),
        null,
        null,
        Set.of(AppCatalogChannel.BETA),
        "operator-approved",
        "b".repeat(64),
        NOW.minusSeconds(60),
        NOW,
        APPROVED_REASON,
        LOCAL_OPERATOR_ID);
  }

  private CatalogScopedPublisherVerificationPolicy policy(
      FileCatalogPublisherBindingStore store,
      KeyPair publisher,
      KeyPair catalog,
      KeyPair reviewer) {
    return policy(
        store,
        publisher,
        catalog,
        reviewer,
        CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode.ROLE_SEPARATED);
  }

  private CatalogScopedPublisherVerificationPolicy policy(
      FileCatalogPublisherBindingStore store,
      KeyPair publisher,
      KeyPair catalog,
      KeyPair reviewer,
      CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode catalogSignerTrustMode) {
    TrustedAppKeys publisherKeys =
        TrustedAppKeys.of(new TrustedAppKey(KEY_ID, ED25519, publisher.getPublic()));
    TrustedAppKeys catalogKeys =
        catalogSignerTrustMode
                == CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode
                    .LEGACY_SHARED_APPHOST_REGISTRY
            ? publisherKeys
            : TrustedAppKeys.of(new TrustedAppKey("catalog-key", ED25519, catalog.getPublic()));
    TrustedReviewerKeys reviewerKeys =
        TrustedReviewerKeys.of(
            new TrustedReviewerKey(
                "reviewer-key",
                ED25519,
                reviewer.getPublic(),
                Optional.empty(),
                TrustedReviewerPolicyConstraint.ANY,
                TrustedReviewerKeyLifecycle.ACTIVE));
    return new CatalogScopedPublisherVerificationPolicy(
        store,
        () -> publisherKeys,
        () -> catalogKeys,
        () -> reviewerKeys,
        Clock.fixed(NOW, ZoneOffset.UTC),
        null,
        catalogSignerTrustMode);
  }

  private static void retainAuthorization(
      FileCatalogPublisherBindingStore store,
      String policyDigest,
      AppCatalogBundleVerificationResult verification)
      throws IOException {
    try (var authorization =
        store.retainAuthorization(
            CATALOG_ID, policyDigest, APP_ID, verification, AppCatalogChannel.BETA, NOW)) {
      assertNotNull(authorization);
    }
  }

  private Path signedBundle(KeyPair publisher) throws IOException {
    Path root = Files.createDirectories(tempDir.resolve("bundle-" + APP_ID));
    Files.createDirectories(root.resolve("bin"));
    Files.writeString(root.resolve("bin/launch.sh"), "#!/bin/sh\nexit 0\n", StandardCharsets.UTF_8);
    Files.writeString(
        root.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=APP_ID
        app.name=Federated App
        app.version=1.0.0
        app.exec=bin/launch.sh
        app.permissions=queue.read
        """
            .replace("APP_ID", APP_ID),
        StandardCharsets.UTF_8);
    AppBundleSigner.sign(root, KEY_ID, publisher.getPrivate());
    return root;
  }

  private static AppCatalogEntry entry(String appId) {
    return new AppCatalogEntry(
        appId,
        "Federated App",
        "1.0.0",
        "Scoped publisher test app.",
        java.net.URI.create("https://example.invalid/app.zip"),
        "0".repeat(64),
        1L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of("queue.read"));
  }

  private static KeyPair keyPair() throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance(ED25519).generateKeyPair();
  }
}
