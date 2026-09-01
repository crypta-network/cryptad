package network.crypta.platform.appcatalog;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppCatalogManagerFederationTest {
  private static final String KEY_ID = "catalog-test";
  private static final String CATALOG_ID = "core";
  private static final String APP_ID = "queue-manager";
  private static final String CORE_BINDING_ID = "binding-core";
  private static final String OPERATOR_SUSPENSION_REASON = "operator suspension";
  private static final String OPERATOR_REVOCATION_REASON = "operator revocation";
  private static final String OPERATOR_ID = "operator";
  private static final Instant GENERATED_AT = Instant.parse("2026-04-21T18:22:40Z");

  private final AppCatalogManagerTest fixtures = new AppCatalogManagerTest();

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    fixtures.tempDir = tempDir;
  }

  @Test
  void importCatalogDiscovery_whenFederationConfigured_expectPendingEvidenceOnly()
      throws Exception {
    KeyPair issuer = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(issuer);
    TrustedAppKeys issuerKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(issuer));
    AppCatalogSourceStore sources =
        new AppCatalogSourceStore(tempDir.resolve("discovery-catalogs"));
    FileFederatedCatalogTrustStore trust =
        new FileFederatedCatalogTrustStore(tempDir.resolve("discovery-trust"));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustAndDiscoveryPolicy(
            sources,
            () -> issuerKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> issuerKeys),
            trust,
            new FilePendingCatalogDiscoveryStore(tempDir.resolve("discovery-pending")),
            () -> issuerKeys);

    PendingCatalogDiscoveryRecommendation imported =
        manager.importCatalogDiscovery(
            descriptor.canonicalDocumentBytes(), List.of(), CatalogSignedDocumentTestSupport.NOW);

    assertTrue(manager.catalogDiscoveryEnabled());
    assertEquals(List.of(imported), manager.pendingCatalogDiscoveries());
    assertFalse(PendingCatalogDiscoveryRecommendation.TRUST_GRANTED);
    assertFalse(PendingCatalogDiscoveryRecommendation.SOURCE_CONFIGURED);
    assertFalse(PendingCatalogDiscoveryRecommendation.TRANSITIVE);
    assertTrue(manager.federatedTrustBindings().isEmpty());
    assertTrue(manager.configuredCatalogIds().isEmpty());
    assertTrue(
        manager
            .currentPendingCatalogDiscoveries(CatalogSignedDocumentTestSupport.NOW)
            .getFirst()
            .descriptorActive());
    assertFalse(
        manager
            .currentPendingCatalogDiscoveries(
                CatalogSignedDocumentTestSupport.NOW.plusSeconds(7200))
            .getFirst()
            .descriptorActive());
    assertTrue(manager.discardPendingCatalogDiscovery(imported.descriptorId()));
    assertTrue(manager.pendingCatalogDiscoveries().isEmpty());
  }

  @Test
  void authorizeHistoricalAppOrigin_whenChannelRemovedThenRevoked_expectBoundedHistoryOnly()
      throws Exception {
    KeyPair keyPair = AppCatalogManagerTest.keyPair();
    TrustedAppKeys trustedKeys = AppCatalogManagerTest.trustedKeys(keyPair);
    Path bundle = fixtures.signedBundle(keyPair);
    Path artifact =
        AppCatalogManagerTest.zipDirectory(
            bundle, tempDir.resolve("historical-origin-artifact.zip"));
    Path catalog =
        fixtures.signedCatalog(
            artifact, keyPair, AppCatalogManagerTest.sha256(artifact), Files.size(artifact));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve("historical-origin-catalogs"));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("historical-origin-trust"));
    trustStore.put(
        AppCatalogManagerTest.federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, keyPair));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(catalog.toString(), CATALOG_ID);
    AppCatalogOriginContext captured;
    AppCatalogEntry entry;
    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      captured = plan.originContext().orElseThrow();
      entry = plan.entry();
    }
    manager.transitionFederatedTrustBinding(
        CATALOG_ID,
        FederatedCatalogTrustBinding.Status.SUSPENDED,
        OPERATOR_SUSPENSION_REASON,
        OPERATOR_ID,
        GENERATED_AT.plusSeconds(1));

    AppCatalogEntry authorized =
        manager.authorizeHistoricalAppOrigin(
            captured, entry.appId(), entry.version(), entry.bundleSha256());
    FederatedCatalogTrustBinding suspended = trustStore.findByCatalogId(CATALOG_ID).orElseThrow();
    trustStore.put(
        FederatedCatalogTrustBinding.create(
            suspended.bindingId(),
            suspended.catalogId(),
            suspended.signerFingerprints(),
            suspended.status(),
            Set.of(AppCatalogChannel.BETA),
            suspended.localPriority(),
            suspended.discoveryProvenanceDigest().orElse(null),
            suspended.reviewerPolicyDigest().orElse(null),
            suspended.publisherPolicyDigest().orElse(null),
            suspended.createdAt(),
            GENERATED_AT.plusSeconds(2),
            "operator removed stable rollback scope",
            OPERATOR_ID));
    String appId = entry.appId();
    String appVersion = entry.version();
    String bundleSha256 = entry.bundleSha256();
    assertThrows(
        AppCatalogException.class,
        () -> manager.authorizeHistoricalAppOrigin(captured, appId, appVersion, bundleSha256));
    manager.transitionFederatedTrustBinding(
        CATALOG_ID,
        FederatedCatalogTrustBinding.Status.REVOKED,
        OPERATOR_REVOCATION_REASON,
        OPERATOR_ID,
        GENERATED_AT.plusSeconds(3));

    assertEquals(entry, authorized);
    assertThrows(
        AppCatalogException.class,
        () -> manager.authorizeHistoricalAppOrigin(captured, appId, appVersion, bundleSha256));
  }

  @Test
  void authorizeHistoricalAppOrigin_whenSourceReadmittedAfterPolicyChange_expectRetainedOrigin()
      throws Exception {
    KeyPair keyPair = AppCatalogManagerTest.keyPair();
    TrustedAppKeys trustedKeys = AppCatalogManagerTest.trustedKeys(keyPair);
    Path bundle = fixtures.signedBundle(keyPair);
    Path artifact =
        AppCatalogManagerTest.zipDirectory(
            bundle, tempDir.resolve("readmitted-origin-artifact.zip"));
    Path catalog =
        fixtures.signedCatalog(
            artifact, keyPair, AppCatalogManagerTest.sha256(artifact), Files.size(artifact));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve("readmitted-origin-catalogs"));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("readmitted-origin-trust"));
    FederatedCatalogTrustBinding admitted =
        AppCatalogManagerTest.federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, keyPair);
    trustStore.put(admitted);
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(catalog.toString(), CATALOG_ID);
    AppCatalogOriginContext captured;
    AppCatalogEntry entry;
    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      captured = plan.originContext().orElseThrow();
      entry = plan.entry();
    }
    fixtures.signedCatalog(
        CATALOG_ID,
        artifact.toUri(),
        keyPair,
        KEY_ID,
        AppCatalogManagerTest.sha256(artifact),
        Files.size(artifact),
        GENERATED_AT.plusSeconds(1));
    manager.refresh(CATALOG_ID);
    FederatedCatalogTrustBinding readmitted =
        FederatedCatalogTrustBinding.create(
            admitted.bindingId(),
            admitted.catalogId(),
            admitted.signerFingerprints(),
            admitted.status(),
            admitted.allowedChannels(),
            admitted.localPriority() + 1,
            admitted.discoveryProvenanceDigest().orElse(null),
            admitted.reviewerPolicyDigest().orElse(null),
            admitted.publisherPolicyDigest().orElse(null),
            admitted.createdAt(),
            GENERATED_AT.plusSeconds(2),
            "operator re-admission",
            OPERATOR_ID);
    trustStore.put(readmitted);
    StoredCatalogSource stored = sourceStore.read(CATALOG_ID);
    AppCatalog current =
        FederatedCatalogVerifier.verifyRoutine(
            stored.fetchedCatalog().catalogBytes(),
            stored.fetchedCatalog().signatureBytes(),
            trustedKeys,
            readmitted);
    sourceStore.write(
        new AppCatalogSourceStore.VerifiedCatalogWrite(
            current,
            stored.source(),
            stored.fetchedCatalog(),
            stored.addedAt(),
            GENERATED_AT.plusSeconds(2),
            Optional.of(readmitted.bindingId()),
            Optional.of(readmitted.selfDigest())),
        new AppCatalogSourceStore.EndpointWriteState(
            stored.mirrors().getFirst(), stored.mirrors(), stored.mirrorHealth()));

    AppCatalogEntry authorized =
        manager.authorizeHistoricalAppOrigin(
            captured, entry.appId(), entry.version(), entry.bundleSha256());

    assertEquals(entry, authorized);
    assertNotEquals(captured.trustBindingDigestSha256(), readmitted.selfDigest());
  }

  @Test
  void authorizeHistoricalAppOriginForRollback_whenRevokedConcurrently_expectLeaseDefersRevocation()
      throws Exception {
    KeyPair keyPair = AppCatalogManagerTest.keyPair();
    TrustedAppKeys trustedKeys = AppCatalogManagerTest.trustedKeys(keyPair);
    Path bundle = fixtures.signedBundle(keyPair);
    Path artifact =
        AppCatalogManagerTest.zipDirectory(bundle, tempDir.resolve("rollback-lease-artifact.zip"));
    Path catalog =
        fixtures.signedCatalog(
            artifact, keyPair, AppCatalogManagerTest.sha256(artifact), Files.size(artifact));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve("rollback-lease-catalogs"));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("rollback-lease-trust"));
    trustStore.put(
        AppCatalogManagerTest.federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, keyPair));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(catalog.toString(), CATALOG_ID);
    AppCatalogOriginContext captured;
    AppCatalogEntry entry;
    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      captured = plan.originContext().orElseThrow();
      entry = plan.entry();
    }
    AppCatalogManager.HistoricalAppOriginAuthorization authorization =
        manager.authorizeHistoricalAppOriginForRollback(
            captured, entry.appId(), entry.version(), entry.bundleSha256());
    CountDownLatch transitionStarted = new CountDownLatch(1);
    CompletableFuture<FederatedCatalogTrustBinding> transition =
        CompletableFuture.supplyAsync(
            () -> {
              transitionStarted.countDown();
              try {
                return manager.transitionFederatedTrustBinding(
                    CATALOG_ID,
                    FederatedCatalogTrustBinding.Status.REVOKED,
                    OPERATOR_REVOCATION_REASON,
                    OPERATOR_ID,
                    GENERATED_AT.plusSeconds(1));
              } catch (java.io.IOException exception) {
                throw new AssertionError(exception);
              }
            });
    try {
      assertTrue(transitionStarted.await(5, TimeUnit.SECONDS));
      assertThrows(TimeoutException.class, () -> transition.get(100, TimeUnit.MILLISECONDS));
      assertEquals(entry, authorization.entry());
      assertEquals(
          FederatedCatalogTrustBinding.Status.ACTIVE,
          trustStore.findByCatalogId(CATALOG_ID).orElseThrow().status());
    } finally {
      authorization.authorization().close();
    }

    assertEquals(
        FederatedCatalogTrustBinding.Status.REVOKED, transition.get(5, TimeUnit.SECONDS).status());
  }
}
