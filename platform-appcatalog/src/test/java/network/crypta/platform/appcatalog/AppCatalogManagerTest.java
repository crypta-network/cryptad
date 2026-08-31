package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import network.crypta.platform.appcatalog.AppCatalogManagerHttpTestSupport.CloseRecordingInputStream;
import network.crypta.platform.appcatalog.AppCatalogManagerHttpTestSupport.FixedResponseHttpClient;
import network.crypta.platform.appcatalog.AppCatalogManagerHttpTestSupport.InputStreamResponse;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeyLifecycle;
import network.crypta.platform.appdist.TrustedAppKeyPolicy;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogManagerTest {
  private static final String KEY_ID = "catalog-test";
  private static final String APP_SIGNING_KEY_ID = "app-signing-test";
  private static final String ROTATED_KEY_ID = "catalog-rotated";
  private static final String CATALOG_ID = "core";
  private static final String STAGING_CATALOG_ID = "staging";
  private static final String APP_ID = "queue-manager";
  private static final String APP_VERSION = "1.0.0";
  private static final String APP_NAME = "Queue Manager";
  private static final String APP_SUMMARY = "Manage local Crypta transfer queues.";
  private static final String ARTIFACT_ZIP = "queue-manager.zip";
  private static final String EXECUTABLE_PATH = "bin/tool";
  private static final String QUEUE_READ_PERMISSION = "queue.read";
  private static final String QUEUE_WRITE_PERMISSION = "queue.write";
  private static final String CRYPTA_URI_PREFIX = "crypta:";
  private static final String FIXTURE_TEXT = "fixture";
  private static final String CORE_BINDING_ID = "binding-core";
  private static final String STAGING_BINDING_ID = "binding-staging";
  private static final String OPERATOR_SUSPENSION_REASON = "operator suspension";
  private static final String OPERATOR_REVOCATION_REASON = "operator revocation";
  private static final String OPERATOR_ID = "operator";
  private static final String MACOS_METADATA_FILE = ".DS_Store";
  private static final String RESOLVED_SIGNATURE_KEY =
      "USK@example/catalog/42/cryptad-app-catalog.signature";
  private static final String LATEST_CATALOG_KEY =
      "USK@example/catalog/latest/cryptad-app-catalog.properties";
  private static final String CATALOG_SIGNATURE_PURPOSE = "catalog signature";
  private static final String PRIMARY_MIRROR_ID = "primary";
  private static final String BACKUP_MIRROR_ID = "backup";
  private static final String PRIMARY_UNAVAILABLE_MESSAGE = "primary unavailable";
  private static final String MIRROR_SOURCE_URI =
      "https://mirror.example.invalid/cryptad-app-catalog.properties";
  private static final String CRYPTA_CATALOG_KEY =
      "USK@example/catalog/cryptad-app-catalog.properties";

  private static final String CRYPTA_SIGNATURE_KEY =
      "USK@example/catalog/cryptad-app-catalog.signature";
  private static final String CRYPTA_CATALOG_SOURCE = CRYPTA_URI_PREFIX + CRYPTA_CATALOG_KEY;
  private static final String CRYPTA_ARTIFACT_KEY = "CHK@artifact-key";
  private static final URI CRYPTA_ARTIFACT_URI =
      URI.create(CRYPTA_URI_PREFIX + CRYPTA_ARTIFACT_KEY);
  private static final String BASIC_CATALOG_PROPERTIES = "catalog.version=1\n";
  private static final String BASIC_CATALOG_SIGNATURE = "catalog.signature.version=1\n";
  private static final String MALFORMED_KEY_VALUE_LINE = "not-a-key-value-line\n";
  private static final String CATALOG_SOURCE_STORE_DIRECTORY = "store";
  private static final String FINDER_METADATA = "finder metadata";
  private static final String UNEXPECTED_HTTP_FETCH = "unexpected HTTP fetch";
  private static final int LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50;
  private static final int CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
  private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50;
  private static final int END_OF_CENTRAL_DIRECTORY_MIN_BYTES = 22;
  private static final int UNIX_REGULAR_FILE_MODE = 32768;
  private static final int UNIX_EXECUTABLE_FILE_MODE = UNIX_REGULAR_FILE_MODE | 448;
  private static final Instant GENERATED_AT = Instant.parse("2026-04-21T18:22:40Z");

  @TempDir Path tempDir;

  @Test
  void addSource_whenLocalSignedCatalogIsValid_expectListAndInstallPlan() throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys);

    AppCatalogSourceSnapshot snapshot = manager.addSource(catalog.toString());
    List<AppCatalogEntry> entries = manager.listApps(CATALOG_ID);

    assertEquals(CATALOG_ID, snapshot.catalogId());
    assertEquals(1, snapshot.appCount());
    assertEquals(APP_ID, entries.getFirst().appId());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertTrue(Files.isDirectory(plan.stagedBundleDirectory()));
      assertTrue(
          Files.isRegularFile(
              plan.stagedBundleDirectory().resolve(AppBundleManifestParser.MANIFEST_FILE_NAME)));
      assertFalse(plan.originContext().orElseThrow().federationScoped());
    }
  }

  @Test
  void prepareInstallPlan_whenDevelopmentPolicyAcceptsUnsignedBundle_expectUnscopedPlan()
      throws Exception {
    KeyPair catalogKey = keyPair();
    Path bundle = unsignedBundle();
    Path artifact = zipDirectory(bundle, tempDir.resolve("unsigned-development.zip"));
    Path catalog = signedCatalog(artifact, catalogKey, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager =
        AppCatalogManager.withBundleVerificationPolicy(
            new AppCatalogSourceStore(tempDir.resolve("unsigned-development-catalogs")),
            () -> trustedKeys(catalogKey),
            stagedRoot -> {
              if (!AppBundleVerifier.isDistributionSidecarFree(stagedRoot)) {
                throw new IOException("expected a sidecar-free development bundle");
              }
            });
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertEquals("unsigned-development", plan.bundleVerification().publisherKeyId());
      assertFalse(plan.bundleVerification().catalogScoped());
      assertTrue(plan.bundleVerification().publisherKeyFingerprintSha256().isEmpty());
      manager.verifyInstallPlan(plan);
    }
  }

  @Test
  void listRoutineCatalogs_whenOneBindingIsSuspended_expectUnrelatedCatalogRemainsAvailable()
      throws Exception {
    KeyPair firstKey = keyPair();
    KeyPair secondKey = keyPair();
    String secondKeyId = "catalog-second";
    Path artifact = Files.writeString(tempDir.resolve("catalog-artifact.zip"), FIXTURE_TEXT);
    Path firstCatalog =
        signedCatalog(
            CATALOG_ID, artifact.toUri(), firstKey, KEY_ID, sha256(artifact), Files.size(artifact));
    Path secondCatalog =
        signedCatalog(
            STAGING_CATALOG_ID,
            artifact.toUri(),
            secondKey,
            secondKeyId,
            sha256(artifact),
            Files.size(artifact));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(trustedKey(KEY_ID, firstKey))
            .plus(TrustedAppKeys.of(trustedKey(secondKeyId, secondKey)));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("catalog-trust"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, firstKey));
    trustStore.put(
        federatedBinding(STAGING_BINDING_ID, STAGING_CATALOG_ID, secondKeyId, secondKey));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(firstCatalog.toString(), CATALOG_ID);
    manager.addSource(secondCatalog.toString(), STAGING_CATALOG_ID);

    manager.transitionFederatedTrustBinding(
        CATALOG_ID,
        FederatedCatalogTrustBinding.Status.SUSPENDED,
        OPERATOR_SUSPENSION_REASON,
        OPERATOR_ID,
        GENERATED_AT.plusSeconds(1));
    List<AppCatalogSourceSnapshot> available = manager.listRoutineCatalogs();

    assertEquals(
        List.of(STAGING_CATALOG_ID),
        available.stream().map(AppCatalogSourceSnapshot::catalogId).toList());
    assertEquals(List.of(CATALOG_ID, STAGING_CATALOG_ID), manager.configuredCatalogIds());
  }

  @Test
  void historicalReads_whenFederatedBindingIsSuspended_expectCatalogRemainsInspectable()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact =
        Files.writeString(tempDir.resolve("suspended-inspection-artifact.zip"), FIXTURE_TEXT);
    Path catalog =
        signedCatalog(
            CATALOG_ID, artifact.toUri(), keyPair, KEY_ID, sha256(artifact), Files.size(artifact));
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve("suspended-inspection-catalogs"));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("suspended-inspection-trust"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, keyPair));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(catalog.toString(), CATALOG_ID);

    manager.transitionFederatedTrustBinding(
        CATALOG_ID,
        FederatedCatalogTrustBinding.Status.SUSPENDED,
        OPERATOR_SUSPENSION_REASON,
        OPERATOR_ID,
        GENERATED_AT.plusSeconds(1));

    assertEquals(CATALOG_ID, manager.catalog(CATALOG_ID).catalogId());
    assertEquals(APP_ID, manager.listApps(CATALOG_ID).getFirst().appId());
    assertEquals(APP_ID, manager.getApp(CATALOG_ID, APP_ID).appId());
    assertEquals(AppCatalogSecurityDecision.OK, manager.securityDecision(CATALOG_ID, APP_ID));
    assertFalse(manager.sourceHealth(CATALOG_ID).isEmpty());
    assertThrows(AppCatalogException.class, () -> prepareAndCloseInstallPlan(manager, APP_ID));
  }

  @Test
  void routineEntries_whenFederatedCatalogHasMixedChannels_expectOnlyAllowedChannelSelectable()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("mixed-channel-artifact.zip"));
    Path catalog =
        signedMixedChannelCatalog(
            artifact.toUri(), keyPair, sha256(artifact), Files.size(artifact));
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve("mixed-channel-catalogs"));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("mixed-channel-trust"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, keyPair));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);

    manager.addSource(catalog.toString(), CATALOG_ID);

    assertEquals(2, manager.listApps(CATALOG_ID).size());
    assertThrows(AppCatalogException.class, () -> prepareAndCloseInstallPlan(manager, "beta-app"));
    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertEquals(APP_ID, plan.entry().appId());
    }
  }

  @Test
  void installedSecurityDecision_whenDenylistingBindingIsSuspended_expectDecisionIsIsolated()
      throws Exception {
    KeyPair suspendedKey = keyPair();
    KeyPair activeKey = keyPair();
    String activeKeyId = "catalog-active";
    Path artifact =
        Files.writeString(tempDir.resolve("suspended-security-artifact.zip"), FIXTURE_TEXT);
    Path suspendedCatalog =
        signedDenylistingCatalog(
            artifact.toUri(), suspendedKey, sha256(artifact), Files.size(artifact));
    Path activeCatalog =
        signedCatalog(
            STAGING_CATALOG_ID,
            artifact.toUri(),
            activeKey,
            activeKeyId,
            sha256(artifact),
            Files.size(artifact));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(trustedKey(KEY_ID, suspendedKey))
            .plus(TrustedAppKeys.of(trustedKey(activeKeyId, activeKey)));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve("suspended-security-catalogs"));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("suspended-security-trust"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, suspendedKey));
    trustStore.put(
        federatedBinding(STAGING_BINDING_ID, STAGING_CATALOG_ID, activeKeyId, activeKey));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(suspendedCatalog.toString(), CATALOG_ID);
    manager.addSource(activeCatalog.toString(), STAGING_CATALOG_ID);
    manager.transitionFederatedTrustBinding(
        CATALOG_ID,
        FederatedCatalogTrustBinding.Status.SUSPENDED,
        OPERATOR_SUSPENSION_REASON,
        OPERATOR_ID,
        GENERATED_AT.plusSeconds(1));

    AppCatalogSecurityDecision decision = manager.installedSecurityDecision(APP_ID, APP_VERSION);

    assertEquals(AppCatalogSecurityDecision.OK, decision);
    assertEquals(
        List.of(STAGING_CATALOG_ID),
        manager.listRoutineCatalogs().stream().map(AppCatalogSourceSnapshot::catalogId).toList());
  }

  @Test
  void installedSecurityDecision_whenOneBindingIsRevoked_expectUnrelatedCatalogStillEvaluated()
      throws Exception {
    KeyPair firstKey = keyPair();
    KeyPair secondKey = keyPair();
    String secondKeyId = "catalog-second";
    Path artifact = Files.writeString(tempDir.resolve("security-artifact.zip"), FIXTURE_TEXT);
    Path firstCatalog =
        signedCatalog(
            CATALOG_ID, artifact.toUri(), firstKey, KEY_ID, sha256(artifact), Files.size(artifact));
    Path secondCatalog =
        signedCatalog(
            STAGING_CATALOG_ID,
            artifact.toUri(),
            secondKey,
            secondKeyId,
            sha256(artifact),
            Files.size(artifact));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(trustedKey(KEY_ID, firstKey))
            .plus(TrustedAppKeys.of(trustedKey(secondKeyId, secondKey)));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("security-catalog-trust"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, firstKey));
    trustStore.put(
        federatedBinding(STAGING_BINDING_ID, STAGING_CATALOG_ID, secondKeyId, secondKey));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(firstCatalog.toString(), CATALOG_ID);
    manager.addSource(secondCatalog.toString(), STAGING_CATALOG_ID);
    manager.transitionFederatedTrustBinding(
        CATALOG_ID,
        FederatedCatalogTrustBinding.Status.REVOKED,
        OPERATOR_REVOCATION_REASON,
        OPERATOR_ID,
        GENERATED_AT.plusSeconds(1));

    AppCatalogSecurityDecision decision = manager.installedSecurityDecision(APP_ID, APP_VERSION);

    assertEquals(AppCatalogSecurityDecision.OK, decision);
    assertEquals(
        List.of(STAGING_CATALOG_ID),
        manager.listCatalogs().stream().map(AppCatalogSourceSnapshot::catalogId).toList());
  }

  @Test
  void listRoutineCatalogs_whenOneSourceHasLocalIoFailure_expectHealthyCatalogRemainsAvailable()
      throws Exception {
    Assumptions.assumeTrue(
        Files.getFileStore(tempDir).supportsFileAttributeView("posix"),
        "requires POSIX permissions to induce a source-local read failure");
    KeyPair firstKey = keyPair();
    KeyPair secondKey = keyPair();
    String secondKeyId = "catalog-io-healthy";
    Path artifact = Files.writeString(tempDir.resolve("catalog-io-artifact.zip"), FIXTURE_TEXT);
    Path firstCatalog =
        signedCatalog(
            CATALOG_ID, artifact.toUri(), firstKey, KEY_ID, sha256(artifact), Files.size(artifact));
    Path secondCatalog =
        signedCatalog(
            STAGING_CATALOG_ID,
            artifact.toUri(),
            secondKey,
            secondKeyId,
            sha256(artifact),
            Files.size(artifact));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(trustedKey(KEY_ID, firstKey))
            .plus(TrustedAppKeys.of(trustedKey(secondKeyId, secondKey)));
    Path sourceRoot = tempDir.resolve("catalog-source-io-isolation");
    AppCatalogSourceStore sourceStore = new AppCatalogSourceStore(sourceRoot);
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("catalog-trust-io-isolation"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, firstKey));
    trustStore.put(
        federatedBinding(STAGING_BINDING_ID, STAGING_CATALOG_ID, secondKeyId, secondKey));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(firstCatalog.toString(), CATALOG_ID);
    manager.addSource(secondCatalog.toString(), STAGING_CATALOG_ID);
    Path unreadableCatalog =
        sourceRoot.resolve(CATALOG_ID).resolve(AppCatalogSignature.CATALOG_FILE_NAME);
    Set<java.nio.file.attribute.PosixFilePermission> originalPermissions =
        Files.getPosixFilePermissions(unreadableCatalog);
    Files.setPosixFilePermissions(unreadableCatalog, Set.of());
    try {
      List<AppCatalogSourceSnapshot> available = manager.listRoutineCatalogs();

      assertEquals(
          List.of(STAGING_CATALOG_ID),
          available.stream().map(AppCatalogSourceSnapshot::catalogId).toList());
    } finally {
      Files.setPosixFilePermissions(unreadableCatalog, originalPermissions);
    }
  }

  @Test
  void prepareInstallPlan_whenRoleSpecificKeysConfigured_expectEachSignatureUsesItsRole()
      throws Exception {
    KeyPair catalogKeyPair = keyPair();
    KeyPair appKeyPair = keyPair();
    Path bundle = signedBundle(appKeyPair, APP_SIGNING_KEY_ID);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, catalogKeyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager =
        new AppCatalogManager(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            () -> trustedKeys(catalogKeyPair),
            () -> TrustedAppKeys.of(trustedKey(APP_SIGNING_KEY_ID, appKeyPair)));

    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertTrue(Files.isDirectory(plan.stagedBundleDirectory()));
      assertEquals(APP_SIGNING_KEY_ID, plan.bundleVerification().publisherKeyId());
      assertEquals(
          PublicKeyFingerprint.sha256(appKeyPair.getPublic()),
          plan.bundleVerification().publisherKeyFingerprintSha256());
      assertFalse(plan.bundleVerification().catalogScoped());
    }
  }

  @Test
  void verifyInstallPlan_whenExplicitBundlePolicyConfigured_expectPolicyRunsAtBothBoundaries()
      throws Exception {
    KeyPair catalogKeyPair = keyPair();
    KeyPair appKeyPair = keyPair();
    TrustedAppKeys appKeys = TrustedAppKeys.of(trustedKey(APP_SIGNING_KEY_ID, appKeyPair));
    Path bundle = signedBundle(appKeyPair, APP_SIGNING_KEY_ID);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, catalogKeyPair, sha256(artifact), Files.size(artifact));
    AtomicInteger verificationCount = new AtomicInteger();
    AppCatalogManager manager =
        AppCatalogManager.withBundleVerificationPolicy(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            () -> trustedKeys(catalogKeyPair),
            stagedBundle -> {
              verificationCount.incrementAndGet();
              AppBundleVerifier.verify(stagedBundle, appKeys);
            });
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      manager.verifyInstallPlan(plan);
    }

    assertEquals(2, verificationCount.get());
  }

  @Test
  void verifyInstallPlan_whenCatalogRefreshChangesOriginSubject_expectPlanRejected()
      throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("origin-race-artifact.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys);
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      signedCatalog(
          CATALOG_ID,
          artifact.toUri(),
          keyPair,
          KEY_ID,
          sha256(artifact),
          Files.size(artifact),
          GENERATED_AT.plusSeconds(1));
      manager.refresh(CATALOG_ID);

      AppCatalogException exception =
          assertThrows(AppCatalogException.class, () -> manager.verifyInstallPlan(plan));

      assertTrue(exception.getMessage().contains("changed after plan creation"));
    }
  }

  @Test
  void authorizeInstallPlanForMutation_whenTrustTransitionRuns_expectLeaseDefersTransition()
      throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("mutation-lease-artifact.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("mutation-lease-trust"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, keyPair));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            new AppCatalogSourceStore(tempDir.resolve("mutation-lease-catalogs")),
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(catalog.toString(), CATALOG_ID);

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      AppCatalogManager.CatalogTrustAuthorization authorization =
          manager.authorizeInstallPlanForMutation(plan);
      CountDownLatch transitionStarted = new CountDownLatch(1);
      CompletableFuture<FederatedCatalogTrustBinding> transition =
          CompletableFuture.supplyAsync(
              () -> {
                transitionStarted.countDown();
                try {
                  return manager.transitionFederatedTrustBinding(
                      CATALOG_ID,
                      FederatedCatalogTrustBinding.Status.SUSPENDED,
                      OPERATOR_SUSPENSION_REASON,
                      OPERATOR_ID,
                      GENERATED_AT.plusSeconds(1));
                } catch (IOException exception) {
                  throw new AssertionError(exception);
                }
              });
      try {
        assertTrue(transitionStarted.await(5, TimeUnit.SECONDS));
        assertThrows(TimeoutException.class, () -> transition.get(100, TimeUnit.MILLISECONDS));
        CompletableFuture<List<AppCatalogSourceSnapshot>> listing =
            CompletableFuture.supplyAsync(
                () -> {
                  try {
                    return manager.listCatalogs();
                  } catch (IOException exception) {
                    throw new AssertionError(exception);
                  }
                });
        assertEquals(1, listing.get(5, TimeUnit.SECONDS).size());
        assertEquals(
            FederatedCatalogTrustBinding.Status.ACTIVE,
            trustStore.findByCatalogId(CATALOG_ID).orElseThrow().status());
      } finally {
        authorization.close();
      }

      assertEquals(
          FederatedCatalogTrustBinding.Status.SUSPENDED,
          transition.get(5, TimeUnit.SECONDS).status());
    }
  }

  @Test
  void authorizeInstallPlanForMutation_whenRefreshRuns_expectLeaseDefersSourceReplacement()
      throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("refresh-lease-artifact.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("refresh-lease-trust"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, keyPair));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            new AppCatalogSourceStore(tempDir.resolve("refresh-lease-catalogs")),
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore);
    manager.addSource(catalog.toString(), CATALOG_ID);

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      AppCatalogManager.CatalogTrustAuthorization authorization =
          manager.authorizeInstallPlanForMutation(plan);
      signedCatalog(
          CATALOG_ID,
          artifact.toUri(),
          keyPair,
          KEY_ID,
          sha256(artifact),
          Files.size(artifact),
          GENERATED_AT.plusSeconds(1));
      CountDownLatch refreshStarted = new CountDownLatch(1);
      CompletableFuture<AppCatalogSourceSnapshot> refresh =
          CompletableFuture.supplyAsync(
              () -> {
                refreshStarted.countDown();
                try {
                  return manager.refresh(CATALOG_ID);
                } catch (IOException exception) {
                  throw new AssertionError(exception);
                }
              });
      try {
        assertTrue(refreshStarted.await(5, TimeUnit.SECONDS));
        assertThrows(TimeoutException.class, () -> refresh.get(100, TimeUnit.MILLISECONDS));
        manager.verifyInstallPlan(plan);
      } finally {
        authorization.close();
      }

      assertEquals(GENERATED_AT.plusSeconds(1), refresh.get(5, TimeUnit.SECONDS).generatedAt());
    }
  }

  @Test
  void prepareInstallPlan_whenExplicitBundlePolicyRejectsSubject_expectInvalidBundle()
      throws Exception {
    KeyPair catalogKeyPair = keyPair();
    KeyPair appKeyPair = keyPair();
    Path bundle = signedBundle(appKeyPair, APP_SIGNING_KEY_ID);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, catalogKeyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager =
        AppCatalogManager.withBundleVerificationPolicy(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            () -> trustedKeys(catalogKeyPair),
            _ -> {
              throw new AppDistributionException("publisher subject is outside approval");
            });
    manager.addSource(catalog.toString());

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> prepareAndCloseInstallPlan(manager, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    assertTrue(exception.getMessage().contains("outside approval"));
  }

  @Test
  void prepareInstallPlan_whenAppKeyIsOnlyCatalogTrusted_expectBundleVerificationFails()
      throws Exception {
    KeyPair catalogKeyPair = keyPair();
    KeyPair appKeyPair = keyPair();
    Path bundle = signedBundle(appKeyPair, APP_SIGNING_KEY_ID);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, catalogKeyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager =
        new AppCatalogManager(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            () ->
                TrustedAppKeys.of(
                    trustedKey(KEY_ID, catalogKeyPair), trustedKey(APP_SIGNING_KEY_ID, appKeyPair)),
            TrustedAppKeys::empty);
    manager.addSource(catalog.toString());

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> prepareAndCloseInstallPlan(manager, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void verifyInstallPlan_whenStagedBundleTampered_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys);
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      Files.writeString(
          plan.stagedBundleDirectory().resolve("bin/launch.sh"),
          "#!/bin/sh\nexit 2\n",
          StandardCharsets.UTF_8);

      AppCatalogException exception =
          assertThrows(AppCatalogException.class, () -> manager.verifyInstallPlan(plan));

      assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    }
  }

  @Test
  void addSource_whenCatalogIsSigned_expectSnapshotIncludesSignatureKeyId() throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys);

    AppCatalogSourceSnapshot snapshot = manager.addSource(catalog.toString());
    AppCatalogSourceSnapshot listedSnapshot = manager.listCatalogs().getFirst();

    assertEquals(Optional.of(KEY_ID), snapshot.signatureKeyId());
    assertEquals(Optional.of(KEY_ID), listedSnapshot.signatureKeyId());
  }

  @Test
  void addSource_whenCatalogBytesAreTampered_expectInvalidCatalogSignature() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    Files.writeString(
        catalog, "\n# tampered\n", StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    String catalogSource = catalog.toString();

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.addSource(catalogSource));

    assertEquals("invalid_catalog_signature", exception.errorCode());
  }

  @Test
  void addSource_whenSignerIsUnknown_expectInvalidCatalogSignature() throws Exception {
    KeyPair signingKeyPair = keyPair();
    KeyPair trustedKeyPair = keyPair();
    Path bundle = signedBundle(signingKeyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, signingKeyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(trustedKeyPair));
    String catalogSource = catalog.toString();

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.addSource(catalogSource));

    assertEquals("invalid_catalog_signature", exception.errorCode());
  }

  @Test
  void addSource_whenSignatureSidecarIsMalformed_expectInvalidCatalogSignature() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    Files.writeString(
        catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME),
        MALFORMED_KEY_VALUE_LINE,
        StandardCharsets.UTF_8);
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    String catalogSource = catalog.toString();

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.addSource(catalogSource));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenArtifactDigestMismatches_expectArtifactDigestMismatch()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, "0".repeat(64), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals("artifact_digest_mismatch", exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipContainsTraversal_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = traversalZip(tempDir.resolve("unsafe.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    assertFalse(Files.exists(tempDir.resolve("evil.txt")));
  }

  @Test
  void prepareInstallPlan_whenZipContainsAppleDoubleEntries_expectMetadataIgnored()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectoryWithAppleDouble(bundle, tempDir.resolve("appledouble.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertFalse(Files.exists(plan.stagedBundleDirectory().resolve("._cryptad-app.properties")));
      assertFalse(Files.exists(plan.stagedBundleDirectory().resolve("__MACOSX")));
      assertFalse(Files.exists(plan.stagedBundleDirectory().resolve("bin").resolve("._launch.sh")));
      assertFalse(Files.exists(plan.stagedBundleDirectory().resolve(MACOS_METADATA_FILE)));
      assertFalse(
          Files.exists(plan.stagedBundleDirectory().resolve("bin").resolve(MACOS_METADATA_FILE)));
    }
  }

  @Test
  void prepareInstallPlan_whenZipParentIsFile_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = parentConflictZip(tempDir.resolve("parent-conflict.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipDirectoryParentIsFile_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = directoryParentConflictZip(tempDir.resolve("directory-parent-conflict.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipPayloadIsCorrupt_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("corrupt-payload.zip"));
    corruptManifestZipEntryPayload(artifact);
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipEntryNameIsPathInvalid_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = invalidPathNameZip(tempDir.resolve("invalid-path-name.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipContainsTooManyEntries_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = manyEntriesZip(tempDir.resolve("too-many.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenSignedBundleRequiresExecutableBit_expectExecutableModePreserved()
      throws Exception {
    Assumptions.assumeTrue(
        Files.getFileStore(tempDir).supportsFileAttributeView("posix"),
        "POSIX executable mode preservation requires POSIX file attributes");
    KeyPair keyPair = keyPair();
    Path bundle = signedExecutableBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("executable.zip"));
    setExecutableZipUnixMode(artifact);
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertTrue(Files.isExecutable(plan.stagedBundleDirectory().resolve(EXECUTABLE_PATH)));
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "https:/cryptad-app-catalog.properties",
        "file:cryptad-app-catalog.properties",
        "file://localhost/tmp/cryptad-app-catalog.properties"
      })
  void requireSafeCatalogSourceUri_whenUriIsUnsafe_expectInvalidCatalogSource(String sourceValue) {
    URI source = URI.create(sourceValue);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogSidecars.requireSafeCatalogSourceUri(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://127.example.com/cryptad-app-catalog.properties",
        "ftp://example.invalid/cryptad-app-catalog.properties"
      })
  void requireSafeCatalogSourceUri_whenSchemeIsUnsupported_expectUnsupportedCatalogSource(
      String sourceValue) {
    URI source = URI.create(sourceValue);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogSidecars.requireSafeCatalogSourceUri(source));

    assertEquals(AppCatalogSidecars.UNSUPPORTED_CATALOG_SOURCE, exception.errorCode());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://127.example.com/queue-manager.zip",
        "ftp://example.invalid/queue-manager.zip",
        "https:queue-manager.zip",
        "file:///tmp/queue-manager.zip?download=1"
      })
  void requireSafeArtifactUri_whenUriIsUnsafe_expectInvalidCatalogEntry(String artifactValue) {
    URI artifact = URI.create(artifactValue);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppCatalogSidecars.requireSafeArtifactUri(artifact));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void requireSafeArtifactUri_whenHttpHostIsNumeric127Loopback_expectAllowed() {
    URI artifact = URI.create("http://127.0.0.2/queue-manager.zip");

    assertEquals(artifact, AppCatalogSidecars.requireSafeArtifactUri(artifact));
  }

  @Test
  void parse_whenWindowsDriveLetterCatalogPath_expectLocalFileSource() {
    AppCatalogSource source =
        AppCatalogSource.parse("C:/Cryptad/catalog/cryptad-app-catalog.properties");

    assertEquals("file", source.uri().getScheme());
  }

  @ParameterizedTest
  @CsvSource(
      delimiter = '|',
      textBlock =
          """
          crypta:USK@example/catalog/cryptad-app-catalog.properties | USK@example/catalog/cryptad-app-catalog.properties | crypta:USK@example/catalog/cryptad-app-catalog.signature
          crypta:SSK@example/catalog/cryptad-app-catalog.properties | SSK@example/catalog/cryptad-app-catalog.properties | crypta:SSK@example/catalog/cryptad-app-catalog.signature
          crypta:CHK@catalog-key?signature=CHK@signature-key | CHK@catalog-key | crypta:CHK@signature-key
          """)
  void parse_whenCryptaCatalogSourceIsValid_expectRuntimeKeyAndSignature(
      String sourceValue, String expectedFetchUri, String expectedSignatureUri) {
    AppCatalogSource source = AppCatalogSource.parse(sourceValue);

    assertEquals(AppCatalogSourceKind.CRYPTA, source.kind());
    assertEquals(expectedFetchUri, source.resolvedCatalogFetchUri());
    assertEquals(URI.create(expectedSignatureUri), source.signatureUri());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "crypta:CHK@catalog-key",
        "crypta:USK@example",
        "crypta:USK@example/catalog bad/cryptad-app-catalog.properties",
        "crypta:USK@example/catalog/cryptad-app-catalog.properties#fragment",
        "crypta:SSK@example/catalog/cryptad-app-catalog.properties?signature=CHK@signature-key",
        "crypta:CHK@catalog-key?signature=CHK@signature-key&extra=1"
      })
  void parse_whenCryptaCatalogSourceIsInvalid_expectInvalidCatalogSource(String sourceValue) {
    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogSource.parse(sourceValue));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @Test
  void fetch_whenCryptaSourceUsesContentFetchPort_expectCatalogAndSignatureBytes()
      throws Exception {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = BASIC_CATALOG_SIGNATURE.getBytes(StandardCharsets.UTF_8);
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, signatureBytes));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    FetchedCatalog fetched = fetcher.fetch(source);

    assertEquals(
        List.of(CRYPTA_CATALOG_KEY, CRYPTA_SIGNATURE_KEY), contentFetchPort.requestedKeys());
    org.junit.jupiter.api.Assertions.assertArrayEquals(catalogBytes, fetched.catalogBytes());
    org.junit.jupiter.api.Assertions.assertArrayEquals(signatureBytes, fetched.signatureBytes());
  }

  @Test
  void fetch_whenCryptaCatalogResolvesToUskEdition_expectSignatureFetchedFromResolvedEdition()
      throws Exception {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = BASIC_CATALOG_SIGNATURE.getBytes(StandardCharsets.UTF_8);
    String requestedCatalogKey = "USK@example/catalog/41/cryptad-app-catalog.properties";
    String resolvedCatalogKey = "USK@example/catalog/42/cryptad-app-catalog.properties";
    String resolvedSignatureKey = RESOLVED_SIGNATURE_KEY;
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(requestedCatalogKey, catalogBytes, resolvedSignatureKey, signatureBytes),
            Map.of(requestedCatalogKey, resolvedCatalogKey));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_URI_PREFIX + requestedCatalogKey);

    FetchedCatalog fetched = fetcher.fetch(source);

    assertEquals(
        List.of(requestedCatalogKey, resolvedSignatureKey), contentFetchPort.requestedKeys());
    org.junit.jupiter.api.Assertions.assertArrayEquals(catalogBytes, fetched.catalogBytes());
    org.junit.jupiter.api.Assertions.assertArrayEquals(signatureBytes, fetched.signatureBytes());
    assertEquals(Optional.of(resolvedCatalogKey), fetched.resolvedCatalogUri());
  }

  @Test
  void fetch_whenCryptaResolvedCatalogHasSchemePrefix_expectSignatureFetchedFromResolvedEdition()
      throws Exception {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = BASIC_CATALOG_SIGNATURE.getBytes(StandardCharsets.UTF_8);
    String requestedCatalogKey = LATEST_CATALOG_KEY;
    String resolvedCatalogKey = "crypta:USK@example/catalog/42/cryptad-app-catalog.properties";
    String resolvedSignatureKey = RESOLVED_SIGNATURE_KEY;
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(requestedCatalogKey, catalogBytes, resolvedSignatureKey, signatureBytes),
            Map.of(requestedCatalogKey, resolvedCatalogKey));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_URI_PREFIX + requestedCatalogKey);

    FetchedCatalog fetched = fetcher.fetch(source);

    assertEquals(
        List.of(requestedCatalogKey, resolvedSignatureKey), contentFetchPort.requestedKeys());
    org.junit.jupiter.api.Assertions.assertArrayEquals(catalogBytes, fetched.catalogBytes());
    org.junit.jupiter.api.Assertions.assertArrayEquals(signatureBytes, fetched.signatureBytes());
    assertEquals(Optional.of(resolvedCatalogKey), fetched.resolvedCatalogUri());
  }

  @Test
  void fetch_whenCryptaResolvedCatalogChangesKeyKind_expectInvalidCatalogSource() {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    String requestedCatalogKey = LATEST_CATALOG_KEY;
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(requestedCatalogKey, catalogBytes),
            Map.of(requestedCatalogKey, "SSK@example/catalog/42/cryptad-app-catalog.properties"));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_URI_PREFIX + requestedCatalogKey);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
    assertEquals(List.of(requestedCatalogKey), contentFetchPort.requestedKeys());
  }

  @Test
  void fetch_whenCryptaSourceUsesContentFetchPort_expectBoundedRequests() throws Exception {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = BASIC_CATALOG_SIGNATURE.getBytes(StandardCharsets.UTF_8);
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, signatureBytes));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    fetcher.fetch(source);

    List<BoundedContentFetchRequest> requests = contentFetchPort.requests();
    assertEquals(2, requests.size());
    assertEquals("catalog properties", requests.getFirst().purpose());
    assertEquals(AppCatalogSidecars.MAX_CATALOG_BYTES, requests.get(0).maxBytes());
    assertTrue(requests.get(0).timeout().compareTo(Duration.ZERO) > 0);
    assertEquals(CATALOG_SIGNATURE_PURPOSE, requests.get(1).purpose());
    assertEquals(AppCatalogSidecars.MAX_SIGNATURE_BYTES, requests.get(1).maxBytes());
    assertTrue(requests.get(1).timeout().compareTo(Duration.ZERO) > 0);
  }

  @Test
  void fetch_whenCryptaRuntimeIsUnavailable_expectCatalogFetchUnavailable() {
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), null);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.CATALOG_FETCH_UNAVAILABLE, exception.errorCode());
  }

  @Test
  void fetch_whenCryptaRuntimeRejectsSource_expectInvalidCatalogSource() {
    ContentFetchPort contentFetchPort =
        _ -> {
          throw new ContentFetchException(
              ContentFetchException.INVALID_CATALOG_SOURCE, "invalid runtime key");
        };
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @Test
  void fetch_whenCryptaRuntimeReturnsOversizedSignature_expectCatalogFetchFailed() {
    ContentFetchPort contentFetchPort =
        request -> {
          byte[] bytes =
              CATALOG_SIGNATURE_PURPOSE.equals(request.purpose())
                  ? new byte[(int) AppCatalogSidecars.MAX_SIGNATURE_BYTES + 1]
                  : BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
          return new BoundedContentFetchResult(bytes, request.uri(), null, null);
        };
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.CATALOG_FETCH_FAILED, exception.errorCode());
  }

  @Test
  void fetch_whenCryptaSignatureIsMissing_expectCatalogSignatureMissing() {
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8)));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.CATALOG_SIGNATURE_MISSING, exception.errorCode());
  }

  @Test
  void addSource_whenCryptaSignatureIsInvalid_expectInvalidCatalogSignature() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                MALFORMED_KEY_VALUE_LINE.getBytes(StandardCharsets.UTF_8)));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.addSource(CRYPTA_CATALOG_SOURCE));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
  }

  @Test
  void addSource_whenCryptaFetchReportsResolvedUri_expectSnapshotRecordsResolvedUri()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    String sourceKey = LATEST_CATALOG_KEY;
    String resolvedUri = "USK@example/catalog/42/cryptad-app-catalog.properties";
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                sourceKey,
                Files.readAllBytes(catalog),
                RESOLVED_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))),
            Map.of(sourceKey, resolvedUri));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);

    AppCatalogSourceSnapshot snapshot =
        manager.addSource("crypta:USK@example/catalog/latest/cryptad-app-catalog.properties");

    assertEquals(Optional.of(resolvedUri), snapshot.lastResolvedUri());
    assertEquals(Optional.of(resolvedUri), manager.listCatalogs().getFirst().lastResolvedUri());
  }

  @Test
  void refresh_whenCryptaFetchFails_expectPreviousVerifiedCatalogPreservedAndMetadataUpdated()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    contentFetchPort.failWith(new IOException("content fetch failed"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    List<AppCatalogEntry> entries = manager.listApps(CATALOG_ID);
    AppCatalogSourceSnapshot snapshot = manager.listCatalogs().getFirst();
    AppCatalogMirrorHealth primaryHealth =
        healthFor(manager.sourceHealth(CATALOG_ID), PRIMARY_MIRROR_ID);

    assertEquals(AppCatalogSidecars.CATALOG_FETCH_FAILED, exception.errorCode());
    assertEquals(APP_ID, entries.getFirst().appId());
    assertEquals(AppCatalogFetchStatus.FAILED, snapshot.lastFetchStatus());
    assertEquals(
        Optional.of(AppCatalogSidecars.CATALOG_FETCH_FAILED), snapshot.lastFetchErrorCode());
    assertEquals(snapshot.refreshedAt(), snapshot.lastSuccessfulRefreshAt());
    assertEquals(AppCatalogFetchStatus.FAILED, primaryHealth.lastFetchStatus());
    assertEquals(Optional.of(snapshot.refreshedAt()), primaryHealth.lastSuccessfulRefreshAt());
    assertTrue(primaryHealth.lastCatalogDigest().isPresent());
    assertEquals(Optional.of(KEY_ID), primaryHealth.lastSignatureKeyId());
    assertEquals(Optional.of(GENERATED_AT), primaryHealth.lastGeneratedAt());
  }

  @Test
  void refresh_whenPrimaryFailsAndMirrorIsVerified_expectMirrorFallbackAccepted() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    manager.addMirror(CATALOG_ID, BACKUP_MIRROR_ID, catalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));

    AppCatalogSourceSnapshot refreshed = manager.refresh(CATALOG_ID);
    List<AppCatalogMirrorHealth> health = manager.sourceHealth(CATALOG_ID);

    assertEquals(AppCatalogFetchStatus.SUCCESS, refreshed.lastFetchStatus());
    assertEquals(
        AppCatalogFetchStatus.FAILED, healthFor(health, PRIMARY_MIRROR_ID).lastFetchStatus());
    assertEquals(
        AppCatalogFetchStatus.SUCCESS, healthFor(health, BACKUP_MIRROR_ID).lastFetchStatus());
    assertEquals(Optional.of(KEY_ID), healthFor(health, BACKUP_MIRROR_ID).lastSignatureKeyId());
  }

  @Test
  void updateMirror_whenActiveMirrorSourceChanges_expectActiveRevisionProvenancePreserved()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    String originalMirrorUri = AppCatalogSource.parse(catalog.toString()).resolvedCatalogFetchUri();
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    manager.addMirror(CATALOG_ID, BACKUP_MIRROR_ID, catalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));
    manager.refresh(CATALOG_ID);
    assertEquals(
        AppCatalogFetchStatus.SUCCESS,
        healthFor(manager.sourceHealth(CATALOG_ID), BACKUP_MIRROR_ID).lastFetchStatus());

    manager.updateMirror(CATALOG_ID, BACKUP_MIRROR_ID, MIRROR_SOURCE_URI, null, null);
    AppCatalogMirrorHealth updatedHealth =
        healthFor(manager.sourceHealth(CATALOG_ID), BACKUP_MIRROR_ID);

    assertEquals(AppCatalogFetchStatus.SUCCESS, updatedHealth.lastFetchStatus());
    assertTrue(updatedHealth.lastSuccessfulRefreshAt().isPresent());
    assertTrue(updatedHealth.lastCatalogDigest().isPresent());
    assertEquals(Optional.of(KEY_ID), updatedHealth.lastSignatureKeyId());
    assertEquals(Optional.of(originalMirrorUri), updatedHealth.lastResolvedUri());
  }

  @Test
  void addMirror_whenReusingRemovedActiveMirrorId_expectActiveRevisionProvenancePreserved()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    String originalMirrorUri = AppCatalogSource.parse(catalog.toString()).resolvedCatalogFetchUri();
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = manager(sourceStore, trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    manager.addMirror(CATALOG_ID, BACKUP_MIRROR_ID, catalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));
    manager.refresh(CATALOG_ID);
    assertEquals(
        AppCatalogFetchStatus.SUCCESS,
        healthFor(manager.sourceHealth(CATALOG_ID), BACKUP_MIRROR_ID).lastFetchStatus());

    manager.removeMirror(CATALOG_ID, BACKUP_MIRROR_ID);
    AppCatalogMirrorHealth removedHealth =
        healthFor(manager.sourceHealth(CATALOG_ID), BACKUP_MIRROR_ID);
    assertEquals(AppCatalogFetchStatus.SUCCESS, removedHealth.lastFetchStatus());
    assertEquals(Optional.of(originalMirrorUri), removedHealth.lastResolvedUri());
    assertTrue(
        manager.listMirrors(CATALOG_ID).stream()
            .noneMatch(mirror -> BACKUP_MIRROR_ID.equals(mirror.id().value())));
    manager.addMirror(
        CATALOG_ID,
        BACKUP_MIRROR_ID,
        "https://replacement.example.invalid/cryptad-app-catalog.properties",
        1,
        true);
    AppCatalogMirror reusedMirror =
        manager.listMirrors(CATALOG_ID).stream()
            .filter(mirror -> BACKUP_MIRROR_ID.equals(mirror.id().value()))
            .findFirst()
            .orElseThrow();
    sourceStore.writeMirrorHealth(
        CATALOG_ID, Map.of(reusedMirror.id(), AppCatalogMirrorHealth.skipped(reusedMirror)));
    AppCatalogMirrorHealth reusedHealth =
        healthFor(manager.sourceHealth(CATALOG_ID), BACKUP_MIRROR_ID);

    assertEquals(AppCatalogFetchStatus.SUCCESS, reusedHealth.lastFetchStatus());
    assertTrue(reusedHealth.lastSuccessfulRefreshAt().isPresent());
    assertTrue(reusedHealth.lastCatalogDigest().isPresent());
    assertEquals(Optional.of(KEY_ID), reusedHealth.lastSignatureKeyId());
    assertEquals(Optional.of(originalMirrorUri), reusedHealth.lastResolvedUri());
  }

  @Test
  void updateMirror_whenInactiveMirrorSourceChanges_expectPreviousMirrorHealthCleared()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    byte[] catalogBytes = Files.readAllBytes(catalog);
    byte[] signatureBytes =
        Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, signatureBytes));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    manager.addMirror(CATALOG_ID, BACKUP_MIRROR_ID, catalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));
    manager.refresh(CATALOG_ID);
    contentFetchPort.replaceContent(
        Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, signatureBytes), Map.of());
    manager.refresh(CATALOG_ID);
    assertEquals(
        AppCatalogFetchStatus.SUCCESS,
        healthFor(manager.sourceHealth(CATALOG_ID), PRIMARY_MIRROR_ID).lastFetchStatus());

    manager.updateMirror(CATALOG_ID, BACKUP_MIRROR_ID, MIRROR_SOURCE_URI, null, null);
    AppCatalogMirrorHealth updatedHealth =
        healthFor(manager.sourceHealth(CATALOG_ID), BACKUP_MIRROR_ID);

    assertEquals(AppCatalogFetchStatus.SKIPPED, updatedHealth.lastFetchStatus());
    assertTrue(updatedHealth.lastSuccessfulRefreshAt().isEmpty());
    assertTrue(updatedHealth.lastCatalogDigest().isEmpty());
    assertTrue(updatedHealth.lastSignatureKeyId().isEmpty());
  }

  @Test
  void addMirror_whenEndpointMetadataWouldExceedReadBound_expectRejectedAndCatalogReadable()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));

    manager.addSource(catalog.toString());
    String oversizedSource = oversizedMirrorSource();
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> manager.addMirror(CATALOG_ID, "oversized", oversizedSource, 1, true));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
    assertEquals(APP_ID, manager.listApps(CATALOG_ID).getFirst().appId());
    assertTrue(
        manager.listMirrors(CATALOG_ID).stream()
            .noneMatch(mirror -> "oversized".equals(mirror.id().value())));
  }

  @Test
  void updateMirror_whenEndpointMetadataWouldExceedReadBound_expectExistingMirrorPreserved()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    String originalSource = MIRROR_SOURCE_URI;
    AppCatalogManager manager = manager(trustedKeys(keyPair));

    manager.addSource(catalog.toString());
    manager.addMirror(CATALOG_ID, BACKUP_MIRROR_ID, originalSource, 1, true);
    String oversizedSource = oversizedMirrorSource();
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> manager.updateMirror(CATALOG_ID, BACKUP_MIRROR_ID, oversizedSource, null, null));
    AppCatalogMirror retained =
        manager.listMirrors(CATALOG_ID).stream()
            .filter(mirror -> BACKUP_MIRROR_ID.equals(mirror.id().value()))
            .findFirst()
            .orElseThrow();

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
    assertEquals(
        AppCatalogSource.parse(originalSource).displayUri(), retained.source().displayUri());
    assertEquals(APP_ID, manager.listApps(CATALOG_ID).getFirst().appId());
  }

  @Test
  void writeMirrorHealth_whenHealthMetadataWouldExceedReadBound_expectPreviousHealthPreserved()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = new AppCatalogManager(sourceStore, () -> trustedKeys(keyPair));
    AppCatalogMirrorHealth retainedHealth = failedPrimaryHealth(MIRROR_SOURCE_URI);

    manager.addSource(catalog.toString());
    sourceStore.writeMirrorHealth(CATALOG_ID, Map.of(AppCatalogMirrorId.PRIMARY, retainedHealth));
    String oversizedSource = oversizedMirrorSource();
    Map<AppCatalogMirrorId, AppCatalogMirrorHealth> oversizedHealth =
        Map.of(AppCatalogMirrorId.PRIMARY, failedPrimaryHealth(oversizedSource));
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> sourceStore.writeMirrorHealth(CATALOG_ID, oversizedHealth));
    AppCatalogMirrorHealth storedHealth =
        sourceStore.read(CATALOG_ID).mirrorHealth().get(AppCatalogMirrorId.PRIMARY);

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
    assertEquals(retainedHealth.lastResolvedUri(), storedHealth.lastResolvedUri());
    assertEquals(retainedHealth.lastFetchErrorMessage(), storedHealth.lastFetchErrorMessage());
    assertEquals(APP_ID, manager.listApps(CATALOG_ID).getFirst().appId());
  }

  @Test
  void refresh_whenMirrorReturnsOlderVerifiedRevision_expectCurrentCatalogPreserved()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    Path staleCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT.minusSeconds(3600));
    manager.addMirror(CATALOG_ID, "stale", staleCatalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    AppCatalogSourceSnapshot snapshot = manager.listCatalogs().getFirst();
    List<AppCatalogMirrorHealth> health = manager.sourceHealth(CATALOG_ID);

    assertEquals(AppCatalogSidecars.CATALOG_FETCH_FAILED, exception.errorCode());
    assertEquals(GENERATED_AT, snapshot.generatedAt());
    assertEquals(AppCatalogFetchStatus.FAILED, snapshot.lastFetchStatus());
    assertEquals(AppCatalogFetchStatus.STALE, healthFor(health, "stale").lastFetchStatus());
  }

  @Test
  void refresh_whenMirrorReturnsSameTimestampDifferentCatalog_expectCurrentCatalogPreserved()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    byte[] catalogBytes = Files.readAllBytes(catalog);
    byte[] signatureBytes =
        Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, signatureBytes));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    Path alternateArtifact = tempDir.resolve("alternate-" + ARTIFACT_ZIP);
    Files.copy(artifact, alternateArtifact);
    Path ambiguousCatalog =
        signedCatalog(
            CATALOG_ID,
            alternateArtifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(alternateArtifact),
            Files.size(alternateArtifact),
            GENERATED_AT);
    manager.addMirror(CATALOG_ID, "ambiguous", ambiguousCatalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    AppCatalogSourceSnapshot snapshot = manager.listCatalogs().getFirst();
    AppCatalogEntry entry = manager.listApps(CATALOG_ID).getFirst();
    List<AppCatalogMirrorHealth> health = manager.sourceHealth(CATALOG_ID);

    assertEquals(AppCatalogSidecars.CATALOG_FETCH_FAILED, exception.errorCode());
    assertEquals(GENERATED_AT, snapshot.generatedAt());
    assertEquals(artifact.toUri(), entry.bundleUri());
    assertEquals(AppCatalogFetchStatus.FAILED, snapshot.lastFetchStatus());
    assertEquals(AppCatalogFetchStatus.STALE, healthFor(health, "ambiguous").lastFetchStatus());
  }

  @Test
  void
      refresh_whenPreviouslySuccessfulMirrorLaterReturnsStaleRevision_expectSuccessDigestPreserved()
          throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    Instant successfulMirrorGeneratedAt = GENERATED_AT.plusSeconds(3600);
    Path mirrorCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            successfulMirrorGeneratedAt);
    manager.addMirror(CATALOG_ID, BACKUP_MIRROR_ID, mirrorCatalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));
    manager.refresh(CATALOG_ID);
    AppCatalogMirrorHealth successfulHealth =
        healthFor(manager.sourceHealth(CATALOG_ID), BACKUP_MIRROR_ID);
    Optional<Instant> previousSuccessAt = successfulHealth.lastSuccessfulRefreshAt();
    Optional<String> previousDigest = successfulHealth.lastCatalogDigest();

    signedCatalog(
        CATALOG_ID,
        artifact.toUri(),
        keyPair,
        KEY_ID,
        sha256(artifact),
        Files.size(artifact),
        GENERATED_AT.minusSeconds(3600));
    assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    AppCatalogMirrorHealth staleHealth =
        healthFor(manager.sourceHealth(CATALOG_ID), BACKUP_MIRROR_ID);

    assertEquals(AppCatalogFetchStatus.SUCCESS, successfulHealth.lastFetchStatus());
    assertTrue(previousSuccessAt.isPresent());
    assertTrue(previousDigest.isPresent());
    assertEquals(AppCatalogFetchStatus.STALE, staleHealth.lastFetchStatus());
    assertEquals(previousSuccessAt, staleHealth.lastSuccessfulRefreshAt());
    assertEquals(previousDigest, staleHealth.lastCatalogDigest());
    assertEquals(Optional.of(KEY_ID), staleHealth.lastSignatureKeyId());
    assertEquals(Optional.of(successfulMirrorGeneratedAt), staleHealth.lastGeneratedAt());
  }

  @Test
  void rollback_whenPreviousRevisionIsRetained_expectRevisionReverifiedAndRestored()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    Path newerCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT.plusSeconds(3600));
    manager.addMirror(CATALOG_ID, "mirror-1", newerCatalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));
    AppCatalogSourceSnapshot refreshed = manager.refresh(CATALOG_ID);

    AppCatalogRollbackCandidate candidate =
        manager.rollbackCandidates(CATALOG_ID).stream()
            .filter(AppCatalogRollbackCandidate::eligible)
            .findFirst()
            .orElseThrow();
    String rollbackReason = " operator rollback after bad publication ";
    AppCatalogSourceSnapshot rolledBack =
        manager.rollback(CATALOG_ID, candidate.revision().revisionDigest(), rollbackReason);
    AppCatalogRollbackCandidate currentRevision =
        manager.rollbackCandidates(CATALOG_ID).stream()
            .filter(current -> current.revision().current())
            .findFirst()
            .orElseThrow();
    AppCatalogMirrorHealth primaryHealth =
        healthFor(manager.sourceHealth(CATALOG_ID), PRIMARY_MIRROR_ID);

    assertEquals(GENERATED_AT.plusSeconds(3600), refreshed.generatedAt());
    assertEquals(GENERATED_AT, rolledBack.generatedAt());
    assertEquals(AppCatalogFetchStatus.SUCCESS, rolledBack.lastFetchStatus());
    assertEquals(
        Optional.of("operator rollback after bad publication"),
        currentRevision.revision().rollbackReason());
    assertEquals(
        Optional.of("operator rollback after bad publication"), primaryHealth.lastRollbackReason());
  }

  @Test
  void rollback_whenFederatedBindingIsSuspended_expectHistoricalRevisionRestoredOnly()
      throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("suspended-rollback-artifact.zip"));
    Path initialCatalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(initialCatalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    initialCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve("suspended-rollback-catalogs"));
    FileFederatedCatalogTrustStore trustStore =
        new FileFederatedCatalogTrustStore(tempDir.resolve("suspended-rollback-trust"));
    trustStore.put(federatedBinding(CORE_BINDING_ID, CATALOG_ID, KEY_ID, keyPair));
    AppCatalogManager manager =
        AppCatalogManager.withFederatedTrustPolicy(
            sourceStore,
            () -> trustedKeys,
            AppCatalogBundleVerificationPolicy.fromTrustedKeys(() -> trustedKeys),
            trustStore,
            contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE, CATALOG_ID);
    Path newerCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT.plusSeconds(3600));
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY,
            Files.readAllBytes(newerCatalog),
            CRYPTA_SIGNATURE_KEY,
            Files.readAllBytes(
                newerCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))),
        Map.of());
    manager.refresh(CATALOG_ID);
    manager.transitionFederatedTrustBinding(
        CATALOG_ID,
        FederatedCatalogTrustBinding.Status.SUSPENDED,
        OPERATOR_SUSPENSION_REASON,
        OPERATOR_ID,
        GENERATED_AT.plusSeconds(7200));

    AppCatalogRollbackCandidate candidate =
        manager.rollbackCandidates(CATALOG_ID).stream()
            .filter(AppCatalogRollbackCandidate::eligible)
            .findFirst()
            .orElseThrow();
    AppCatalogSourceSnapshot rolledBack =
        manager.rollback(CATALOG_ID, candidate.revision().revisionDigest(), "suspended rollback");

    assertEquals(GENERATED_AT, rolledBack.generatedAt());
    assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    assertThrows(AppCatalogException.class, () -> prepareAndCloseInstallPlan(manager, APP_ID));
  }

  @Test
  void rollback_whenMirrorRevisionSourceWasRemoved_expectRollbackProvenancePreserved()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path initialCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT);
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(initialCatalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    initialCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    Path mirrorCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT.plusSeconds(3600));
    String mirrorResolvedUri =
        AppCatalogSource.parse(mirrorCatalog.toString()).resolvedCatalogFetchUri();
    manager.addMirror(CATALOG_ID, BACKUP_MIRROR_ID, mirrorCatalog.toString(), 1, true);
    contentFetchPort.failWith(new IOException(PRIMARY_UNAVAILABLE_MESSAGE));
    AppCatalogSourceSnapshot mirrorRefresh = manager.refresh(CATALOG_ID);
    Path primaryCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT.plusSeconds(7200));
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY,
            Files.readAllBytes(primaryCatalog),
            CRYPTA_SIGNATURE_KEY,
            Files.readAllBytes(
                primaryCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))),
        Map.of());
    AppCatalogSourceSnapshot primaryRefresh = manager.refresh(CATALOG_ID);
    manager.removeMirror(CATALOG_ID, BACKUP_MIRROR_ID);

    AppCatalogRollbackCandidate mirrorCandidate =
        manager.rollbackCandidates(CATALOG_ID).stream()
            .filter(candidate -> BACKUP_MIRROR_ID.equals(candidate.revision().sourceId().value()))
            .findFirst()
            .orElseThrow();
    AppCatalogSourceSnapshot rolledBack =
        manager.rollback(
            CATALOG_ID, mirrorCandidate.revision().revisionDigest(), "bad publication");
    List<AppCatalogMirrorHealth> health = manager.sourceHealth(CATALOG_ID);
    AppCatalogMirrorHealth mirrorHealth = healthFor(health, BACKUP_MIRROR_ID);

    assertEquals(GENERATED_AT.plusSeconds(3600), mirrorRefresh.generatedAt());
    assertEquals(GENERATED_AT.plusSeconds(7200), primaryRefresh.generatedAt());
    assertTrue(mirrorCandidate.eligible());
    assertEquals(GENERATED_AT.plusSeconds(3600), rolledBack.generatedAt());
    assertEquals(Optional.of(mirrorResolvedUri), rolledBack.lastResolvedUri());
    assertEquals(AppCatalogSourceRole.MIRROR, mirrorHealth.role());
    assertEquals(AppCatalogFetchStatus.SUCCESS, mirrorHealth.lastFetchStatus());
    assertEquals(Optional.of(mirrorResolvedUri), mirrorHealth.lastResolvedUri());
    assertEquals(
        Optional.of(mirrorCandidate.revision().revisionDigest()), mirrorHealth.lastCatalogDigest());
    assertTrue(
        manager.listMirrors(CATALOG_ID).stream()
            .noneMatch(mirror -> BACKUP_MIRROR_ID.equals(mirror.id().value())));
  }

  @Test
  void rollback_whenRevisionDigestContainsPathTraversal_expectInvalidRevisionDigest()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> manager.rollback(CATALOG_ID, "sha256:../../core", "bad publication"));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @Test
  void refresh_whenCatalogSignatureKeyRotates_expectSnapshotIncludesRefreshedSignatureKeyId()
      throws Exception {
    KeyPair initialKeyPair = keyPair();
    KeyPair rotatedKeyPair = keyPair();
    Path bundle = signedBundle(initialKeyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            initialKeyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact));
    byte[] initialCatalogBytes = Files.readAllBytes(catalog);
    byte[] initialSignatureBytes =
        Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    Path refreshedCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            rotatedKeyPair,
            ROTATED_KEY_ID,
            sha256(artifact),
            Files.size(artifact));
    byte[] refreshedCatalogBytes = Files.readAllBytes(refreshedCatalog);
    byte[] refreshedSignatureBytes =
        Files.readAllBytes(
            refreshedCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                initialCatalogBytes,
                CRYPTA_SIGNATURE_KEY,
                initialSignatureBytes));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
            trustedKey(KEY_ID, initialKeyPair), trustedKey(ROTATED_KEY_ID, rotatedKeyPair));
    AppCatalogManager manager = manager(trustedKeys, contentFetchPort);
    AppCatalogSourceSnapshot added = manager.addSource(CRYPTA_CATALOG_SOURCE);
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY,
            refreshedCatalogBytes,
            CRYPTA_SIGNATURE_KEY,
            refreshedSignatureBytes),
        Map.of());

    AppCatalogSourceSnapshot refreshed = manager.refresh(CATALOG_ID);
    AppCatalogSourceSnapshot listedSnapshot = manager.listCatalogs().getFirst();

    assertEquals(Optional.of(KEY_ID), added.signatureKeyId());
    assertEquals(Optional.of(ROTATED_KEY_ID), refreshed.signatureKeyId());
    assertEquals(Optional.of(ROTATED_KEY_ID), listedSnapshot.signatureKeyId());
  }

  @Test
  void keyRotationStatus_whenCachedCatalogBytesAreCorrupted_expectSignatureVerificationFailure()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = new AppCatalogManager(sourceStore, () -> trustedKeys(keyPair));
    manager.addSource(catalog.toString());
    Files.writeString(
        sourceStore
            .rootDirectory()
            .resolve(CATALOG_ID)
            .resolve(AppCatalogSignature.CATALOG_FILE_NAME),
        "\n# tampered\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.keyRotationStatus(CATALOG_ID));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
  }

  @Test
  void keyRotationStatus_whenCurrentCatalogKeyBecomesRetired_expectHistoricalTrustOnly()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AtomicReference<TrustedAppKeys> registry =
        new AtomicReference<>(lifecycleKeys(keyPair, TrustedAppKeyLifecycle.ACTIVE));
    AppCatalogManager manager =
        new AppCatalogManager(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            registry::get);
    manager.addSource(catalog.toString());

    registry.set(lifecycleKeys(keyPair, TrustedAppKeyLifecycle.RETIRED));
    AppCatalogKeyRotationStatus status = manager.keyRotationStatus(CATALOG_ID);

    assertFalse(manager.hasTrustedCatalogKey(KEY_ID));
    assertTrue(status.currentKeyTrusted());
    assertEquals(List.of(), status.blockerReasons());
    assertEquals(CATALOG_ID, manager.listCatalogs().getFirst().catalogId());
  }

  @ParameterizedTest
  @EnumSource(
      value = TrustedAppKeyLifecycle.class,
      names = {"RETIRING", "RETIRED"})
  void prepareInstallPlan_whenCatalogKeyIsNotActive_expectHistoricalInspectionOnly(
      TrustedAppKeyLifecycle lifecycle) throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AtomicReference<TrustedAppKeys> registry =
        new AtomicReference<>(lifecycleKeys(keyPair, TrustedAppKeyLifecycle.ACTIVE));
    AppCatalogManager manager =
        new AppCatalogManager(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            registry::get);
    manager.addSource(catalog.toString());
    registry.set(lifecycleKeys(keyPair, lifecycle));

    List<AppCatalogEntry> inspectedEntries = manager.listApps(CATALOG_ID);
    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> prepareAndCloseInstallPlan(manager, APP_ID));

    assertEquals(APP_ID, inspectedEntries.getFirst().appId());
    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
    assertEquals(
        "trusted catalog key is not authorized for routine catalog verification: " + KEY_ID,
        exception.getMessage());
  }

  @Test
  void refresh_whenCatalogIsResignedWithSameBytes_expectBothRevisionSignaturesRetained()
      throws Exception {
    KeyPair initialKeyPair = keyPair();
    KeyPair rotatedKeyPair = keyPair();
    Path bundle = signedBundle(initialKeyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path initialCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            initialKeyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT);
    byte[] initialCatalogBytes = Files.readAllBytes(initialCatalog);
    byte[] initialSignatureBytes =
        Files.readAllBytes(initialCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    Path rotatedCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            rotatedKeyPair,
            ROTATED_KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT);
    byte[] rotatedCatalogBytes = Files.readAllBytes(rotatedCatalog);
    byte[] rotatedSignatureBytes =
        Files.readAllBytes(rotatedCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                initialCatalogBytes,
                CRYPTA_SIGNATURE_KEY,
                initialSignatureBytes));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
            trustedKey(KEY_ID, initialKeyPair), trustedKey(ROTATED_KEY_ID, rotatedKeyPair));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = manager(sourceStore, trustedKeys, contentFetchPort);

    manager.addSource(CRYPTA_CATALOG_SOURCE);
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY, rotatedCatalogBytes, CRYPTA_SIGNATURE_KEY, rotatedSignatureBytes),
        Map.of());
    manager.refresh(CATALOG_ID);

    assertArrayEquals(initialCatalogBytes, rotatedCatalogBytes);
    String currentDigest =
        AppCatalogRevisions.catalogDigest(
            new FetchedCatalog(rotatedCatalogBytes, rotatedSignatureBytes));
    List<AppCatalogVerifiedRevision> revisions =
        sourceStore.listRevisions(CATALOG_ID, currentDigest);
    List<String> signatureKeyIds =
        revisions.stream().map(AppCatalogVerifiedRevision::signatureKeyId).toList();

    assertEquals(2, revisions.size());
    assertEquals(
        2, revisions.stream().map(AppCatalogVerifiedRevision::revisionDigest).distinct().count());
    assertTrue(signatureKeyIds.contains(KEY_ID));
    assertTrue(signatureKeyIds.contains(ROTATED_KEY_ID));
    assertTrue(
        revisions.stream()
            .anyMatch(
                revision ->
                    revision.current() && ROTATED_KEY_ID.equals(revision.signatureKeyId())));
    assertEquals(Optional.of(KEY_ID), manager.keyRotationStatus(CATALOG_ID).previousKeyId());
  }

  @Test
  void refresh_whenCachedCatalogKeyIsNoLongerTrusted_expectFreshTrustedCatalogReplacesCache()
      throws Exception {
    KeyPair initialKeyPair = keyPair();
    KeyPair rotatedKeyPair = keyPair();
    Path bundle = signedBundle(initialKeyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path initialCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            initialKeyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT);
    byte[] initialCatalogBytes = Files.readAllBytes(initialCatalog);
    byte[] initialSignatureBytes =
        Files.readAllBytes(initialCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    Path rotatedCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            rotatedKeyPair,
            ROTATED_KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT.plusSeconds(3600));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                initialCatalogBytes,
                CRYPTA_SIGNATURE_KEY,
                initialSignatureBytes));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager initialManager =
        manager(sourceStore, trustedKeys(initialKeyPair), contentFetchPort);
    initialManager.addSource(CRYPTA_CATALOG_SOURCE);
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY,
            Files.readAllBytes(rotatedCatalog),
            CRYPTA_SIGNATURE_KEY,
            Files.readAllBytes(
                rotatedCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))),
        Map.of());
    AppCatalogManager rotatedManager =
        manager(
            sourceStore,
            TrustedAppKeys.of(trustedKey(ROTATED_KEY_ID, rotatedKeyPair)),
            contentFetchPort);

    AppCatalogSourceSnapshot refreshed = rotatedManager.refresh(CATALOG_ID);

    assertEquals(GENERATED_AT.plusSeconds(3600), refreshed.generatedAt());
    assertEquals(Optional.of(ROTATED_KEY_ID), refreshed.signatureKeyId());
    assertEquals(APP_ID, rotatedManager.listApps(CATALOG_ID).getFirst().appId());
  }

  @Test
  void refresh_whenCryptaVerificationFailsAfterResolvedFetch_expectMetadataUsesResolvedUri()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    byte[] catalogBytes = Files.readAllBytes(catalog);
    byte[] validSignatureBytes =
        Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    String resolvedCatalogKey = "USK@example/catalog/99/cryptad-app-catalog.properties";
    String resolvedSignatureKey = "USK@example/catalog/99/cryptad-app-catalog.signature";
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, validSignatureBytes));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY,
            catalogBytes,
            resolvedSignatureKey,
            MALFORMED_KEY_VALUE_LINE.getBytes(StandardCharsets.UTF_8)),
        Map.of(CRYPTA_CATALOG_KEY, resolvedCatalogKey));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    AppCatalogSourceSnapshot snapshot = manager.listCatalogs().getFirst();

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
    assertEquals(AppCatalogFetchStatus.FAILED, snapshot.lastFetchStatus());
    assertEquals(
        Optional.of(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE), snapshot.lastFetchErrorCode());
    assertEquals(Optional.of(resolvedCatalogKey), snapshot.lastResolvedUri());
  }

  @Test
  void refresh_whenPersistenceWriteFails_expectIOExceptionAndNoFetchFailureMetadata()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = new AppCatalogManager(sourceStore, () -> trustedKeys);
    manager.addSource(catalog.toString());
    AppCatalogSourceSnapshot beforeRefresh = manager.listCatalogs().getFirst();
    AppCatalogSourceStore failingStore =
        new AppCatalogSourceStore(
            sourceStore.rootDirectory(),
            (_, _, _) -> {
              throw new IOException("metadata write failed");
            });
    AppCatalogManager failingManager = new AppCatalogManager(failingStore, () -> trustedKeys);

    IOException exception =
        assertThrows(IOException.class, () -> failingManager.refresh(CATALOG_ID));
    AppCatalogSourceSnapshot afterRefresh = manager.listCatalogs().getFirst();

    assertEquals("metadata write failed", exception.getMessage());
    assertEquals(beforeRefresh.refreshedAt(), afterRefresh.refreshedAt());
    assertEquals(AppCatalogFetchStatus.SUCCESS, afterRefresh.lastFetchStatus());
    assertTrue(afterRefresh.lastFetchErrorCode().isEmpty());
  }

  @Test
  void refresh_whenRevisionPruneRejectsCorruptHistory_expectActiveCatalogRestored()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path initialCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT);
    byte[] initialCatalogBytes = Files.readAllBytes(initialCatalog);
    byte[] initialSignatureBytes =
        Files.readAllBytes(initialCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    Path refreshedCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            keyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact),
            GENERATED_AT.plusSeconds(3600));
    byte[] refreshedCatalogBytes = Files.readAllBytes(refreshedCatalog);
    byte[] refreshedSignatureBytes =
        Files.readAllBytes(
            refreshedCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                initialCatalogBytes,
                CRYPTA_SIGNATURE_KEY,
                initialSignatureBytes));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = manager(sourceStore, trustedKeys(keyPair), contentFetchPort);

    manager.addSource(CRYPTA_CATALOG_SOURCE);
    AppCatalogSourceSnapshot beforeRefresh = manager.listCatalogs().getFirst();
    String initialRevisionDigest =
        AppCatalogRevisions.catalogDigest(
            new FetchedCatalog(initialCatalogBytes, initialSignatureBytes));
    Files.writeString(
        sourceStore
            .rootDirectory()
            .resolve(CATALOG_ID)
            .resolve("history")
            .resolve(AppCatalogRevisions.digestDirectoryName(initialRevisionDigest))
            .resolve("revision.properties"),
        "unsupported.property=true\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY,
            refreshedCatalogBytes,
            CRYPTA_SIGNATURE_KEY,
            refreshedSignatureBytes),
        Map.of());

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    AppCatalogSourceSnapshot afterRefresh = manager.listCatalogs().getFirst();

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
    assertEquals(beforeRefresh.generatedAt(), afterRefresh.generatedAt());
    assertEquals(beforeRefresh.signatureKeyId(), afterRefresh.signatureKeyId());
    assertEquals(beforeRefresh.refreshedAt(), afterRefresh.refreshedAt());
    assertEquals(AppCatalogFetchStatus.SUCCESS, afterRefresh.lastFetchStatus());
  }

  @Test
  void entry_whenArtifactUriIsCryptaChk_expectAccepted() {
    String artifactDigest = "0".repeat(64);
    List<String> permissions = List.of(QUEUE_READ_PERMISSION);

    AppCatalogEntry entry =
        new AppCatalogEntry(
            APP_ID,
            APP_NAME,
            APP_VERSION,
            APP_SUMMARY,
            CRYPTA_ARTIFACT_URI,
            artifactDigest,
            1L,
            AppCatalogEntry.ZIP_BUNDLE_TYPE,
            permissions);

    assertEquals(CRYPTA_ARTIFACT_URI, entry.bundleUri());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "crypta:USK@example/apps/queue-manager.zip",
        "crypta:SSK@example/apps/queue-manager.zip",
        "crypta:CHK@bundle-key?signature=CHK@signature-key"
      })
  void entry_whenArtifactUriIsUnsupportedCryptaForm_expectInvalidCatalogEntry(String uri) {
    String artifactDigest = "0".repeat(64);
    List<String> permissions = List.of(QUEUE_READ_PERMISSION);
    URI artifactUri = URI.create(uri);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                new AppCatalogEntry(
                    APP_ID,
                    APP_NAME,
                    APP_VERSION,
                    APP_SUMMARY,
                    artifactUri,
                    artifactDigest,
                    1L,
                    AppCatalogEntry.ZIP_BUNDLE_TYPE,
                    permissions));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenCryptaArtifactUsesContentFetchPort_expectVerifiedPlan()
      throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog =
        signedCatalog(
            CATALOG_ID, CRYPTA_ARTIFACT_URI, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME)),
                CRYPTA_ARTIFACT_KEY,
                Files.readAllBytes(artifact)));
    AppCatalogManager manager =
        new AppCatalogManager(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            () -> trustedKeys,
            contentFetchPort);

    manager.addSource(CRYPTA_CATALOG_SOURCE);
    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertTrue(Files.isDirectory(plan.stagedBundleDirectory()));
    }

    assertEquals(
        List.of(CRYPTA_CATALOG_KEY, CRYPTA_SIGNATURE_KEY, CRYPTA_ARTIFACT_KEY),
        contentFetchPort.requestedKeys());
  }

  @Test
  void download_whenCryptaArtifactUsesStreamingFetch_expectVerifiedArtifact() throws Exception {
    byte[] artifactBytes = new byte[] {1, 2, 3};
    List<String> streamedKeys = new java.util.ArrayList<>();
    ContentFetchPort contentFetchPort =
        new ContentFetchPort() {
          @Override
          public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request)
              throws ContentFetchException {
            throw new ContentFetchException(
                ContentFetchException.CATALOG_FETCH_FAILED,
                "materialized artifact fetch should not be used");
          }

          @Override
          public void fetchContent(BoundedContentFetchRequest request, OutputStream destination)
              throws IOException {
            streamedKeys.add(request.uri());
            destination.write(artifactBytes);
          }
        };
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-streaming");

    Path downloaded =
        downloader.download(
            cryptaEntry(sha256(artifactBytes), artifactBytes.length), scratchDirectory);

    assertEquals(List.of(CRYPTA_ARTIFACT_KEY), streamedKeys);
    assertEquals(artifactBytes.length, Files.size(downloaded));
    assertEquals(sha256(artifactBytes), sha256(downloaded));
  }

  @Test
  void addSource_whenExpectedCatalogIdDiffers_expectCatalogIdMismatchAndNoStoredSource()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    String catalogSource = catalog.toString();

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.addSource(catalogSource, "other-catalog"));

    assertEquals(AppCatalogSidecars.CATALOG_ID_MISMATCH, exception.errorCode());
    assertTrue(manager.listCatalogs().isEmpty());
  }

  @Test
  void download_whenCryptaRuntimeIsUnavailable_expectArtifactFetchUnavailable() {
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)),
            (ContentFetchPort) null);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-unavailable");
    AppCatalogEntry entry = cryptaEntry("0".repeat(64), 1L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_FETCH_UNAVAILABLE, exception.errorCode());
  }

  @Test
  void download_whenCryptaFetchFails_expectArtifactDownloadFailed() {
    ContentFetchPort contentFetchPort =
        _ -> {
          throw new ContentFetchException(
              ContentFetchException.CATALOG_FETCH_FAILED, "content is unavailable");
        };
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-failed");
    AppCatalogEntry entry = cryptaEntry("0".repeat(64), 1L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
  }

  @Test
  void download_whenCryptaArtifactDigestMismatches_expectArtifactDigestMismatch() {
    ContentFetchPort contentFetchPort =
        request -> new BoundedContentFetchResult(new byte[] {1}, request.uri(), null, null);
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-digest");
    AppCatalogEntry entry = cryptaEntry("0".repeat(64), 1L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH, exception.errorCode());
  }

  @Test
  void download_whenCryptaArtifactByteCountMismatches_expectArtifactDigestMismatch()
      throws Exception {
    ContentFetchPort contentFetchPort =
        request -> new BoundedContentFetchResult(new byte[] {1}, request.uri(), null, null);
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-size");
    AppCatalogEntry entry = cryptaEntry(sha256(new byte[] {1}), 2L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH, exception.errorCode());
  }

  @Test
  void download_whenCryptaArtifactExceedsDeclaredByteCount_expectArtifactDownloadFailed()
      throws Exception {
    byte[] artifactBytes = new byte[] {1, 2};
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(Map.of(CRYPTA_ARTIFACT_KEY, artifactBytes));
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-oversize");
    AppCatalogEntry entry = cryptaEntry(sha256(artifactBytes), 1L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
  }

  @Test
  void fetch_whenRemoteStatusRejected_expectResponseBodyClosed() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(new FixedResponseHttpClient(new InputStreamResponse(404, body)));
    AppCatalogSource source =
        new AppCatalogSource(URI.create("http://localhost/cryptad-app-catalog.properties"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
    assertTrue(body.closed());
  }

  @Test
  void fetch_whenRemoteTransportFails_expectInvalidCatalogSource() {
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(new FixedResponseHttpClient(new IOException("connect failed")));
    AppCatalogSource source =
        new AppCatalogSource(URI.create("http://localhost/cryptad-app-catalog.properties"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @Test
  void download_whenRemoteStatusRejected_expectResponseBodyClosed() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new InputStreamResponse(404, body)));
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-status");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
    assertTrue(body.closed());
  }

  @Test
  void download_whenRemoteTransportFails_expectArtifactDownloadFailed() {
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException("connect failed")));
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-transport");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
  }

  @Test
  void download_whenLocalArtifactIsMissing_expectArtifactDownloadFailed() {
    AppCatalogArtifactDownloader downloader = new AppCatalogArtifactDownloader();
    AppCatalogEntry entry = localEntry(tempDir.resolve("missing.zip"));
    Path scratchDirectory = tempDir.resolve("scratch-missing");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
  }

  @Test
  void download_whenRemoteContentLengthRejected_expectResponseBodyClosed() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(InputStreamResponse.withContentLength(body, "2")));
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-length");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH, exception.errorCode());
    assertTrue(body.closed());
  }

  @Test
  void download_whenArtifactValidationAndCleanupFail_expectCatalogErrorPreserved() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    IOException cleanupFailure = new IOException("delete failed");
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(InputStreamResponse.withContentLength(body, "2")),
            (AppCatalogArtifactDownloader.ArtifactCleaner)
                _ -> {
                  throw cleanupFailure;
                });
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-cleanup-failure");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH, exception.errorCode());
    assertEquals(1, exception.getSuppressed().length);
    assertEquals(cleanupFailure, exception.getSuppressed()[0]);
    assertTrue(body.closed());
  }

  @Test
  void download_whenRemoteContentLengthIsMalformed_expectArtifactDownloadFailed() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(
                InputStreamResponse.withContentLength(body, "not-a-number")));
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-bad-length");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
    assertTrue(body.closed());
  }

  @Test
  void addSource_whenCatalogIdIsStaging_expectCatalogIsListedAndScratchUsesHiddenDirectory()
      throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog =
        signedCatalog(
            STAGING_CATALOG_ID, artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = new AppCatalogManager(sourceStore, () -> trustedKeys);

    manager.addSource(catalog.toString());
    List<AppCatalogSourceSnapshot> catalogs = manager.listCatalogs();

    assertEquals(STAGING_CATALOG_ID, catalogs.getFirst().catalogId());
    assertEquals(sourceStore.rootDirectory().resolve(".staging"), sourceStore.stagingDirectory());
    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(STAGING_CATALOG_ID, APP_ID)) {
      assertTrue(plan.scratchDirectory().startsWith(sourceStore.stagingDirectory()));
    }
  }

  private AppCatalogManager manager(TrustedAppKeys trustedKeys) {
    return new AppCatalogManager(
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
        () -> trustedKeys);
  }

  static FederatedCatalogTrustBinding federatedBinding(
      String bindingId, String catalogId, String keyId, KeyPair keyPair) {
    return FederatedCatalogTrustBinding.create(
        bindingId,
        catalogId,
        Map.of(keyId, PublicKeyFingerprint.sha256(keyPair.getPublic())),
        FederatedCatalogTrustBinding.Status.ACTIVE,
        Set.of(AppCatalogChannel.STABLE),
        100,
        null,
        null,
        null,
        GENERATED_AT,
        GENERATED_AT,
        "operator approval",
        OPERATOR_ID);
  }

  @SuppressWarnings("EmptyTryBlock")
  private static void prepareAndCloseInstallPlan(AppCatalogManager manager, String appId)
      throws IOException {
    try (var _ = manager.prepareInstallPlan(CATALOG_ID, appId)) {
      // An unexpected successful plan still owns scratch state that must be released.
    }
  }

  private AppCatalogManager manager(
      TrustedAppKeys trustedKeys, FakeContentFetchPort contentFetchPort) {
    return manager(
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
        trustedKeys,
        contentFetchPort);
  }

  private AppCatalogManager manager(
      AppCatalogSourceStore sourceStore,
      TrustedAppKeys trustedKeys,
      FakeContentFetchPort contentFetchPort) {
    return new AppCatalogManager(
        sourceStore,
        () -> trustedKeys,
        new AppCatalogManagerDependencies(
            new AppCatalogFetcher(
                new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)),
                contentFetchPort),
            new AppCatalogArtifactDownloader(),
            new AppCatalogBundleExtractor(),
            AppReviewTransparencyLog.fileBacked(sourceStore.reviewTransparencyLogFile())));
  }

  private static AppCatalogMirrorHealth healthFor(
      List<AppCatalogMirrorHealth> health, String sourceId) {
    return health.stream()
        .filter(entry -> entry.id().value().equals(sourceId))
        .findFirst()
        .orElseThrow();
  }

  private static String oversizedMirrorSource() {
    return "https://mirror.example.invalid/"
        + "a".repeat((int) AppCatalogSidecars.MAX_SIGNATURE_BYTES)
        + "/cryptad-app-catalog.properties";
  }

  private static AppCatalogMirrorHealth failedPrimaryHealth(String resolvedUri) {
    return new AppCatalogMirrorHealth(
        AppCatalogMirrorId.PRIMARY,
        AppCatalogSourceRole.PRIMARY,
        AppCatalogFetchStatus.FAILED,
        Optional.of(GENERATED_AT),
        Optional.empty(),
        Optional.of(AppCatalogSidecars.CATALOG_FETCH_FAILED),
        Optional.of("fetch failed"),
        Optional.of(resolvedUri),
        Optional.empty(),
        Optional.empty(),
        Optional.empty());
  }

  Path signedBundle(KeyPair keyPair) throws IOException {
    return signedBundle(keyPair, KEY_ID);
  }

  Path signedBundle(KeyPair keyPair, String keyId) throws IOException {
    Path root = Files.createDirectories(tempDir.resolve("bundle").resolve(APP_ID));
    Path bin = Files.createDirectories(root.resolve("bin"));
    Files.writeString(bin.resolve("launch.sh"), "#!/bin/sh\nexit 0\n", StandardCharsets.UTF_8);
    Files.writeString(
        root.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s,%s
        """
            .formatted(
                APP_ID, APP_NAME, APP_VERSION, QUEUE_READ_PERMISSION, QUEUE_WRITE_PERMISSION),
        StandardCharsets.UTF_8);
    AppBundleSigner.sign(root, keyId, keyPair.getPrivate());
    return root;
  }

  private Path unsignedBundle() throws IOException {
    Path root = Files.createDirectories(tempDir.resolve("unsigned-bundle").resolve(APP_ID));
    Path bin = Files.createDirectories(root.resolve("bin"));
    Files.writeString(bin.resolve("launch.sh"), "#!/bin/sh\nexit 0\n", StandardCharsets.UTF_8);
    Files.writeString(
        root.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s,%s
        """
            .formatted(
                APP_ID, APP_NAME, APP_VERSION, QUEUE_READ_PERMISSION, QUEUE_WRITE_PERMISSION),
        StandardCharsets.UTF_8);
    return root;
  }

  private Path signedExecutableBundle(KeyPair keyPair) throws IOException {
    Path root = Files.createDirectories(tempDir.resolve("bundle").resolve(APP_ID));
    Files.createDirectories(root.resolve("bin"));
    Path executable = root.resolve(EXECUTABLE_PATH);
    Files.writeString(executable, "echo sample\n", StandardCharsets.UTF_8);
    Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));
    Files.writeString(
        root.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=%s
        app.permissions=%s,%s
        """
            .formatted(
                APP_ID,
                APP_NAME,
                APP_VERSION,
                EXECUTABLE_PATH,
                QUEUE_READ_PERMISSION,
                QUEUE_WRITE_PERMISSION),
        StandardCharsets.UTF_8);
    AppBundleSigner.sign(root, KEY_ID, keyPair.getPrivate());
    return root;
  }

  Path signedCatalog(Path artifact, KeyPair keyPair, String artifactSha256, long artifactSize)
      throws IOException {
    return signedCatalog(CATALOG_ID, artifact, keyPair, artifactSha256, artifactSize);
  }

  private Path signedCatalog(
      String catalogId, Path artifact, KeyPair keyPair, String artifactSha256, long artifactSize)
      throws IOException {
    return signedCatalog(catalogId, artifact.toUri(), keyPair, artifactSha256, artifactSize);
  }

  private Path signedCatalog(
      String catalogId, URI artifactUri, KeyPair keyPair, String artifactSha256, long artifactSize)
      throws IOException {
    return signedCatalog(catalogId, artifactUri, keyPair, KEY_ID, artifactSha256, artifactSize);
  }

  Path signedCatalog(
      String catalogId,
      URI artifactUri,
      KeyPair keyPair,
      String keyId,
      String artifactSha256,
      long artifactSize)
      throws IOException {
    return signedCatalog(
        catalogId, artifactUri, keyPair, keyId, artifactSha256, artifactSize, GENERATED_AT);
  }

  Path signedCatalog(
      String catalogId,
      URI artifactUri,
      KeyPair keyPair,
      String keyId,
      String artifactSha256,
      long artifactSize,
      Instant generatedAt)
      throws IOException {
    Path catalogDir = Files.createDirectories(tempDir.resolve("catalog-" + catalogId));
    Path catalog = catalogDir.resolve(AppCatalogSignature.CATALOG_FILE_NAME);
    Files.writeString(
        catalog,
        """
        catalog.version=1
        catalog.id=%s
        catalog.name=Crypta Core Apps
        catalog.generatedAt=%s
        catalog.entries=%s
        app.%s.id=%s
        app.%s.name=%s
        app.%s.version=%s
        app.%s.summary=%s
        app.%s.bundle.uri=%s
        app.%s.bundle.sha256=%s
        app.%s.bundle.size.bytes=%d
        app.%s.bundle.type=zip
        app.%s.permissions=%s,%s
        """
            .formatted(
                catalogId,
                generatedAt,
                APP_ID,
                APP_ID,
                APP_ID,
                APP_ID,
                APP_NAME,
                APP_ID,
                APP_VERSION,
                APP_ID,
                APP_SUMMARY,
                APP_ID,
                artifactUri,
                APP_ID,
                artifactSha256,
                APP_ID,
                artifactSize,
                APP_ID,
                APP_ID,
                QUEUE_READ_PERMISSION,
                QUEUE_WRITE_PERMISSION),
        StandardCharsets.UTF_8);
    AppCatalogSigner.sign(catalog, keyId, keyPair.getPrivate());
    return catalog;
  }

  private Path signedDenylistingCatalog(
      URI artifactUri, KeyPair keyPair, String artifactSha256, long artifactSize)
      throws IOException {
    Path catalog =
        signedCatalog(
            CATALOG_ID, artifactUri, keyPair, KEY_ID, artifactSha256, artifactSize, GENERATED_AT);
    String catalogText =
        Files.readString(catalog, StandardCharsets.UTF_8)
            .replace("catalog.version=1", "catalog.version=4")
            .replace(
                "catalog.entries=%s%n".formatted(APP_ID),
                """
                catalog.entries=%s
                catalog.securityAdvisories=ADV-1
                catalog.securityAdvisory.ADV-1.uri=https://example.invalid/advisories/ADV-1
                catalog.securityAdvisory.ADV-1.title=Suspended catalog advisory
                catalog.securityAdvisory.ADV-1.severity=critical
                catalog.securityAdvisory.ADV-1.status=active
                catalog.securityAdvisory.ADV-1.action=denylist
                catalog.securityAdvisory.ADV-1.summary=This source must not affect active catalogs.
                catalog.securityAdvisory.ADV-1.publishedAt=2026-04-21T18:22:40Z
                catalog.securityAdvisory.ADV-1.updatedAt=2026-04-21T18:22:40Z
                catalog.securityDenylist=deny-app
                catalog.securityDenylist.deny-app.appId=%s
                catalog.securityDenylist.deny-app.version=%s
                catalog.securityDenylist.deny-app.advisoryId=ADV-1
                catalog.securityDenylist.deny-app.reason=Suspended source fixture.
                """
                    .formatted(APP_ID, APP_ID, APP_VERSION))
            .replace(
                "app.%s.bundle.uri=".formatted(APP_ID),
                "app.%s.channel=stable%napp.%s.bundle.uri=".formatted(APP_ID, APP_ID));
    Files.writeString(catalog, catalogText, StandardCharsets.UTF_8);
    AppCatalogSigner.sign(catalog, KEY_ID, keyPair.getPrivate());
    return catalog;
  }

  private Path signedMixedChannelCatalog(
      URI artifactUri, KeyPair keyPair, String artifactSha256, long artifactSize)
      throws IOException {
    Path catalog =
        signedCatalog(
            CATALOG_ID, artifactUri, keyPair, KEY_ID, artifactSha256, artifactSize, GENERATED_AT);
    String catalogText =
        Files.readString(catalog, StandardCharsets.UTF_8)
                .replace("catalog.version=1", "catalog.version=3")
                .replace("catalog.entries=" + APP_ID, "catalog.entries=" + APP_ID + ",beta-app")
                .replace(
                    "app.%s.bundle.uri=".formatted(APP_ID),
                    "app.%s.channel=stable%napp.%s.bundle.uri=".formatted(APP_ID, APP_ID))
            + """
            app.beta-app.id=beta-app
            app.beta-app.name=Beta app
            app.beta-app.version=1
            app.beta-app.summary=Beta entry outside the local channel scope
            app.beta-app.channel=beta
            app.beta-app.bundle.uri=%s
            app.beta-app.bundle.sha256=%s
            app.beta-app.bundle.size.bytes=%d
            app.beta-app.bundle.type=zip
            app.beta-app.permissions=
            """
                .formatted(artifactUri, artifactSha256, artifactSize);
    Files.writeString(catalog, catalogText, StandardCharsets.UTF_8);
    AppCatalogSigner.sign(catalog, KEY_ID, keyPair.getPrivate());
    return catalog;
  }

  static Path zipDirectory(Path sourceRoot, Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip));
        var paths = Files.walk(sourceRoot)) {
      for (Path path : paths.sorted(Comparator.naturalOrder()).toList()) {
        if (Files.isDirectory(path)) {
          continue;
        }
        String relative = sourceRoot.relativize(path).toString().replace('\\', '/');
        zip.putNextEntry(new ZipEntry(relative));
        Files.copy(path, zip);
        zip.closeEntry();
      }
    }
    return targetZip;
  }

  private static Path zipDirectoryWithAppleDouble(Path sourceRoot, Path targetZip)
      throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip));
        var paths = Files.walk(sourceRoot)) {
      for (Path path : paths.sorted(Comparator.naturalOrder()).toList()) {
        if (Files.isDirectory(path)) {
          continue;
        }
        String relative = sourceRoot.relativize(path).toString().replace('\\', '/');
        zip.putNextEntry(new ZipEntry(relative));
        Files.copy(path, zip);
        zip.closeEntry();
      }
      zip.putNextEntry(new ZipEntry("._cryptad-app.properties"));
      zip.write(FINDER_METADATA.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry("__MACOSX/"));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry("__MACOSX/._cryptad-app.properties"));
      zip.write(FINDER_METADATA.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry("bin/._launch.sh"));
      zip.write(FINDER_METADATA.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry(MACOS_METADATA_FILE));
      zip.write(FINDER_METADATA.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry("bin/.DS_Store"));
      zip.write(FINDER_METADATA.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return targetZip;
  }

  private static Path traversalZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("../evil.txt"));
      zip.write("evil".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return targetZip;
  }

  private static Path parentConflictZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("bin"));
      zip.write("not-a-directory".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry(EXECUTABLE_PATH));
      zip.write("echo sample\n".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return targetZip;
  }

  private static Path directoryParentConflictZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("bin"));
      zip.write("not-a-directory".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry(EXECUTABLE_PATH + "/"));
      zip.closeEntry();
    }
    return targetZip;
  }

  private static Path manyEntriesZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      for (int i = 0; i < 4097; i++) {
        zip.putNextEntry(new ZipEntry("entry-" + i + ".txt"));
        zip.write('x');
        zip.closeEntry();
      }
    }
    return targetZip;
  }

  private static Path invalidPathNameZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("bad\0name"));
      zip.write('x');
      zip.closeEntry();
    }
    return targetZip;
  }

  private static void corruptManifestZipEntryPayload(Path targetZip) throws IOException {
    byte[] zipBytes = Files.readAllBytes(targetZip);
    ByteBuffer zip = ByteBuffer.wrap(zipBytes).order(ByteOrder.LITTLE_ENDIAN);
    int centralDirectoryOffset = centralDirectoryOffset(zip);
    while (centralDirectoryOffset < zip.limit()
        && zip.getInt(centralDirectoryOffset) == CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      int nameLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 28));
      int extraLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 30));
      int commentLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 32));
      int nameOffset = centralDirectoryOffset + 46;
      String centralDirectoryName =
          new String(zipBytes, nameOffset, nameLength, StandardCharsets.UTF_8);
      if (AppBundleManifestParser.MANIFEST_FILE_NAME.equals(centralDirectoryName)) {
        int compressedSize = zip.getInt(centralDirectoryOffset + 20);
        int localHeaderOffset = zip.getInt(centralDirectoryOffset + 42);
        int dataOffset = zipEntryDataOffset(zip, localHeaderOffset);
        if (compressedSize <= 0 || dataOffset >= centralDirectoryOffset) {
          throw new IOException(
              "ZIP entry has no payload to corrupt: " + AppBundleManifestParser.MANIFEST_FILE_NAME);
        }
        zipBytes[dataOffset + Math.max(0, compressedSize / 2 - 1)] ^= 0x01;
        Files.write(targetZip, zipBytes);
        return;
      }
      centralDirectoryOffset = nameOffset + nameLength + extraLength + commentLength;
    }
    throw new IOException("ZIP entry not found: " + AppBundleManifestParser.MANIFEST_FILE_NAME);
  }

  private static int zipEntryDataOffset(ByteBuffer zip, int localHeaderOffset) throws IOException {
    if (zip.getInt(localHeaderOffset) != LOCAL_FILE_HEADER_SIGNATURE) {
      throw new IOException("ZIP local file header not found");
    }
    int nameLength = Short.toUnsignedInt(zip.getShort(localHeaderOffset + 26));
    int extraLength = Short.toUnsignedInt(zip.getShort(localHeaderOffset + 28));
    return localHeaderOffset + 30 + nameLength + extraLength;
  }

  private static void setExecutableZipUnixMode(Path targetZip) throws IOException {
    byte[] zipBytes = Files.readAllBytes(targetZip);
    ByteBuffer zip = ByteBuffer.wrap(zipBytes).order(ByteOrder.LITTLE_ENDIAN);
    int centralDirectoryOffset = centralDirectoryOffset(zip);
    while (centralDirectoryOffset < zip.limit()
        && zip.getInt(centralDirectoryOffset) == CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      int nameLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 28));
      int extraLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 30));
      int commentLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 32));
      int nameOffset = centralDirectoryOffset + 46;
      String centralDirectoryName =
          new String(zipBytes, nameOffset, nameLength, StandardCharsets.UTF_8);
      if (EXECUTABLE_PATH.equals(centralDirectoryName)) {
        zip.putShort(centralDirectoryOffset + 4, (short) 0x0314);
        zip.putInt(centralDirectoryOffset + 38, UNIX_EXECUTABLE_FILE_MODE << 16);
        Files.write(targetZip, zipBytes);
        return;
      }
      centralDirectoryOffset = nameOffset + nameLength + extraLength + commentLength;
    }
    throw new IOException("ZIP entry not found: " + EXECUTABLE_PATH);
  }

  private static int centralDirectoryOffset(ByteBuffer zip) throws IOException {
    for (int offset = zip.limit() - END_OF_CENTRAL_DIRECTORY_MIN_BYTES; offset >= 0; offset--) {
      if (zip.getInt(offset) == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
        return zip.getInt(offset + 16);
      }
    }
    throw new IOException("ZIP end-of-central-directory record not found");
  }

  private static AppCatalogEntry remoteEntry() {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        APP_VERSION,
        APP_SUMMARY,
        URI.create("http://localhost/queue-manager.zip"),
        "0".repeat(64),
        1L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION));
  }

  private static AppCatalogEntry localEntry(Path artifact) {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        APP_VERSION,
        APP_SUMMARY,
        artifact.toUri(),
        "0".repeat(64),
        1L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION));
  }

  private static AppCatalogEntry cryptaEntry(String artifactSha256, long artifactSizeBytes) {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        APP_VERSION,
        APP_SUMMARY,
        CRYPTA_ARTIFACT_URI,
        artifactSha256,
        artifactSizeBytes,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION));
  }

  static String sha256(Path path) throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(Files.readAllBytes(path));
    return HexFormat.of().formatHex(digest.digest());
  }

  private static String sha256(byte[] bytes) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(bytes);
    return HexFormat.of().formatHex(digest.digest());
  }

  static KeyPair keyPair() throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
  }

  static TrustedAppKeys trustedKeys(KeyPair keyPair) {
    return TrustedAppKeys.of(trustedKey(KEY_ID, keyPair));
  }

  private static TrustedAppKeys lifecycleKeys(KeyPair keyPair, TrustedAppKeyLifecycle lifecycle) {
    return TrustedAppKeys.ofPolicies(
        new TrustedAppKeyPolicy(
            trustedKey(KEY_ID, keyPair),
            lifecycle,
            Instant.parse("2020-01-01T00:00:00Z"),
            Instant.parse("2100-01-01T00:00:00Z")));
  }

  static TrustedAppKey trustedKey(String keyId, KeyPair keyPair) {
    return new TrustedAppKey(keyId, AppBundleSignature.SIGNATURE_ALGORITHM, keyPair.getPublic());
  }

  private static final class FakeContentFetchPort implements ContentFetchPort {
    private final Map<String, byte[]> content = new java.util.LinkedHashMap<>();
    private final Map<String, String> resolvedUris = new java.util.LinkedHashMap<>();
    private final java.util.ArrayList<String> requestedKeys = new java.util.ArrayList<>();
    private final java.util.ArrayList<BoundedContentFetchRequest> requests =
        new java.util.ArrayList<>();
    private ContentFetchException failure;

    private FakeContentFetchPort(Map<String, byte[]> content) {
      this(content, Map.of());
    }

    private FakeContentFetchPort(Map<String, byte[]> content, Map<String, String> resolvedUris) {
      replaceContent(content, resolvedUris);
    }

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request)
        throws ContentFetchException {
      requests.add(request);
      requestedKeys.add(request.uri());
      if (failure != null) {
        throw failure;
      }
      byte[] bytes = content.get(request.uri());
      if (bytes == null) {
        throw new ContentFetchException(
            CATALOG_SIGNATURE_PURPOSE.equals(request.purpose())
                ? AppCatalogSidecars.CATALOG_SIGNATURE_MISSING
                : ContentFetchException.CATALOG_FETCH_FAILED,
            "content is unavailable");
      }
      if (bytes.length > request.maxBytes()) {
        throw new ContentFetchException(
            ContentFetchException.CATALOG_FETCH_FAILED, "content exceeds the allowed size");
      }
      return new BoundedContentFetchResult(
          bytes, request.uri(), resolvedUris.get(request.uri()), null);
    }

    private void failWith(IOException failure) {
      this.failure =
          new ContentFetchException(
              ContentFetchException.CATALOG_FETCH_FAILED, "content fetch failed", failure);
    }

    private void replaceContent(Map<String, byte[]> content, Map<String, String> resolvedUris) {
      this.content.clear();
      this.content.putAll(content);
      this.resolvedUris.clear();
      this.resolvedUris.putAll(resolvedUris);
      failure = null;
      requestedKeys.clear();
      requests.clear();
    }

    private List<String> requestedKeys() {
      return List.copyOf(requestedKeys);
    }

    private List<BoundedContentFetchRequest> requests() {
      return List.copyOf(requests);
    }
  }
}
