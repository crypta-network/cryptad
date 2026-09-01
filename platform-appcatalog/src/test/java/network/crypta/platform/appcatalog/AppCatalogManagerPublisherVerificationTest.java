package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppCatalogManagerPublisherVerificationTest {
  private static final String APP_SIGNING_KEY_ID = "app-signing-test";
  private static final String CATALOG_ID = "core";
  private static final String APP_ID = "queue-manager";
  private static final String ARTIFACT_ZIP = "queue-manager.zip";
  private static final String CATALOG_SOURCE_STORE_DIRECTORY = "store";

  private final AppCatalogManagerTest fixtures = new AppCatalogManagerTest();

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    fixtures.tempDir = tempDir;
  }

  @Test
  void verifyInstallPlan_whenPublisherAuthorizationResultChanges_expectPlanRejected()
      throws Exception {
    KeyPair catalogKeyPair = AppCatalogManagerTest.keyPair();
    KeyPair appKeyPair = AppCatalogManagerTest.keyPair();
    TrustedAppKeys appKeys =
        TrustedAppKeys.of(AppCatalogManagerTest.trustedKey(APP_SIGNING_KEY_ID, appKeyPair));
    Path bundle = fixtures.signedBundle(appKeyPair, APP_SIGNING_KEY_ID);
    Path artifact = AppCatalogManagerTest.zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog =
        fixtures.signedCatalog(
            artifact, catalogKeyPair, AppCatalogManagerTest.sha256(artifact), Files.size(artifact));
    AtomicInteger verificationCount = new AtomicInteger();
    AtomicReference<AppCatalogBundleVerificationContext> firstContext = new AtomicReference<>();
    AppCatalogBundleVerificationPolicy policy =
        new AppCatalogBundleVerificationPolicy() {
          @Override
          public void verify(Path stagedBundleDirectory) throws IOException {
            AppBundleVerifier.verify(stagedBundleDirectory, appKeys);
          }

          @Override
          public AppCatalogBundleVerificationResult verify(
              AppCatalogBundleVerificationContext context, Path stagedBundleDirectory)
              throws IOException {
            AppBundleSignature signature = AppBundleVerifier.verify(stagedBundleDirectory, appKeys);
            int invocation = verificationCount.incrementAndGet();
            if (invocation == 1) {
              firstContext.set(context);
            } else {
              assertEquals(firstContext.get(), context);
            }
            return new AppCatalogBundleVerificationResult(
                signature.keyId(),
                PublicKeyFingerprint.sha256(appKeyPair.getPublic()),
                "catalog-app-publisher-binding",
                (invocation == 1 ? "a" : "b").repeat(64),
                true,
                "c".repeat(64));
          }
        };
    AppCatalogManager manager =
        AppCatalogManager.withBundleVerificationPolicy(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            () -> AppCatalogManagerTest.trustedKeys(catalogKeyPair),
            policy);
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      AppCatalogException exception =
          assertThrows(AppCatalogException.class, () -> manager.verifyInstallPlan(plan));

      assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
      assertTrue(exception.getMessage().contains("authorization changed"));
      assertEquals(CATALOG_ID, firstContext.get().catalogId());
      assertEquals(APP_ID, firstContext.get().entry().appId());
    }
    assertEquals(2, verificationCount.get());
  }
}
