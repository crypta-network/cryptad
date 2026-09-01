package network.crypta.platform.api.appupdates;

import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppUpdateBundleSupportTest {
  @TempDir Path tempDir;

  @Test
  void readManifest_whenStagedManifestIsValid_expectParsedManifest() throws Exception {
    Files.writeString(
        tempDir.resolve(AppManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=Feed-Reader
        app.name=Feed Reader
        app.version=2
        app.exec=bin/start.sh
        """);

    AppManifest manifest = AppUpdateBundleSupport.readManifest(tempDir);

    assertEquals("feed-reader", manifest.appId());
    assertEquals("Feed Reader", manifest.appName());
    assertEquals("2", manifest.appVersion());
    assertEquals(Path.of("bin", "start.sh"), manifest.execPath());
  }

  @Test
  void isInvalidBundleFailure_whenManifestParserRejectsBundle_expectTrue() {
    AppHostException failure = new AppManifestException("invalid manifest");

    boolean invalidBundle = AppUpdateBundleSupport.isInvalidBundleFailure(failure);

    assertTrue(invalidBundle);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "stagedAppDirectory is missing",
        "staging directory is unsafe",
        "copied manifest is invalid",
        "copied app.exec is missing",
        "app.ui.entry is unsafe",
        "app.exec is unsafe",
        "staged app bundle is malformed"
      })
  void isInvalidBundleFailure_whenFailureHasBundleShapePrefix_expectTrue(String message) {
    AppHostException failure = new AppHostException(message);

    boolean invalidBundle = AppUpdateBundleSupport.isInvalidBundleFailure(failure);

    assertTrue(invalidBundle);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "app process did not become healthy"})
  void isInvalidBundleFailure_whenFailureIsNotBundleShapeError_expectFalse(String message) {
    AppHostException failure = new AppHostException(message);

    boolean invalidBundle = AppUpdateBundleSupport.isInvalidBundleFailure(failure);

    assertFalse(invalidBundle);
  }

  @Test
  void isSignedBundleVerificationFailure_whenFailureTypesDiffer_expectTypedClassification() {
    AppHostException verificationFailure = new AppBundleVerificationException("signature rejected");
    AppHostException lifecycleFailure = new AppHostException("process failed");

    boolean signedBundleFailure =
        AppUpdateBundleSupport.isSignedBundleVerificationFailure(verificationFailure);
    boolean ordinaryHostFailure =
        AppUpdateBundleSupport.isSignedBundleVerificationFailure(lifecycleFailure);

    assertTrue(signedBundleFailure);
    assertFalse(ordinaryHostFailure);
  }
}
