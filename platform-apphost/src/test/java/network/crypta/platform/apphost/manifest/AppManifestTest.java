package network.crypta.platform.apphost.manifest;

import java.util.List;
import network.crypta.platform.appdist.AppSandboxMode;
import network.crypta.platform.appdist.AppUiMode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppManifestTest {
  private static final String SAMPLE_APP_ID = "sample-app";
  private static final String SAMPLE_APP_NAME = "Sample App";
  private static final String SAMPLE_APP_VERSION = "1.0";
  private static final String SAMPLE_EXEC_PATH = "bin/start.sh";
  private static final List<String> NO_PERMISSIONS = List.of();

  @Test
  void constructor_whenManifestVersionIsUnsupported_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppManifest(
                    2,
                    SAMPLE_APP_ID,
                    SAMPLE_APP_NAME,
                    SAMPLE_APP_VERSION,
                    SAMPLE_EXEC_PATH,
                    null,
                    NO_PERMISSIONS,
                    null,
                    null));

    assertEquals("unsupported manifest.version: 2", exception.getMessage());
  }

  @Test
  void constructor_whenQuotaIsNegative_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppManifest(
                    1,
                    SAMPLE_APP_ID,
                    SAMPLE_APP_NAME,
                    SAMPLE_APP_VERSION,
                    SAMPLE_EXEC_PATH,
                    null,
                    NO_PERMISSIONS,
                    -1L,
                    null));

    assertEquals("quota.data.bytes must be >= 0", exception.getMessage());
  }

  @Test
  void constructor_whenRequiredFieldIsBlank_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppManifest(
                    1,
                    SAMPLE_APP_ID,
                    "  ",
                    SAMPLE_APP_VERSION,
                    SAMPLE_EXEC_PATH,
                    null,
                    NO_PERMISSIONS,
                    null,
                    null));

    assertEquals("app.name must not be blank", exception.getMessage());
  }

  @Test
  void constructor_whenStaticUiEntryIsUnsafe_expectFailure() {
    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new AppManifest(
                    1,
                    SAMPLE_APP_ID,
                    SAMPLE_APP_NAME,
                    SAMPLE_APP_VERSION,
                    SAMPLE_EXEC_PATH,
                    AppUiMode.STATIC,
                    "../index.html",
                    NO_PERMISSIONS,
                    null,
                    null));

    assertEquals(
        "app.ui.entry must stay under the app root: ../index.html", exception.getMessage());
  }

  @Test
  void constructor_whenSandboxPolicyMissing_expectDefaultNoSandboxPolicy() {
    AppManifest manifest =
        new AppManifest(
            1,
            SAMPLE_APP_ID,
            SAMPLE_APP_NAME,
            SAMPLE_APP_VERSION,
            SAMPLE_EXEC_PATH,
            AppUiMode.NONE,
            null,
            NO_PERMISSIONS,
            null,
            null);

    assertEquals(AppSandboxMode.NONE, manifest.sandboxPolicy().mode());
    assertFalse(manifest.sandboxPolicy().required());
  }

  @Test
  void constructor_whenRestrictedSandboxProvided_expectPolicyPreserved() {
    AppManifest manifest =
        new AppManifest(
            1,
            SAMPLE_APP_ID,
            SAMPLE_APP_NAME,
            SAMPLE_APP_VERSION,
            SAMPLE_EXEC_PATH,
            AppUiMode.NONE,
            null,
            NO_PERMISSIONS,
            null,
            null,
            AppSandboxMode.RESTRICTED_PROCESS,
            true);

    assertEquals(AppSandboxMode.RESTRICTED_PROCESS, manifest.sandboxPolicy().mode());
    assertTrue(manifest.sandboxPolicy().required());
  }
}
