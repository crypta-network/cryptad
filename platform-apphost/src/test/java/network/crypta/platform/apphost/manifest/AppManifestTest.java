package network.crypta.platform.apphost.manifest;

import java.util.List;
import network.crypta.platform.appdist.AppUiMode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
}
