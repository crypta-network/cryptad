package network.crypta.fs.readiness;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LauncherReadinessInfoTest {

  @Test
  void ready_whenPortValid_expectDefaultReadyPayload() {
    LauncherReadinessInfo actual = LauncherReadinessInfo.ready(8888);

    assertEquals(LauncherReadinessInfo.VERSION_1, actual.version());
    assertEquals(LauncherReadinessInfo.READY_STATE, actual.state());
    assertEquals(8888, actual.uiPort());
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, actual.uiRoot());
    assertTrue(actual.isReady());
  }

  @Test
  void ready_whenUiRootProvided_expectReadyPayloadPreservesRoot() {
    LauncherReadinessInfo actual = LauncherReadinessInfo.ready(8888, "/app/node/");

    assertEquals(LauncherReadinessInfo.VERSION_1, actual.version());
    assertEquals(LauncherReadinessInfo.READY_STATE, actual.state());
    assertEquals(8888, actual.uiPort());
    assertEquals("/app/node/", actual.uiRoot());
    assertTrue(actual.isReady());
  }

  @Test
  void constructor_whenStateUnsupported_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class, () -> new LauncherReadinessInfo(1, "booting", 8888, "/"));
  }

  @Test
  void constructor_whenUiRootRelative_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new LauncherReadinessInfo(1, LauncherReadinessInfo.READY_STATE, 8888, "ui"));
  }

  @Test
  void constructor_whenUiRootContainsUnsafeUriCharacters_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new LauncherReadinessInfo(1, LauncherReadinessInfo.READY_STATE, 8888, "/app node/"));
  }

  @Test
  void isValidUiRoot_whenQueryOrFragmentPresent_expectRejected() {
    assertFalse(LauncherReadinessInfo.isValidUiRoot("/app/node/?tab=stats"));
    assertFalse(LauncherReadinessInfo.isValidUiRoot("/app/node/#overview"));
  }
}
