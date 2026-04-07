package network.crypta.launcher;

import network.crypta.fs.readiness.LauncherReadinessInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppStateTest {

  @Test
  void constructor_whenUiRootMissingTrailingSlash_expectNormalizedUiRoot() {
    AppState state = new AppState(true, 8888, "/app/node", false, false);

    assertTrue(state.isRunning());
    assertEquals(8888, state.knownPort());
    assertEquals("/app/node/", state.knownUiRoot());
    assertFalse(state.isStopping());
    assertFalse(state.isShuttingDown());
  }

  @Test
  void constructor_whenUiRootUnsafe_expectDefaultUiRoot() {
    AppState state = new AppState(true, 8888, "/app node/", false, false);

    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, state.knownUiRoot());
  }

  @Test
  void fourArgumentConstructor_whenCreated_expectDefaultUiRoot() {
    AppState state = new AppState(true, 8888, false, false);

    assertTrue(state.isRunning());
    assertEquals(8888, state.knownPort());
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, state.knownUiRoot());
    assertFalse(state.isStopping());
    assertFalse(state.isShuttingDown());
  }

  @Test
  void withKnownUiRoot_whenValueMissingTrailingSlash_expectNormalizedUiRoot() {
    AppState initial = new AppState();

    AppState updated = initial.withKnownUiRoot("/app/node");

    assertNull(initial.knownPort());
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, initial.knownUiRoot());
    assertEquals("/app/node/", updated.knownUiRoot());
  }
}
