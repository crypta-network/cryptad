package network.crypta.launcher;

import network.crypta.fs.readiness.LauncherReadinessInfo;

/**
 * Immutable snapshot of the launcher runtime state consumed by the Swing UI.
 *
 * <p>This record models the minimal state needed to drive view behavior and button enablement
 * without exposing mutable launcher internals. Instances are inexpensive value objects: update
 * operations return new records instead of mutating existing state, which keeps transitions
 * explicit and makes state changes easier to reason about in event-driven code. The optional port
 * field is nullable until a bound node port is known.
 *
 * @param isRunning whether the managed process is currently running
 * @param knownPort known node port value, or {@code null} when no port is available yet
 * @param knownUiRoot known browser-facing UI root path, defaulting to {@code /}
 * @param isStopping whether a stop request is in progress
 * @param isShuttingDown whether full launcher shutdown is in progress
 */
public record AppState(
    boolean isRunning,
    Integer knownPort,
    String knownUiRoot,
    boolean isStopping,
    boolean isShuttingDown) {

  /**
   * Creates the default initial launcher state.
   *
   * <p>The default represents an idle launcher with no known port and no stop or shutdown in
   * progress.
   */
  public AppState() {
    this(false, null, LauncherReadinessInfo.DEFAULT_UI_ROOT, false, false);
  }

  /**
   * Creates a launcher state that uses the default UI root.
   *
   * <p>This overload keeps the historical four-argument construction sites working while the
   * launcher gradually adopts the structured readiness `uiRoot` value.
   *
   * @param isRunning whether the managed process is currently running
   * @param knownPort known node port value, or {@code null} when no port is available yet
   * @param isStopping whether a stop request is in progress
   * @param isShuttingDown whether full launcher shutdown is in progress
   */
  public AppState(
      boolean isRunning, Integer knownPort, boolean isStopping, boolean isShuttingDown) {
    this(isRunning, knownPort, LauncherReadinessInfo.DEFAULT_UI_ROOT, isStopping, isShuttingDown);
  }

  /**
   * Creates a normalized immutable launcher state snapshot.
   *
   * <p>The UI root stays normalized, so browser-launch and tooltip code can reuse it without adding
   * per-call fallback logic.
   */
  public AppState {
    knownUiRoot = normalizeUiRoot(knownUiRoot);
  }

  /**
   * Indicates whether either stop flow or shutdown flow is currently active.
   *
   * @return {@code true} when stopping or shutting down, otherwise {@code false}
   */
  public boolean isStoppingOrShuttingDown() {
    return isStopping() || isShuttingDown();
  }

  /**
   * Returns a copy of this state with the running flag replaced.
   *
   * @param value new running-state flag
   * @return new immutable state instance with {@code isRunning} set to {@code value}
   */
  public AppState withRunning(boolean value) {
    return new AppState(value, knownPort(), knownUiRoot(), isStopping(), isShuttingDown());
  }

  /**
   * Returns a copy of this state with the known port replaced.
   *
   * @param value new known port value, or {@code null} when not yet known
   * @return new immutable state instance with {@code knownPort} set to {@code value}
   */
  public AppState withKnownPort(Integer value) {
    return new AppState(isRunning(), value, knownUiRoot(), isStopping(), isShuttingDown());
  }

  /**
   * Returns a copy of this state with the known UI root replaced.
   *
   * @param value new known UI root value
   * @return new immutable state instance with {@code knownUiRoot} set to {@code value}
   */
  public AppState withKnownUiRoot(String value) {
    return new AppState(isRunning(), knownPort(), value, isStopping(), isShuttingDown());
  }

  /**
   * Returns a copy of this state with the stopping flag replaced.
   *
   * @param value new stopping-state flag
   * @return new immutable state instance with {@code isStopping} set to {@code value}
   */
  public AppState withStopping(boolean value) {
    return new AppState(isRunning(), knownPort(), knownUiRoot(), value, isShuttingDown());
  }

  /**
   * Returns a copy of this state with the shutting-down flag replaced.
   *
   * @param value new shutdown-state flag
   * @return new immutable state instance with {@code isShuttingDown} set to {@code value}
   */
  public AppState withShuttingDown(boolean value) {
    return new AppState(isRunning(), knownPort(), knownUiRoot(), isStopping(), value);
  }

  private static String normalizeUiRoot(String value) {
    if (!LauncherReadinessInfo.isValidUiRoot(value)) {
      return LauncherReadinessInfo.DEFAULT_UI_ROOT;
    }
    return value.endsWith("/") ? value : value + "/";
  }
}
