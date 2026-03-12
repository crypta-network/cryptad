package network.crypta.launcher;

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
 * @param isStopping whether a stop request is in progress
 * @param isShuttingDown whether full launcher shutdown is in progress
 */
public record AppState(
    boolean isRunning, Integer knownPort, boolean isStopping, boolean isShuttingDown) {

  /**
   * Creates the default initial launcher state.
   *
   * <p>The default represents an idle launcher with no known port and no stop or shutdown in
   * progress.
   */
  public AppState() {
    this(false, null, false, false);
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
    return new AppState(value, knownPort(), isStopping(), isShuttingDown());
  }

  /**
   * Returns a copy of this state with the known port replaced.
   *
   * @param value new known port value, or {@code null} when not yet known
   * @return new immutable state instance with {@code knownPort} set to {@code value}
   */
  public AppState withKnownPort(Integer value) {
    return new AppState(isRunning(), value, isStopping(), isShuttingDown());
  }

  /**
   * Returns a copy of this state with the stopping flag replaced.
   *
   * @param value new stopping-state flag
   * @return new immutable state instance with {@code isStopping} set to {@code value}
   */
  public AppState withStopping(boolean value) {
    return new AppState(isRunning(), knownPort(), value, isShuttingDown());
  }

  /**
   * Returns a copy of this state with the shutting-down flag replaced.
   *
   * @param value new shutdown-state flag
   * @return new immutable state instance with {@code isShuttingDown} set to {@code value}
   */
  public AppState withShuttingDown(boolean value) {
    return new AppState(isRunning(), knownPort(), isStopping(), value);
  }
}
