package network.crypta.launcher;

/** Immutable application state exposed to the Swing view. */
public record AppState(
    boolean isRunning, Integer knownPort, boolean isStopping, boolean isShuttingDown) {

  public AppState() {
    this(false, null, false, false);
  }

  public boolean isStoppingOrShuttingDown() {
    return isStopping() || isShuttingDown();
  }

  public AppState withRunning(boolean value) {
    return new AppState(value, knownPort(), isStopping(), isShuttingDown());
  }

  public AppState withKnownPort(Integer value) {
    return new AppState(isRunning(), value, isStopping(), isShuttingDown());
  }

  public AppState withStopping(boolean value) {
    return new AppState(isRunning(), knownPort(), value, isShuttingDown());
  }

  public AppState withShuttingDown(boolean value) {
    return new AppState(isRunning(), knownPort(), isStopping(), value);
  }
}
