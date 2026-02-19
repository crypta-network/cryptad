package network.crypta.launcher;

import java.util.Objects;

/** Immutable application state exposed to the Swing view. */
public final class AppState {
  private final boolean isRunning;
  private final Integer knownPort;
  private final boolean isStopping;
  private final boolean isShuttingDown;

  public AppState() {
    this(false, null, false, false);
  }

  public AppState(
      boolean isRunning, Integer knownPort, boolean isStopping, boolean isShuttingDown) {
    this.isRunning = isRunning;
    this.knownPort = knownPort;
    this.isStopping = isStopping;
    this.isShuttingDown = isShuttingDown;
  }

  public boolean isRunning() {
    return isRunning;
  }

  public Integer getKnownPort() {
    return knownPort;
  }

  public boolean isStopping() {
    return isStopping;
  }

  public boolean isShuttingDown() {
    return isShuttingDown;
  }

  public boolean isStoppingOrShuttingDown() {
    return isStopping || isShuttingDown;
  }

  public AppState withRunning(boolean value) {
    return new AppState(value, knownPort, isStopping, isShuttingDown);
  }

  public AppState withKnownPort(Integer value) {
    return new AppState(isRunning, value, isStopping, isShuttingDown);
  }

  public AppState withStopping(boolean value) {
    return new AppState(isRunning, knownPort, value, isShuttingDown);
  }

  public AppState withShuttingDown(boolean value) {
    return new AppState(isRunning, knownPort, isStopping, value);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof AppState appState)) {
      return false;
    }
    return isRunning == appState.isRunning
        && isStopping == appState.isStopping
        && isShuttingDown == appState.isShuttingDown
        && Objects.equals(knownPort, appState.knownPort);
  }

  @Override
  public int hashCode() {
    return Objects.hash(isRunning, knownPort, isStopping, isShuttingDown);
  }

  @Override
  public String toString() {
    return "AppState{"
        + "isRunning="
        + isRunning
        + ", knownPort="
        + knownPort
        + ", isStopping="
        + isStopping
        + ", isShuttingDown="
        + isShuttingDown
        + '}';
  }
}
