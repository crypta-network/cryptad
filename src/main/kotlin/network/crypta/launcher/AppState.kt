package network.crypta.launcher

/** Immutable application state exposed to the Swing view. */
data class AppState(
  val isRunning: Boolean = false,
  val knownPort: Int? = null,
  val isStopping: Boolean = false,
  val isShuttingDown: Boolean = false,
) {
  val isStoppingOrShuttingDown: Boolean
    get() = isStopping || isShuttingDown
}
