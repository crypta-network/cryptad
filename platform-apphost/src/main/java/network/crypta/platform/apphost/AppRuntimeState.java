package network.crypta.platform.apphost;

/**
 * Process-level runtime state for an installed AppHost application.
 *
 * <p>The state is intentionally limited to host-observed process lifecycle. It does not imply an
 * application-level health check, a browser session state, or an operating-system sandbox. AppHost
 * derives these values from the managed child process, retained exit metadata, and pending bounded
 * restart attempts.
 *
 * <p>Callers should treat the enum as an operator diagnostic signal. {@link #RUNNING} means the
 * host has a representative process handle, not that the app is ready to serve requests. {@link
 * #EXITED} and {@link #CRASHED} describe the last observed managed process result in this daemon
 * session. {@link #RESTARTING} is transient and remains cancellable by an explicit stop request.
 */
public enum AppRuntimeState {
  /**
   * The app is installed but has no live or recently failed managed process.
   *
   * <p>This state is the stable baseline for newly installed apps, apps stopped by an operator, and
   * apps whose previous runtime metadata is no longer retained by the current daemon session.
   */
  STOPPED,

  /**
   * The app has a live managed process.
   *
   * <p>The reported process id is the host's representative process for the app. The state does not
   * assert that the app has completed startup or that any app-owned HTTP endpoint is healthy.
   */
  RUNNING,

  /**
   * The app's last managed process exited with status code {@code 0}.
   *
   * <p>A clean exit is terminal for the current process run. It does not trigger an {@code
   * on-failure} restart policy because the app reported successful completion.
   */
  EXITED,

  /**
   * The app's last managed process exited with a non-zero status code or unknown failed outcome.
   *
   * <p>This state is used for crash diagnostics and for deciding whether a bounded {@code
   * on-failure} restart may be scheduled, subject to the app's manifest limits.
   */
  CRASHED,

  /**
   * The host has scheduled a bounded automatic restart attempt.
   *
   * <p>The app is not currently running during the backoff window, but AppHost still considers it
   * managed so a stop or update request can cancel the pending relaunch before it starts.
   */
  RESTARTING
}
