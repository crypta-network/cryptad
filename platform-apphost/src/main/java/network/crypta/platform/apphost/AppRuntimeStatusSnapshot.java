package network.crypta.platform.apphost;

import java.time.Instant;
import java.util.Objects;

/**
 * Token-free process status snapshot for one installed app.
 *
 * <p>This read model is safe for operator-facing APIs: it reports process lifecycle metadata and
 * log availability, but it intentionally omits launch tokens and host filesystem paths. {@code
 * LocalProcessAppHost} builds snapshots from live process handles and retained runtime records,
 * then Platform API and Web Shell callers serialize the result without needing access to internal
 * launch state.
 *
 * <p>The model is process-scoped. A running value means AppHost still observes a managed process;
 * it does not imply application-level readiness or successful API authentication. Exit fields
 * describe the last managed process result known to the current daemon session. Restart counters
 * are best-effort diagnostics for bounded automatic restarts and reset when the app is started
 * manually in a new managed run.
 *
 * <p>Log metadata mirrors the process-log tail API without exposing the log path. Callers can use
 * {@code logAvailable} and {@code logSizeBytes} to decide whether to show a log action while still
 * keeping run directories and token-bearing launch details outside the public response shape.
 *
 * @param appId stable application identifier normalized by {@link InstalledAppPaths#normalizeAppId}
 * @param state current host-observed runtime state for the installed app
 * @param running whether a managed process is currently live according to AppHost
 * @param pid representative process id when running, otherwise {@code null}
 * @param startedAt process start time when running, otherwise {@code null}
 * @param lastExitAt last managed process exit time retained by this daemon, if known
 * @param lastExitCode last managed process exit code retained by this daemon, if known
 * @param restartCount completed automatic restart launches in this daemon-managed run
 * @param currentRestartAttempt current or pending automatic restart attempt number
 * @param logAvailable whether the process log can currently be read as a regular file
 * @param logSizeBytes process log size in bytes, if known without exposing the path
 */
public record AppRuntimeStatusSnapshot(
    String appId,
    AppRuntimeState state,
    boolean running,
    Long pid,
    Instant startedAt,
    Instant lastExitAt,
    Integer lastExitCode,
    int restartCount,
    int currentRestartAttempt,
    boolean logAvailable,
    Long logSizeBytes) {
  /**
   * Creates a validated runtime status snapshot.
   *
   * <p>The constructor normalizes the app id and rejects values that cannot represent a valid
   * status response. It deliberately allows nullable timestamps, process ids, exit codes, and log
   * sizes because those facts may be unknown for stopped apps, unavailable logs, or older runtime
   * records retained only for crash diagnostics.
   *
   * @param appId stable application identifier accepted by AppHost path normalization
   * @param state current host-observed runtime state for the installed app
   * @param running whether a managed process is currently live according to AppHost
   * @param pid representative process id when running, otherwise {@code null}
   * @param startedAt process start time when running, otherwise {@code null}
   * @param lastExitAt last managed process exit time retained by this daemon, if known
   * @param lastExitCode last managed process exit code retained by this daemon, if known
   * @param restartCount completed automatic restart launches in this daemon-managed run
   * @param currentRestartAttempt current or pending automatic restart attempt number
   * @param logAvailable whether the process log can currently be read as a regular file
   * @param logSizeBytes process log size in bytes, if known without exposing the path
   */
  public AppRuntimeStatusSnapshot {
    appId = InstalledAppPaths.normalizeAppId(appId);
    Objects.requireNonNull(state, "state");
    if (pid != null && pid <= 0L) {
      throw new IllegalArgumentException("pid must be positive when present");
    }
    if (restartCount < 0) {
      throw new IllegalArgumentException("restartCount must be non-negative");
    }
    if (currentRestartAttempt < 0) {
      throw new IllegalArgumentException("currentRestartAttempt must be non-negative");
    }
    if (logSizeBytes != null && logSizeBytes < 0L) {
      throw new IllegalArgumentException("logSizeBytes must be non-negative when present");
    }
  }
}
