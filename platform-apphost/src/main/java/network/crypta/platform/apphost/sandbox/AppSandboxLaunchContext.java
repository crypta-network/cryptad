package network.crypta.platform.apphost.sandbox;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.fs.AppEnv;
import network.crypta.platform.apphost.InstalledAppPaths;
import org.jetbrains.annotations.NotNull;

/**
 * Sensitive launch input passed from AppHost to a sandbox provider.
 *
 * <p>This record is the handoff point between {@code LocalProcessAppHost} and an {@link
 * AppSandboxProvider}. It contains every value a provider may need to inspect or rewrite before
 * process launch: app identity, immutable and mutable app directories, the command that AppHost
 * would otherwise execute, the child environment, the requested policy, and platform detection
 * state. The canonical constructor normalizes app ids and paths so providers can compare locations
 * without repeating path cleanup.
 *
 * <p>The values are intentionally sensitive. The environment contains the per-launch app token, and
 * paths reveal the host-owned app layout. Providers may return a rewritten launch plan, but logs,
 * exceptions, and public status objects must never expose environment values, command text that may
 * carry secrets, or private filesystem paths. The custom {@link #toString()} reports only coarse
 * sizes and environment key names for diagnostics.
 *
 * @param appId normalized application identifier used for provider checks and status correlation
 * @param installDir installed bundle root used as the immutable application directory
 * @param dataDir app-scoped mutable data directory managed by AppHost
 * @param cacheDir app-scoped mutable cache directory managed by AppHost
 * @param runDir app-scoped runtime directory for process state and transient files
 * @param logDir directory that contains the AppHost-managed process log
 * @param command command AppHost would launch before provider rewriting or wrapping
 * @param environment sanitized child environment, including the sensitive per-launch app token
 * @param workingDirectory child working directory selected before provider rewriting
 * @param policy manifest-derived sandbox policy requested for this launch
 * @param appEnv host platform environment used for OS and architecture decisions
 */
public record AppSandboxLaunchContext(
    String appId,
    Path installDir,
    Path dataDir,
    Path cacheDir,
    Path runDir,
    Path logDir,
    List<String> command,
    Map<String, String> environment,
    Path workingDirectory,
    AppSandboxPolicy policy,
    AppEnv appEnv) {
  /**
   * Creates a normalized launch context.
   *
   * <p>All directory arguments are converted to absolute normalized paths, the app id is canonical
   * AppHost form, and collection inputs are defensively copied. The constructor rejects an empty
   * command because providers must always return a concrete {@link ProcessBuilder} command in the
   * corresponding {@link AppSandboxLaunchPlan}.
   *
   * @throws IllegalArgumentException if the app id is invalid or the command list is empty
   * @throws NullPointerException if any required launch field is {@code null}
   */
  public AppSandboxLaunchContext {
    appId = InstalledAppPaths.normalizeAppId(appId);
    installDir = normalizePath(installDir, "installDir");
    dataDir = normalizePath(dataDir, "dataDir");
    cacheDir = normalizePath(cacheDir, "cacheDir");
    runDir = normalizePath(runDir, "runDir");
    logDir = normalizePath(logDir, "logDir");
    command = List.copyOf(Objects.requireNonNull(command, "command"));
    if (command.isEmpty()) {
      throw new IllegalArgumentException("command must not be empty");
    }
    environment = Map.copyOf(Objects.requireNonNull(environment, "environment"));
    workingDirectory = normalizePath(workingDirectory, "workingDirectory");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(appEnv, "appEnv");
  }

  /**
   * Returns a redacted diagnostic representation of the launch context.
   *
   * <p>The output deliberately omits command entries, environment values, and filesystem paths. It
   * is suitable for local debugging of provider selection shape, but not for reconstructing a
   * process launch.
   *
   * @return token-free summary containing app id, policy, command size, and environment keys
   */
  @Override
  public @NotNull String toString() {
    return "AppSandboxLaunchContext[appId="
        + appId
        + ", policy="
        + policy
        + ", commandSize="
        + command.size()
        + ", environmentKeys="
        + environment.keySet()
        + ']';
  }

  private static Path normalizePath(Path path, String label) {
    return Objects.requireNonNull(path, label).toAbsolutePath().normalize();
  }
}
