package network.crypta.platform.apphost.sandbox;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import network.crypta.fs.AppEnv;

/**
 * Host-side availability probe for the Linux bubblewrap sandbox provider.
 *
 * <p>The probe keeps host detection and executable discovery out of launch planning. It uses {@link
 * AppEnv} for platform and {@code PATH} checks, accepts an optional absolute executable override,
 * and returns only path-free public reasons for unavailable hosts. The resolved executable is
 * launch-sensitive data: it may be an operator-configured path and must not be copied into public
 * status text.
 *
 * <p>Availability means more than finding a binary. The default probe also asks bubblewrap to
 * create a tiny namespace so provider selection can reject hosts where user or mount namespaces are
 * blocked, such as hardened containers or kernels with unprivileged namespaces disabled. Callers
 * use the resulting {@link Result} as a selection gate for {@link BubblewrapSandboxProvider};
 * optional restricted-process apps can then fall back to best-effort handling, while required apps
 * fail before any child process starts.
 */
public final class BubblewrapAvailability {
  /** Default command name resolved through {@code PATH}. */
  public static final String DEFAULT_COMMAND = "bwrap";

  private final AppEnv appEnv;
  private final String configuredExecutable;
  private final ExecutableProbe executableProbe;

  /**
   * Creates a probe that resolves {@code bwrap} from the host {@code PATH}.
   *
   * <p>The probe is safe to keep and reuse. Executable and namespace preflight results are cached
   * by the default executable probe, so repeated provider selection does not spawn a bubblewrap
   * preflight process for every app launch.
   *
   * @param appEnv platform and {@code PATH} detector for the AppHost process
   */
  @SuppressWarnings("unused")
  public BubblewrapAvailability(AppEnv appEnv) {
    this(appEnv, "");
  }

  /**
   * Creates a probe with an optional absolute executable override.
   *
   * <p>A blank override means the default {@code bwrap} command is resolved from {@code PATH}. A
   * non-blank override must be an absolute executable path. The override value is intentionally not
   * exposed by {@link Result#unavailableReason()}.
   *
   * <p>This constructor is the host-configuration entry point for {@code CRYPTAD_APPHOST_BWRAP}. It
   * keeps the configured path in the private launch plan only; public API, Web Shell, and
   * release-certification text should use the returned availability reason and provider name rather
   * than the raw executable path.
   *
   * @param appEnv platform and {@code PATH} detector for the AppHost process
   * @param configuredExecutable optional absolute path configured by the host operator
   */
  public BubblewrapAvailability(AppEnv appEnv, String configuredExecutable) {
    this(appEnv, configuredExecutable, new DefaultExecutableProbe());
  }

  BubblewrapAvailability(
      AppEnv appEnv, String configuredExecutable, ExecutableProbe executableProbe) {
    this.appEnv = Objects.requireNonNull(appEnv, "appEnv");
    this.configuredExecutable = normalizeConfiguredExecutable(configuredExecutable);
    this.executableProbe = Objects.requireNonNull(executableProbe, "executableProbe");
  }

  /**
   * Probes whether bubblewrap can be used for a launch on this host.
   *
   * <p>The method performs deterministic checks in the order that produces the safest public
   * result: Linux-family host detection, executable discovery, and finally a short namespace
   * preflight. A successful result contains the private executable token needed by the command
   * builder. An unsuccessful result contains only a stable, path-free reason suitable for
   * diagnostics and public sandbox status.
   *
   * @return immutable availability result containing a launch executable only when supported
   */
  public Result probe() {
    if (!isLinuxFamilyHost(appEnv)) {
      return Result.unavailable("bubblewrap sandbox is only available on Linux hosts");
    }
    if (!configuredExecutable.isEmpty()) {
      return explicitExecutableResult();
    }
    if (!executableProbe.onPath(appEnv, DEFAULT_COMMAND)) {
      return Result.unavailable("bubblewrap executable is not available on PATH");
    }
    if (executableProbe.sandboxPreflightFails(DEFAULT_COMMAND)) {
      return Result.unavailable("bubblewrap cannot create sandbox namespaces on this host");
    }
    return Result.available(DEFAULT_COMMAND);
  }

  private Result explicitExecutableResult() {
    Path executable = Path.of(configuredExecutable);
    if (!executable.isAbsolute()) {
      return Result.unavailable("configured bubblewrap executable must be an absolute path");
    }
    if (!executableProbe.isExecutable(executable)) {
      return Result.unavailable("configured bubblewrap executable is unavailable");
    }
    String normalizedExecutable = executable.toAbsolutePath().normalize().toString();
    if (executableProbe.sandboxPreflightFails(normalizedExecutable)) {
      return Result.unavailable("bubblewrap cannot create sandbox namespaces on this host");
    }
    return Result.available(normalizedExecutable);
  }

  private static String normalizeConfiguredExecutable(String value) {
    return value == null ? "" : value.trim();
  }

  private static boolean isLinuxFamilyHost(AppEnv appEnv) {
    // AppEnv groups some Unix-like hosts as Linux-style. Bubblewrap itself is Linux-specific.
    return appEnv.isLinux() && appEnv.osNameRaw().toLowerCase(Locale.ROOT).contains("linux");
  }

  static List<String> sandboxPreflightCommand(String executable) {
    return List.of(
        executable,
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-ipc",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/tmp",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--",
        "/proc/self/exe",
        "--version");
  }

  /**
   * Path-free bubblewrap availability result.
   *
   * <p>The record is deliberately small because it crosses the boundary between host probing and
   * provider selection. {@link #executable()} is private launch data and is populated only when
   * {@link #available()} is {@code true}. {@link #unavailableReason()} is the safe counterpart for
   * public status: it identifies the unsupported condition without revealing configured executable
   * paths, daemon directories, or other host-private values.
   *
   * @param available whether the provider may wrap a restricted-process launch
   * @param executable executable token used in the private process command when available
   * @param unavailableReason short public reason when bubblewrap is unavailable
   */
  public record Result(boolean available, String executable, String unavailableReason) {
    /**
     * Creates a normalized availability result and rejects contradictory state.
     *
     * <p>Available results must carry the private executable token that the launch plan will use.
     * Unavailable results must carry a short public reason. Null text values are normalized before
     * validation so callers cannot accidentally create a result that serializes as {@code null} in
     * diagnostics.
     *
     * @param available whether the provider may wrap a restricted-process launch
     * @param executable executable token used in the private process command when available
     * @param unavailableReason short public reason when bubblewrap is unavailable
     */
    public Result {
      executable = executable == null ? "" : executable.trim();
      unavailableReason = unavailableReason == null ? "" : unavailableReason.trim();
      if (available && executable.isEmpty()) {
        throw new IllegalArgumentException("available bubblewrap result requires executable");
      }
      if (!available && unavailableReason.isEmpty()) {
        throw new IllegalArgumentException("unavailable bubblewrap result requires reason");
      }
    }

    private static Result available(String executable) {
      return new Result(true, executable, "");
    }

    private static Result unavailable(String reason) {
      return new Result(false, "", reason);
    }
  }

  interface ExecutableProbe {
    boolean onPath(AppEnv appEnv, String command);

    boolean isExecutable(Path executable);

    boolean sandboxPreflightFails(String executable);
  }

  private static final class DefaultExecutableProbe implements ExecutableProbe {
    private static final long PREFLIGHT_TIMEOUT_SECONDS = 2L;
    private static final ConcurrentMap<String, Boolean> SANDBOX_PREFLIGHT_CACHE =
        new ConcurrentHashMap<>();

    @Override
    public boolean onPath(AppEnv appEnv, String command) {
      return appEnv.onPath(command);
    }

    @Override
    public boolean isExecutable(Path executable) {
      return Files.isRegularFile(executable) && Files.isExecutable(executable);
    }

    @Override
    public boolean sandboxPreflightFails(String executable) {
      return !SANDBOX_PREFLIGHT_CACHE.computeIfAbsent(
          executable, DefaultExecutableProbe::runSandboxPreflightSucceeds);
    }

    private static boolean runSandboxPreflightSucceeds(String executable) {
      Process process;
      try {
        process = newPreflightProcess(executable).start();
      } catch (IOException _) {
        return false;
      }
      try {
        if (!process.waitFor(PREFLIGHT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
          process.destroyForcibly();
          return false;
        }
        return process.exitValue() == 0;
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        process.destroyForcibly();
        return false;
      }
    }

    private static ProcessBuilder newPreflightProcess(String executable) {
      return new ProcessBuilder(sandboxPreflightCommand(executable))
          .redirectOutput(ProcessBuilder.Redirect.DISCARD)
          .redirectError(ProcessBuilder.Redirect.DISCARD);
    }
  }
}
