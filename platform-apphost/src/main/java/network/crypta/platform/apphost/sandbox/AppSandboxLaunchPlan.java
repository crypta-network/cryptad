package network.crypta.platform.apphost.sandbox;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Provider-selected command, environment, working directory, and public sandbox status.
 *
 * <p>A provider returns this record after it has accepted an {@link AppSandboxLaunchContext}. The
 * command, environment, and working directory are the exact values that AppHost should pass to
 * {@link ProcessBuilder}. The status is the public, token-free description that AppHost retains for
 * runtime summaries and Platform API responses.
 *
 * <p>Providers may leave the launch unchanged, minimize the environment further, wrap the command,
 * or redirect to a future enforced runtime. Whatever they return must remain internally consistent:
 * the command cannot be empty, the environment is copied, and the status must describe the actual
 * level of support applied. The plan intentionally omits command text, environment values, and
 * filesystem paths from {@link #toString()} because the environment carries the per-launch app
 * token.
 *
 * @param command final command passed to {@link ProcessBuilder} for the child process
 * @param environment final child process environment, copied before AppHost starts the process
 * @param workingDirectory final child working directory used by the process builder
 * @param sandboxStatus token-free public sandbox status for this launch plan
 */
public record AppSandboxLaunchPlan(
    List<String> command,
    Map<String, String> environment,
    Path workingDirectory,
    AppSandboxStatus sandboxStatus) {
  /**
   * Creates a validated launch plan.
   *
   * <p>Collection inputs are defensively copied so a provider cannot mutate a plan after AppHost
   * accepts it. The working directory is normalized for stable comparison and process-builder use.
   * The constructor does not inspect environment values because providers may need to pass opaque
   * secrets such as the per-launch app token through to the child process.
   *
   * @throws IllegalArgumentException if the command list is empty
   * @throws NullPointerException if any required plan field is {@code null}
   */
  public AppSandboxLaunchPlan {
    command = List.copyOf(Objects.requireNonNull(command, "command"));
    if (command.isEmpty()) {
      throw new IllegalArgumentException("command must not be empty");
    }
    environment = Map.copyOf(Objects.requireNonNull(environment, "environment"));
    workingDirectory = Objects.requireNonNull(workingDirectory, "workingDirectory").normalize();
    Objects.requireNonNull(sandboxStatus, "sandboxStatus");
  }

  /**
   * Returns a redacted diagnostic representation of the launch plan.
   *
   * <p>The output is intended for debugging provider behavior without exposing launch secrets. It
   * reports the number of command elements, environment key names, and public sandbox status, but
   * never includes command entries, environment values, or filesystem paths.
   *
   * @return token-free summary of the launch plan shape and sandbox status
   */
  @Override
  public @NotNull String toString() {
    return "AppSandboxLaunchPlan[commandSize="
        + command.size()
        + ", environmentKeys="
        + environment.keySet()
        + ", sandboxStatus="
        + sandboxStatus
        + ']';
  }
}
