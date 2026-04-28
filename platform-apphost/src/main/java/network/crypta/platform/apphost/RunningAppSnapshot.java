package network.crypta.platform.apphost;

import java.time.Instant;
import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.sandbox.AppSandboxProviders;
import network.crypta.platform.apphost.sandbox.AppSandboxStatus;
import org.jetbrains.annotations.NotNull;

/**
 * Immutable snapshot of one running child process.
 *
 * <p>This record extends the installed-app view with the launch token, representative process id,
 * and start timestamp that the host uses for runtime tracking. It is the public read model for
 * callers that need to display or poll AppHost runtime state without reaching into implementation
 * internals.
 *
 * <p>The stored pid is the host's best current representative for the running app. For direct
 * launches it is usually the root child process, while for wrapper or handoff launches it may be a
 * recovered descendant that better represents the long-lived application process.
 *
 * @param manifest parsed application manifest
 * @param paths derived filesystem paths for the installed app
 * @param token opaque per-start launch token
 * @param pid child-process id
 * @param startedAt launch timestamp
 * @param sandboxStatus token-free sandbox status for this launch
 */
public record RunningAppSnapshot(
    AppManifest manifest,
    InstalledAppPaths paths,
    String token,
    long pid,
    Instant startedAt,
    AppSandboxStatus sandboxStatus) {
  /**
   * Creates a validated running-app snapshot.
   *
   * @param manifest parsed application manifest
   * @param paths derived filesystem paths for the installed app
   * @param token opaque per-start launch token
   * @param pid child-process id
   * @param startedAt launch timestamp
   * @param sandboxStatus token-free sandbox status for this launch
   */
  public RunningAppSnapshot {
    Objects.requireNonNull(manifest, "manifest");
    Objects.requireNonNull(paths, "paths");
    Objects.requireNonNull(token, "token");
    Objects.requireNonNull(startedAt, "startedAt");
    Objects.requireNonNull(sandboxStatus, "sandboxStatus");
    if (token.isBlank()) {
      throw new IllegalArgumentException("token must not be blank");
    }
    if (pid <= 0) {
      throw new IllegalArgumentException("pid must be positive");
    }
  }

  /**
   * Creates a running snapshot with an inactive manifest-derived sandbox status.
   *
   * <p>This overload preserves compatibility for tests and embeddings that construct running
   * snapshots directly without exercising the provider launch path.
   *
   * @param manifest parsed application manifest
   * @param paths derived filesystem paths for the installed app
   * @param token opaque per-start launch token
   * @param pid child-process id
   * @param startedAt launch timestamp
   */
  public RunningAppSnapshot(
      AppManifest manifest, InstalledAppPaths paths, String token, long pid, Instant startedAt) {
    this(
        manifest,
        paths,
        token,
        pid,
        startedAt,
        AppSandboxProviders.inactiveStatus(manifest.sandboxPolicy()));
  }

  /**
   * Returns the stable application identifier.
   *
   * <p>This mirrors the manifest identifier, so callers can correlate running state with installed
   * state and sort snapshots without repeatedly dereferencing the manifest.
   *
   * @return manifest application identifier
   */
  public String appId() {
    return manifest.appId();
  }

  /**
   * Returns a diagnostic string that never includes the launch token or filesystem paths.
   *
   * @return redacted diagnostic representation
   */
  @Override
  public @NotNull String toString() {
    return "RunningAppSnapshot[appId=%s, name=%s, version=%s, token=%s, pid=%d, startedAt=%s]"
        .formatted(
            manifest.appId(),
            manifest.appName(),
            manifest.appVersion(),
            AppHostTokenRedactor.REDACTED,
            pid,
            startedAt);
  }
}
