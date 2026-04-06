package network.crypta.platform.apphost;

import java.time.Instant;
import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

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
 */
public record RunningAppSnapshot(
    AppManifest manifest, InstalledAppPaths paths, String token, long pid, Instant startedAt) {
  /**
   * Creates a validated running-app snapshot.
   *
   * @param manifest parsed application manifest
   * @param paths derived filesystem paths for the installed app
   * @param token opaque per-start launch token
   * @param pid child-process id
   * @param startedAt launch timestamp
   */
  public RunningAppSnapshot {
    Objects.requireNonNull(manifest, "manifest");
    Objects.requireNonNull(paths, "paths");
    Objects.requireNonNull(token, "token");
    Objects.requireNonNull(startedAt, "startedAt");
    if (token.isBlank()) {
      throw new IllegalArgumentException("token must not be blank");
    }
    if (pid <= 0) {
      throw new IllegalArgumentException("pid must be positive");
    }
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
}
