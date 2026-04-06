package network.crypta.platform.apphost;

import java.time.Instant;
import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Immutable snapshot of one running child process.
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
   * @return manifest application identifier
   */
  public String appId() {
    return manifest.appId();
  }
}
