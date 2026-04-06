package network.crypta.platform.apphost;

import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Immutable snapshot of one installed application.
 *
 * @param manifest parsed application manifest
 * @param paths derived filesystem paths for the installed app
 */
public record InstalledAppSnapshot(AppManifest manifest, InstalledAppPaths paths) {
  /**
   * Creates a validated installed-app snapshot.
   *
   * @param manifest parsed application manifest
   * @param paths derived filesystem paths for the installed app
   */
  public InstalledAppSnapshot {
    Objects.requireNonNull(manifest, "manifest");
    Objects.requireNonNull(paths, "paths");
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
