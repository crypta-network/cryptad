package network.crypta.platform.apphost;

import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Immutable snapshot of one installed application.
 *
 * <p>This record joins the parsed manifest with the derived on-disk paths that the host uses for
 * the same application identifier. It is the stable read model returned by install and discovery
 * operations, so callers can inspect identity, version metadata, permissions, and the resolved host
 * layout without re-reading the manifest themselves.
 *
 * <p>The snapshot is immutable, but it is still time-bound. Later host operations may uninstall or
 * replace the application after the snapshot is created. Callers should therefore treat it as a
 * report of what the host observed at one point in time, not as a durable lease on the underlying
 * files.
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
   * <p>This convenience method exposes the canonical identifier that ties together the manifest and
   * the derived path bundle.
   *
   * @return manifest application identifier
   */
  public String appId() {
    return manifest.appId();
  }
}
