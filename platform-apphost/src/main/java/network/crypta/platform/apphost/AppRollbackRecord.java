package network.crypta.platform.apphost;

import java.util.Objects;

/**
 * Path-free metadata for one durable AppHost rollback bundle.
 *
 * <p>The record describes the bundle that {@link AppHost#rollback(String)} would restore for the
 * supplied app id. It intentionally carries only manifest-level identity and version metadata: no
 * launch tokens, command lines, environment values, or host filesystem paths are included in the
 * record state or generated {@code toString()} output.
 *
 * <p>A rollback record is created after a successful update preserves the previous verified
 * installed bundle. It is suitable for Platform API summaries and release-certification evidence,
 * but it is not itself an authority to perform rollback. AppHost still validates the rollback tree,
 * confirms that the retained manifest belongs to the requested app id, and refuses to replace a
 * running app. Rollback restores only immutable bundle files; data, cache, and run directories stay
 * attached to the app id.
 *
 * @param appId stable application identifier normalized by {@link InstalledAppPaths#normalizeAppId}
 * @param appName human-readable application name from the retained bundle manifest
 * @param appVersion display version from the retained bundle manifest
 * @see AppHost#rollbackStatus(String)
 * @see AppHost#rollback(String)
 */
public record AppRollbackRecord(String appId, String appName, String appVersion) {
  /**
   * Creates a validated rollback metadata record.
   *
   * <p>The app id is normalized with the same path-safe rules AppHost uses for installed apps. Name
   * and version are display metadata from a previously verified manifest and must be present. The
   * constructor does not read the filesystem or check that a rollback directory still exists.
   *
   * @param appId stable application identifier accepted by AppHost path normalization
   * @param appName rollback bundle display name, never {@code null}
   * @param appVersion rollback bundle display version, never {@code null}
   */
  public AppRollbackRecord {
    appId = InstalledAppPaths.normalizeAppId(appId);
    Objects.requireNonNull(appName, "appName");
    Objects.requireNonNull(appVersion, "appVersion");
  }
}
