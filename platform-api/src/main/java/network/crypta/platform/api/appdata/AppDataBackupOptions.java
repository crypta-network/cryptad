package network.crypta.platform.api.appdata;

import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;

/**
 * Operator-selected scope for creating one app-data backup bundle.
 *
 * <p>{@code AppDataBackupOptions} is the normalized form of the operator backup route parameters.
 * It decides whether the service exports exactly one app id or every app id known to the durable
 * app-data store. This is intentionally host/operator-only state; app principals continue to use
 * the app-facing export route, which is scoped to the authenticated app and cannot request another
 * app id.
 *
 * <p>The record keeps the route grammar unambiguous. A single-app backup must provide one
 * normalized app id, while an all-app backup must not include an app id at all. The options do not
 * carry filesystem paths, app principal tokens, browser sessions, vault secrets, app bundles, or
 * destination file names. The source daemon version is only a path-free manifest hint and defaults
 * to {@code unknown} when the caller cannot provide one.
 *
 * @param scope backup scope, either {@code single-app} or {@code all-apps}
 * @param appId normalized app id for single-app backups, otherwise {@code null}
 * @param sourceCryptaVersion path-free daemon version label to include in the envelope
 * @see AppDataBackupManifest
 */
public record AppDataBackupOptions(String scope, String appId, String sourceCryptaVersion) {
  /**
   * Backup scope containing exactly one normalized app id.
   *
   * <p>Operator routes use this scope for a per-app backup download. The service rejects a missing
   * or invalid app id before it reads durable store state.
   */
  public static final String SCOPE_SINGLE_APP = "single-app";

  /**
   * Backup scope containing every app-data app id safely known to the store.
   *
   * <p>This scope includes preserved app-data for uninstalled apps when the store can discover the
   * app id safely. It still excludes vault secrets, app bundles, cache data, and arbitrary files.
   */
  public static final String SCOPE_ALL_APPS = "all-apps";

  /**
   * Creates validated backup options.
   *
   * <p>The canonical constructor normalizes a single-app id through the same app-data identifier
   * rules used by records and rejects mixed parameter shapes. That prevents callers from submitting
   * {@code scope=all} with an {@code appId} and then relying on route-specific interpretation. The
   * constructor also trims the source version label and replaces blank labels with {@code unknown}.
   *
   * @throws PlatformApiException if scope or app id is invalid
   * @throws NullPointerException if scope is {@code null}
   */
  public AppDataBackupOptions {
    Objects.requireNonNull(scope, "scope");
    if (!SCOPE_SINGLE_APP.equals(scope) && !SCOPE_ALL_APPS.equals(scope)) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "App-data backup scope must be single-app or all-apps.");
    }
    if (SCOPE_SINGLE_APP.equals(scope)) {
      appId = AppDataRecord.normalizeAppId(appId);
    } else if (appId != null) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "All-app app-data backup must not include appId.");
    }
    sourceCryptaVersion =
        sourceCryptaVersion == null || sourceCryptaVersion.isBlank()
            ? "unknown"
            : sourceCryptaVersion.trim();
  }

  /**
   * Creates options for a single-app backup.
   *
   * <p>Use this factory when route parsing has established that the operator requested one app's
   * durable app-data. The returned options are ready for service-level export and will fail fast if
   * the app id is blank, malformed, or not normalizable.
   *
   * @param appId app id to export through the operator backup path
   * @param sourceCryptaVersion daemon version label to place in the manifest
   * @return validated single-app backup options
   */
  public static AppDataBackupOptions singleApp(String appId, String sourceCryptaVersion) {
    return new AppDataBackupOptions(SCOPE_SINGLE_APP, appId, sourceCryptaVersion);
  }

  /**
   * Creates options for an all-app backup.
   *
   * <p>Use this factory for explicit all-app backups. The resulting options intentionally leave
   * {@code appId} unset so service code can enumerate durable store app ids rather than trust a
   * caller-provided list.
   *
   * @param sourceCryptaVersion daemon version label to place in the manifest
   * @return validated all-app backup options
   */
  public static AppDataBackupOptions allApps(String sourceCryptaVersion) {
    return new AppDataBackupOptions(SCOPE_ALL_APPS, null, sourceCryptaVersion);
  }
}
