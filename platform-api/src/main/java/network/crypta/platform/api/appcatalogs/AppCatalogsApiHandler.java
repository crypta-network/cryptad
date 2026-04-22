package network.crypta.platform.api.appcatalogs;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Signed app-catalog endpoint family for Platform API v1.
 *
 * <p>The handler exposes catalog source management, catalog app listing, and install/update actions
 * while preserving the existing local staged-directory app routes. Catalog install and update first
 * obtain a verified temporary stage from {@link AppCatalogManager}, then call the same AppHost
 * methods used by the local app API. That keeps bundle verification and mutable directory semantics
 * centralized in AppHost.
 *
 * <p>Instances are transport-neutral. The router supplies decoded path and query values, and this
 * class returns JSON-compatible maps and lists that the shared Platform API JSON writer can encode.
 * Catalog failures stay expressed with stable machine-readable catalog codes, while AppHost
 * failures are translated to the same app lifecycle contracts used by local install and update
 * endpoints. The handler does not keep mutable request state; the shared {@link AppCatalogManager}
 * and {@link AppHost} own persistence, staging, and lifecycle decisions.
 */
public final class AppCatalogsApiHandler {
  private static final System.Logger LOG = System.getLogger(AppCatalogsApiHandler.class.getName());

  private static final String APP_ALREADY_INSTALLED_PREFIX = "app already installed: ";
  private static final String APP_NOT_INSTALLED_PREFIX = "app is not installed: ";
  private static final String CANNOT_UPDATE_RUNNING_APP_PREFIX = "cannot update a running app: ";
  private static final String INSTALL_FAILED_MESSAGE = "Failed to install catalog app.";
  private static final String UPDATE_FAILED_MESSAGE = "Failed to update catalog app.";

  private final AppCatalogManager catalogManager;
  private final AppHost appHost;

  /**
   * Creates a handler backed by a catalog manager and shared AppHost.
   *
   * <p>The supplied catalog manager is expected to use the same trusted-key policy as the AppHost
   * verification policy for PR-195. The handler performs no global lookup and does not cache
   * trusted keys itself, which lets runtime composition reload key material between requests when
   * configured to do so.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   */
  public AppCatalogsApiHandler(AppCatalogManager catalogManager, AppHost appHost) {
    this.catalogManager = Objects.requireNonNull(catalogManager, "catalogManager");
    this.appHost = Objects.requireNonNull(appHost, "appHost");
  }

  /**
   * Lists configured catalog sources.
   *
   * <p>Every stored catalog is re-read through the manager, which re-verifies the persisted catalog
   * sidecars before exposing metadata. A corrupt or no-longer-trusted catalog therefore returns a
   * catalog error instead of stale cached data.
   *
   * @return JSON-compatible catalog source summaries in manager-defined order
   */
  public List<Map<String, Object>> listCatalogs() {
    try {
      return catalogManager.listCatalogs().stream().map(this::summarizeCatalog).toList();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list app catalogs.");
    }
  }

  /**
   * Adds a signed catalog source and returns the verified catalog summary.
   *
   * <p>The {@code source} parameter may name a local file, a {@code file:} URI, an HTTPS URI, or a
   * loopback HTTP URI accepted by the catalog source policy. Adding is intentionally eager: the
   * source is fetched, its signature is checked, the catalog is parsed, and only then is the source
   * persisted.
   *
   * @param queryParameters decoded request query or form parameters containing {@code source}
   * @return JSON-compatible summary for the newly stored and verified catalog
   */
  public Map<String, Object> add(Map<String, List<String>> queryParameters) {
    String source = PlatformApiParameters.requireString(queryParameters, "source");
    try {
      return summarizeCatalog(catalogManager.addSource(source));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to add app catalog.");
    }
  }

  /**
   * Removes one configured catalog source.
   *
   * <p>Removal deletes the locally configured source record and cached catalog sidecars. It does
   * not uninstall apps that were previously installed from that catalog, because installed app
   * lifecycle remains owned by the app endpoints.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible removal summary containing the requested id and removal flag
   */
  public Map<String, Object> remove(String catalogId) {
    try {
      catalogManager.remove(catalogId);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
      json.put("catalogId", catalogId);
      json.put("removed", true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to remove app catalog.");
    }
  }

  /**
   * Refreshes one configured catalog source.
   *
   * <p>Refresh reuses the stored source URI, fetches fresh catalog sidecars, verifies the
   * signature, and rejects the result if the authenticated catalog id no longer matches the
   * configured id. A failed refresh leaves the previous stored sidecars in place.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible summary for the refreshed catalog
   */
  public Map<String, Object> refresh(String catalogId) {
    try {
      return summarizeCatalog(catalogManager.refresh(catalogId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to refresh app catalog.");
    }
  }

  /**
   * Lists apps in one catalog.
   *
   * <p>The response preserves the catalog-declared app order and adds local AppHost state for each
   * entry. Bundle URI, digest, and size metadata remain visible so operators can inspect what a
   * catalog would download before installing or updating.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible app entries enriched with local installed/running state
   */
  public List<Map<String, Object>> listApps(String catalogId) {
    try {
      return catalogManager.listApps(catalogId).stream().map(this::summarizeEntry).toList();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list catalog apps.");
    }
  }

  /**
   * Describes one app in a catalog.
   *
   * <p>The app id is resolved through the verified catalog, not directly through AppHost. That
   * keeps {@code app_not_found} distinct from an installed-app lookup failure and lets callers
   * inspect a catalog entry even when the app is not installed locally.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return JSON-compatible app entry enriched with local installed/running state
   */
  public Map<String, Object> getApp(String catalogId, String appId) {
    try {
      return summarizeEntry(catalogManager.getApp(catalogId, appId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app.");
    }
  }

  /**
   * Installs one catalog app through AppHost.
   *
   * <p>The method first confirms that the catalog entry exists and that the app is not already
   * installed. It then asks the manager to download, digest-check, extract, and verify the signed
   * bundle before delegating the final copy into the managed app tree to AppHost. Scratch cleanup
   * runs after the mutation and is logged if it fails so cleanup trouble does not mask a committed
   * installation.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> install(String catalogId, String appId) {
    String normalizedAppId;
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      normalizedAppId = entry.appId();
      if (appHost.describe(normalizedAppId).isPresent()) {
        throw conflict(APP_ALREADY_INSTALLED_PREFIX + normalizedAppId);
      }
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(INSTALL_FAILED_MESSAGE);
    }
    AppCatalogInstallPlan plan = null;
    try {
      plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);
      InstalledAppSnapshot installed = appHost.installFromDirectory(plan.stagedBundleDirectory());
      return summarizeInstalledApp(installed.manifest());
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (AppHostException exception) {
      throw installFailure(exception);
    } catch (IOException _) {
      throw internalError(INSTALL_FAILED_MESSAGE);
    } finally {
      cleanUpPlan(plan);
    }
  }

  /**
   * Updates one installed app from a catalog entry through AppHost.
   *
   * <p>The update path refuses running apps before staging remote data and fails fast when the app
   * is clearly not installed. If the installed manifest is unreadable, the method still lets
   * AppHost attempt the update so a valid catalog bundle can repair a damaged installation. The
   * staged bundle follows the same catalog digest, extraction, and signed-bundle verification path
   * as install.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return updated installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> update(String catalogId, String appId) {
    String normalizedAppId;
    AppCatalogEntry entry;
    try {
      entry = catalogManager.getApp(catalogId, appId);
      normalizedAppId = entry.appId();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(UPDATE_FAILED_MESSAGE);
    }
    if (appHost.status(normalizedAppId).isPresent()) {
      throw conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + normalizedAppId);
    }
    try {
      if (appHost.describe(normalizedAppId).isEmpty()) {
        throw new PlatformApiException(404, "app_not_found", "App not found.");
      }
    } catch (IOException _) {
      // Allow AppHost to repair installs whose manifest is unreadable.
    }
    AppCatalogInstallPlan plan = null;
    try {
      plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);
      InstalledAppSnapshot updated =
          appHost.updateFromDirectory(entry.appId(), plan.stagedBundleDirectory());
      return summarizeInstalledApp(updated.manifest());
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (AppHostException exception) {
      throw updateFailure(normalizedAppId, exception);
    } catch (IOException _) {
      throw internalError(UPDATE_FAILED_MESSAGE);
    } finally {
      cleanUpPlan(plan);
    }
  }

  private static void cleanUpPlan(AppCatalogInstallPlan plan) {
    if (plan == null) {
      return;
    }
    try {
      plan.close();
    } catch (IOException exception) {
      LOG.log(
          System.Logger.Level.WARNING, "Failed to clean catalog app scratch directory", exception);
    }
  }

  private Map<String, Object> summarizeCatalog(AppCatalogSourceSnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("catalogId", snapshot.catalogId());
    json.put("name", snapshot.name());
    json.put("source", snapshot.sourceUri().toString());
    json.put("generatedAt", snapshot.generatedAt().toString());
    json.put("appCount", snapshot.appCount());
    json.put("addedAt", snapshot.addedAt().toString());
    json.put("refreshedAt", snapshot.refreshedAt().toString());
    return json;
  }

  private Map<String, Object> summarizeEntry(AppCatalogEntry entry) {
    InstalledAppSnapshot installed = installed(entry.appId());
    RunningAppSnapshot running = appHost.status(entry.appId()).orElse(null);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(12);
    json.put("appId", entry.appId());
    json.put("name", entry.name());
    json.put("version", entry.version());
    json.put("summary", entry.summary());
    json.put("permissions", entry.permissions());
    json.put("bundle", summarizeBundle(entry));
    json.put("installed", installed != null);
    json.put("installedVersion", installed == null ? null : installed.manifest().appVersion());
    json.put("running", running != null);
    json.put("pid", running == null ? null : running.pid());
    json.put("startedAt", running == null ? null : running.startedAt().toString());
    return json;
  }

  private InstalledAppSnapshot installed(String appId) {
    try {
      return appHost.describe(appId).orElse(null);
    } catch (IOException _) {
      throw internalError("Failed to read installed apps.");
    }
  }

  private static Map<String, Object> summarizeBundle(AppCatalogEntry entry) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("uri", entry.bundleUri().toString());
    json.put("type", entry.bundleType());
    json.put("sizeBytes", entry.bundleSizeBytes());
    json.put("sha256", entry.bundleSha256());
    return json;
  }

  private static Map<String, Object> summarizeInstalledApp(AppManifest manifest) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("appId", manifest.appId());
    json.put("name", manifest.appName());
    json.put("version", manifest.appVersion());
    json.put("uiEntry", manifest.uiEntry());
    json.put("permissions", manifest.permissions());
    json.put("installed", true);
    json.put("running", false);
    json.put("pid", null);
    json.put("startedAt", null);
    return json;
  }

  private PlatformApiException catalogFailure(AppCatalogException exception) {
    return switch (exception.errorCode()) {
      case "catalog_not_found", "app_not_found" ->
          new PlatformApiException(404, exception.errorCode(), exception.getMessage());
      case "catalog_conflict" ->
          new PlatformApiException(409, exception.errorCode(), exception.getMessage());
      default -> new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    };
  }

  private PlatformApiException installFailure(AppHostException exception) {
    if (isAlreadyInstalledFailure(exception)) {
      return conflict(alreadyInstalledMessage(exception));
    }
    if (exception instanceof AppBundleVerificationException) {
      return new PlatformApiException(
          400, "invalid_app_bundle", "Catalog app bundle failed trusted verification.");
    }
    return internalError(INSTALL_FAILED_MESSAGE);
  }

  private PlatformApiException updateFailure(String appId, AppHostException exception) {
    if (isRunningUpdateFailure(exception) || appHost.status(appId).isPresent()) {
      return conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + appId);
    }
    if (isMissingAppFailure(exception)) {
      return new PlatformApiException(404, "app_not_found", "App not found.");
    }
    if (exception instanceof AppBundleVerificationException) {
      return new PlatformApiException(
          400, "invalid_app_bundle", "Catalog app bundle failed trusted verification.");
    }
    return internalError(UPDATE_FAILED_MESSAGE);
  }

  private static boolean isAlreadyInstalledFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(APP_ALREADY_INSTALLED_PREFIX);
  }

  private static boolean isRunningUpdateFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(CANNOT_UPDATE_RUNNING_APP_PREFIX);
  }

  private static boolean isMissingAppFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(APP_NOT_INSTALLED_PREFIX);
  }

  private static PlatformApiException conflict(String message) {
    return new PlatformApiException(409, "app_conflict", message);
  }

  private static PlatformApiException internalError(String message) {
    return new PlatformApiException(500, "internal_error", message);
  }

  private static String alreadyInstalledMessage(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? "App already installed." : message;
  }
}
