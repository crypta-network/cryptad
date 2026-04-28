package network.crypta.platform.api.apps;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.AppAuditEvent;
import network.crypta.platform.api.AppAuditLog;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppProcessLogSnapshot;
import network.crypta.platform.apphost.AppQuotaPolicy;
import network.crypta.platform.apphost.AppQuotaStatus;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.apphost.sandbox.AppSandboxException;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;
import network.crypta.platform.apphost.sandbox.AppSandboxProviders;
import network.crypta.platform.apphost.sandbox.AppSandboxStatus;
import network.crypta.platform.appui.AppUiPaths;

/**
 * App-management endpoint family for Platform API v1.
 *
 * <p>The handler keeps the transport-neutral AppHost surface small and explicit. It performs
 * request-parameter validation, maps AppHost snapshots onto stable JSON-friendly summaries, and
 * leaves the legacy HTTP bridge responsible only for authentication and byte-level response I/O.
 *
 * <p>Callers typically reach this type through {@code PlatformApiRouter} when servicing {@code
 * /api/v1/apps/...} requests. The handler does not parse request bodies or manage authentication
 * state. Instead, it accepts already-decoded path and query inputs, applies the minimal validation
 * needed for the app-management contract, and delegates lifecycle work to the shared {@link
 * AppHost}. That split keeps the Platform API surface transport-neutral while still exposing local
 * AppHost control operations through stable HTTP-style semantics.
 *
 * <p>The returned maps are deliberately conservative operator-facing projections. They merge
 * installation metadata with live process state, preserve deterministic field ordering for JSON
 * serialization, and avoid leaking AppHost-internal details such as launch tokens or filesystem
 * layout. Error mapping follows the Platform API v1 contract: malformed inputs become structured
 * {@code 400} responses, missing apps become {@code 404}, lifecycle conflicts become {@code 409},
 * and unexpected host-side failures remain {@code 500}.
 *
 * <ul>
 *   <li>Inventory reads merge installed and running state into one summary shape.
 *   <li>Mutation routes stay local and explicit: install, start, update, stop, and uninstall.
 *   <li>Cleanup flows keep working even when installed manifests have become unreadable.
 * </ul>
 */
public final class AppsApiHandler {
  private static final String APP_ALREADY_INSTALLED_PREFIX = "app already installed: ";
  private static final String APP_NOT_INSTALLED_PREFIX = "app is not installed: ";
  private static final String CANNOT_UPDATE_RUNNING_APP_PREFIX = "cannot update a running app: ";
  private static final String FIELD_APP_ID = "appId";
  private static final String FIELD_CACHE_BYTES = "cacheBytes";
  private static final String FIELD_DATA_BYTES = "dataBytes";
  private static final String FIELD_PERMISSIONS = "permissions";
  private static final String FIELD_QUOTA = "quota";
  private static final String FIELD_RECENT_DENIED_COUNT = "recentDeniedCount";
  private static final String FIELD_RUNNING = "running";
  private static final String FIELD_SANDBOX = "sandbox";
  private static final String FIELD_STARTED_AT = "startedAt";
  private static final String FIELD_WARNINGS = "warnings";
  private static final String MAX_BYTES_POSITIVE_INTEGER_MESSAGE =
      "Query parameter 'maxBytes' must be a positive integer.";
  private static final String SIGNED_BUNDLE_FAILURE_MESSAGE =
      "Staged app bundle must pass trusted signature verification.";

  /** Detached AppHost core used for app lifecycle and inventory operations. */
  private final AppHost appHost;

  /** Shared bounded audit log for app-originated Platform API decisions. */
  private final AppAuditLog auditLog;

  /**
   * Creates an app-management handler backed by the supplied AppHost.
   *
   * <p>The supplied host is expected to be a long-lived shared instance owned by bootstrap or
   * composition code rather than a per-request object. This handler keeps only a reference to that
   * dependency and performs no additional caching, so later AppHost reads always reflect the
   * current host view of installed and running applications.
   *
   * @param appHost detached AppHost core used for app lifecycle operations
   */
  public AppsApiHandler(AppHost appHost) {
    this(appHost, new AppAuditLog());
  }

  /**
   * Creates an app-management handler backed by the supplied AppHost and audit log.
   *
   * @param appHost detached AppHost core used for app lifecycle operations
   * @param auditLog bounded process-local app audit log
   */
  public AppsApiHandler(AppHost appHost, AppAuditLog auditLog) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.auditLog = Objects.requireNonNull(auditLog, "auditLog");
  }

  /**
   * Lists all installed apps with their merged running-state summary.
   *
   * <p>The returned list is suitable for the {@code {"apps":[...]}} Platform API envelope. Each
   * entry starts from the AppHost-installed snapshot and then overlays live process information, if
   * present, so callers do not need a second status request to determine whether an app is
   * currently running.
   *
   * @return ordered list of app summaries suitable for JSON serialization
   */
  public List<Map<String, Object>> list() {
    try {
      Map<String, RunningAppSnapshot> runningByAppId = runningByAppId(appHost.listRunning());
      List<InstalledAppSnapshot> installedApps = appHost.listInstalled();
      Map<String, AppQuotaStatus> quotaByAppId = quotaByAppId(installedApps);
      return installedApps.stream()
          .map(
              snapshot ->
                  summarize(
                      snapshot.manifest(),
                      true,
                      runningByAppId.get(snapshot.appId()),
                      quotaByAppId.get(snapshot.appId())))
          .toList();
    } catch (IOException _) {
      throw internalError("Failed to list installed apps.");
    }
  }

  /**
   * Describes one installed app with its merged running-state summary.
   *
   * <p>The supplied identifier is normalized into the canonical AppHost form before lookup. A
   * missing installation therefore reports the stable Platform API {@code app_not_found} error
   * regardless of whether the original path segment differed only by case or formatting.
   *
   * @param appId stable application identifier extracted from the request path
   * @return JSON-compatible app summary
   */
  public Map<String, Object> get(String appId) {
    String normalizedAppId = normalizeAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    return summarize(
        installed.manifest(),
        true,
        appHost.status(normalizedAppId).orElse(null),
        quotaStatusForSummary(normalizedAppId));
  }

  /**
   * Returns token-free process runtime status for one installed app.
   *
   * @param appId stable application identifier extracted from the request path
   * @return JSON-compatible runtime status summary
   */
  public Map<String, Object> runtime(String appId) {
    String normalizedAppId = normalizeAppId(appId);
    try {
      return summarizeRuntime(appHost.runtimeStatus(normalizedAppId));
    } catch (AppHostException e) {
      if (isMissingAppFailure(e)) {
        throw appNotFound();
      }
      throw internalError("Failed to read app runtime status.");
    } catch (IOException _) {
      throw internalError("Failed to read app runtime status.");
    }
  }

  /**
   * Returns a bounded, token-redacted process-log tail for one installed app.
   *
   * @param appId stable application identifier extracted from the request path
   * @param queryParameters decoded query parameters for the current request
   * @return JSON-compatible process-log snapshot
   */
  public Map<String, Object> logs(String appId, Map<String, List<String>> queryParameters) {
    String normalizedAppId = normalizeAppId(appId);
    int maxBytes = parseMaxBytes(queryParameters);
    try {
      return summarizeProcessLog(appHost.readProcessLogTail(normalizedAppId, maxBytes));
    } catch (AppHostException e) {
      if (isMissingAppFailure(e)) {
        throw appNotFound();
      }
      throw internalError("Failed to read app process log.");
    } catch (IOException _) {
      throw internalError("Failed to read app process log.");
    }
  }

  /**
   * Returns the declared permissions for one installed app.
   *
   * @param appId stable application identifier extracted from the request path
   * @return JSON-compatible permissions summary
   */
  public Map<String, Object> permissions(String appId) {
    String normalizedAppId = normalizeAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put(FIELD_APP_ID, normalizedAppId);
    json.put(FIELD_PERMISSIONS, installed.manifest().permissions());
    json.put(FIELD_RUNNING, appHost.status(normalizedAppId).isPresent());
    json.put(FIELD_RECENT_DENIED_COUNT, auditLog.deniedCountForApp(normalizedAppId));
    return json;
  }

  /**
   * Returns recent bounded audit entries for one installed app.
   *
   * @param appId stable application identifier extracted from the request path
   * @return JSON-compatible audit summary
   */
  public Map<String, Object> audit(String appId) {
    String normalizedAppId = normalizeAppId(appId);
    requireInstalled(normalizedAppId);
    return auditSummary(normalizedAppId);
  }

  /**
   * Installs one staged app bundle and returns the installed summary.
   *
   * <p>AppHost v1 installs only from a caller-supplied local staging directory. This method
   * validates the {@code stagedDir} query parameter, parses the staged manifest early so conflicts
   * can be reported before mutation, and returns a summary for the installed copy rather than the
   * staging directory. Client-fixable bundle problems stay in the {@code 400} family, while
   * concurrent reinstallation and already-installed cases are reported as {@code 409} conflicts.
   *
   * @param queryParameters decoded query parameters for the current request
   * @return JSON-compatible app summary for the installed bundle
   */
  public Map<String, Object> install(Map<String, List<String>> queryParameters) {
    Path stagedDir = parseStagedDirectory(queryParameters);
    AppManifest manifest = parseManifest(stagedDir);
    if (installed(manifest.appId())) {
      throw conflict(APP_ALREADY_INSTALLED_PREFIX + manifest.appId());
    }

    try {
      InstalledAppSnapshot installed = appHost.installFromDirectory(stagedDir);
      return summarize(installed.manifest(), true, null, quotaStatusForSummary(installed.appId()));
    } catch (AppHostException e) {
      throw installFailure(manifest.appId(), e);
    } catch (IOException _) {
      throw internalError("Failed to install app.");
    }
  }

  /**
   * Replaces one installed app with a staged bundle and returns the updated summary.
   *
   * <p>The update flow is intentionally conservative. It accepts the same local staged-directory
   * input as install, but it only proceeds when the target app is not currently running. The staged
   * bundle must target the same app id as the installed bundle, and the host-owned mutable
   * directories remain untouched.
   *
   * <p>Unlike read-heavy inventory routes, update does not require the current installed manifest
   * to be readable before it delegates to the AppHost. That keeps staged replacement available as a
   * repair path for damaged installations whose immutable bundle can still be replaced safely.
   *
   * @param appId stable application identifier extracted from the request path
   * @param queryParameters decoded query parameters for the current request
   * @return JSON-compatible app summary for the updated bundle
   */
  public Map<String, Object> update(String appId, Map<String, List<String>> queryParameters) {
    String normalizedAppId = normalizeAppId(appId);
    Path stagedDir = parseStagedDirectory(queryParameters);
    AppManifest manifest = parseManifest(stagedDir);
    if (appHost.status(normalizedAppId).isPresent()) {
      throw conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + normalizedAppId);
    }

    if (!normalizedAppId.equals(manifest.appId())) {
      throw invalidBundle(
          "staged app bundle app.id does not match target app: " + manifest.appId());
    }

    try {
      InstalledAppSnapshot updated = appHost.updateFromDirectory(normalizedAppId, stagedDir);
      return summarize(updated.manifest(), true, null, quotaStatusForSummary(updated.appId()));
    } catch (AppHostException e) {
      throw updateFailure(normalizedAppId, e);
    } catch (IOException _) {
      throw internalError("Failed to update app.");
    }
  }

  /**
   * Starts one installed app and returns the running summary without exposing the launch token.
   *
   * <p>The method checks live status before it requires a readable installed manifest. That keeps
   * repeated start requests idempotent from the caller's perspective even when a running app's
   * installed manifest later becomes unreadable. On success, the summary is derived from the
   * returned {@link RunningAppSnapshot}, so the response reflects the bundle that actually
   * launched.
   *
   * @param appId stable application identifier extracted from the request path
   * @return JSON-compatible app summary for the running app
   */
  public Map<String, Object> start(String appId) {
    String normalizedAppId = normalizeAppId(appId);
    if (appHost.status(normalizedAppId).isPresent()) {
      throw conflict("app is already running: " + normalizedAppId);
    }
    requireInstalled(normalizedAppId);

    try {
      RunningAppSnapshot running = appHost.start(normalizedAppId);
      return summarize(running.manifest(), true, running, quotaStatusForSummary(running.appId()));
    } catch (AppHostException e) {
      throw startFailure(normalizedAppId, e);
    } catch (IOException _) {
      throw internalError("Failed to start app.");
    }
  }

  /**
   * Stops one running app or cancels one pending automatic restart and returns the installed
   * summary.
   *
   * <p>This path anchors on the live {@link RunningAppSnapshot} first, which allows callers to stop
   * a damaged-but-running app even if its installed manifest can no longer be read safely. The
   * method delegates to AppHost before reading an installed summary on the non-running path so a
   * pending {@code RESTARTING} backoff can still be canceled when the installed manifest is damaged
   * or temporarily unreadable.
   *
   * @param appId stable application identifier extracted from the request path
   * @return JSON-compatible app summary after the app has stopped
   */
  public Map<String, Object> stop(String appId) {
    String normalizedAppId = normalizeAppId(appId);
    RunningAppSnapshot running = appHost.status(normalizedAppId).orElse(null);

    try {
      if (!appHost.stop(normalizedAppId)) {
        requireInstalled(normalizedAppId);
        throw conflict("app is not running: " + normalizedAppId);
      }
    } catch (IOException _) {
      throw internalError("Failed to stop app.");
    }
    if (running != null) {
      return summarize(running.manifest(), true, null, quotaStatusForSummary(running.appId()));
    }
    InstalledAppSnapshot installed = describeForStopSummary(normalizedAppId);
    return installed == null
        ? summarizeUnknown(normalizedAppId, true)
        : summarize(installed.manifest(), true, null, quotaStatusForSummary(installed.appId()));
  }

  /**
   * Uninstalls one stopped app and returns the final summary.
   *
   * <p>The response prefers the last readable installed snapshot, so callers get the normal summary
   * shape after a successful uninstallation. If the installed manifest is already unreadable, the
   * method still delegates to the AppHost uninstall path and falls back to a summary with
   * manifest-derived fields set to {@code null}. That keeps cleanup flows available for corrupted
   * installations without changing the top-level response envelope.
   *
   * @param appId stable application identifier extracted from the request path
   * @return JSON-compatible app summary with {@code installed=false}
   */
  public Map<String, Object> uninstall(String appId) {
    String normalizedAppId = normalizeAppId(appId);
    if (appHost.status(normalizedAppId).isPresent()) {
      throw conflict("cannot uninstall a running app: " + normalizedAppId);
    }
    InstalledAppSnapshot installed = describeForUninstallSummary(normalizedAppId);

    try {
      appHost.uninstall(normalizedAppId);
      return installed != null
          ? summarize(installed.manifest(), false, null, null)
          : summarizeUnknown(normalizedAppId, false);
    } catch (AppHostException e) {
      throw uninstallFailure(normalizedAppId, e);
    } catch (IOException _) {
      throw internalError("Failed to uninstall app.");
    }
  }

  /**
   * Requires that one app is installed and returns its installed snapshot.
   *
   * @param appId stable application identifier extracted from the request path
   * @return installed snapshot for the requested app
   */
  private InstalledAppSnapshot requireInstalled(String appId) {
    try {
      return appHost.describe(appId).orElseThrow(AppsApiHandler::appNotFound);
    } catch (IOException _) {
      throw internalError("Failed to read installed apps.");
    }
  }

  /**
   * Returns whether an app is already installed.
   *
   * @param appId stable application identifier
   * @return {@code true} when the app is already installed
   */
  private boolean installed(String appId) {
    try {
      return appHost.describe(appId).isPresent();
    } catch (IOException _) {
      throw internalError("Failed to read installed apps.");
    }
  }

  /**
   * Attempts to read the installed snapshot for uninstallation response shaping.
   *
   * <p>Uninstall remains callable by app id even when the installed manifest is unreadable. This
   * helper therefore treats read failures as "summary unavailable" rather than aborting the
   * operation up front.
   *
   * @param appId stable application identifier
   * @return installed snapshot when it can be read safely, otherwise {@code null}
   */
  private InstalledAppSnapshot describeForUninstallSummary(String appId) {
    try {
      return appHost.describe(appId).orElse(null);
    } catch (IOException _) {
      return null;
    }
  }

  /**
   * Attempts to read the installed snapshot for stop response shaping.
   *
   * <p>Stop remains callable for pending restart cancellation even when the installed manifest is
   * unreadable. This helper therefore treats read failures as "summary unavailable" after the
   * stop/cancel operation has already succeeded.
   *
   * @param appId stable application identifier
   * @return installed snapshot when it can be read safely, otherwise {@code null}
   */
  private InstalledAppSnapshot describeForStopSummary(String appId) {
    try {
      return appHost.describe(appId).orElse(null);
    } catch (IOException _) {
      return null;
    }
  }

  /**
   * Converts the running-app list into a lookup keyed by app id.
   *
   * @param running running snapshots returned by the AppHost
   * @return encounter-order-preserving running snapshot lookup
   */
  private static Map<String, RunningAppSnapshot> runningByAppId(List<RunningAppSnapshot> running) {
    LinkedHashMap<String, RunningAppSnapshot> runningByAppId =
        LinkedHashMap.newLinkedHashMap(running.size());
    for (RunningAppSnapshot snapshot : running) {
      runningByAppId.put(snapshot.appId(), snapshot);
    }
    return runningByAppId;
  }

  private Map<String, AppQuotaStatus> quotaByAppId(List<InstalledAppSnapshot> installedApps) {
    LinkedHashMap<String, AppQuotaStatus> quotaByAppId =
        LinkedHashMap.newLinkedHashMap(installedApps.size());
    for (InstalledAppSnapshot snapshot : installedApps) {
      quotaByAppId.put(snapshot.appId(), quotaStatusForSummary(snapshot.appId()));
    }
    return quotaByAppId;
  }

  private AppQuotaStatus quotaStatusForSummary(String appId) {
    try {
      return appHost.runtimeStatus(appId).quotaStatus();
    } catch (IOException _) {
      return null;
    }
  }

  /**
   * Extracts and validates the local staging directory from the request query.
   *
   * @param queryParameters decoded query parameters for the current request
   * @return absolute staging directory path
   */
  private static Path parseStagedDirectory(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.requireString(queryParameters, "stagedDir");
    try {
      Path stagedDir = Path.of(raw).normalize();
      if (!stagedDir.isAbsolute()) {
        throw invalidQuery("Query parameter 'stagedDir' must be an absolute filesystem path.");
      }
      if (!Files.isDirectory(stagedDir, LinkOption.NOFOLLOW_LINKS)) {
        throw invalidQuery("Query parameter 'stagedDir' must reference an existing directory.");
      }
      return stagedDir;
    } catch (InvalidPathException _) {
      throw invalidQuery("Query parameter 'stagedDir' must be a valid absolute filesystem path.");
    }
  }

  /**
   * Parses the staged app manifest so install requests can be rejected before mutation when the
   * target app is already installed.
   *
   * @param stagedDir caller-supplied staged bundle directory
   * @return parsed manifest for the staged bundle
   */
  private static AppManifest parseManifest(Path stagedDir) {
    try {
      return AppManifestParser.parse(stagedDir.resolve(AppManifestParser.MANIFEST_FILE_NAME));
    } catch (IOException _) {
      throw invalidQuery("Query parameter 'stagedDir' must reference a valid staged app bundle.");
    }
  }

  /**
   * Builds one JSON-friendly app summary from the manifest and optional running snapshot.
   *
   * @param manifest normalized application manifest
   * @param installed whether the app is still installed
   * @param running running snapshot when the app is live, or {@code null}
   * @return ordered JSON-compatible summary map
   */
  private Map<String, Object> summarize(
      AppManifest manifest,
      boolean installed,
      RunningAppSnapshot running,
      AppQuotaStatus quotaStatus) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put(FIELD_APP_ID, manifest.appId());
    json.put("name", manifest.appName());
    json.put("version", manifest.appVersion());
    json.put("uiMode", manifest.uiMode().manifestValue());
    json.put("uiEntry", manifest.uiEntry());
    json.put("uiUrl", AppUiPaths.uiUrl(manifest));
    json.put(FIELD_PERMISSIONS, manifest.permissions());
    json.put(FIELD_QUOTA, quota(manifest, quotaStatus));
    json.put(FIELD_SANDBOX, summarizeSandbox(sandboxStatus(manifest, running)));
    json.put("installed", installed);
    json.put(FIELD_RUNNING, running != null);
    json.put("pid", running == null ? null : running.pid());
    json.put(FIELD_STARTED_AT, running == null ? null : running.startedAt().toString());
    json.put(FIELD_RECENT_DENIED_COUNT, auditLog.deniedCountForApp(manifest.appId()));
    json.put("audit", auditSummary(manifest.appId()));
    return json;
  }

  /**
   * Builds one JSON-friendly runtime status object.
   *
   * @param snapshot token-free AppHost runtime status snapshot
   * @return ordered JSON-compatible runtime status map
   */
  private static Map<String, Object> summarizeRuntime(AppRuntimeStatusSnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put(FIELD_APP_ID, snapshot.appId());
    json.put("state", snapshot.state().name());
    json.put(FIELD_RUNNING, snapshot.running());
    json.put("pid", snapshot.pid());
    json.put(FIELD_STARTED_AT, instantText(snapshot.startedAt()));
    json.put("lastExitAt", instantText(snapshot.lastExitAt()));
    json.put("lastExitCode", snapshot.lastExitCode());
    json.put("restartCount", snapshot.restartCount());
    json.put("currentRestartAttempt", snapshot.currentRestartAttempt());
    json.put("logAvailable", snapshot.logAvailable());
    json.put("logSizeBytes", snapshot.logSizeBytes());
    json.put(FIELD_SANDBOX, summarizeSandbox(snapshot.sandboxStatus()));
    json.put(FIELD_QUOTA, quota(snapshot.quotaStatus()));
    json.put(FIELD_WARNINGS, snapshot.warnings());
    return json;
  }

  /**
   * Builds one JSON-friendly process-log object.
   *
   * @param snapshot bounded redacted AppHost process-log snapshot
   * @return ordered JSON-compatible process-log map
   */
  private static Map<String, Object> summarizeProcessLog(AppProcessLogSnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put(FIELD_APP_ID, snapshot.appId());
    json.put("available", snapshot.available());
    json.put("truncated", snapshot.truncated());
    json.put("maxBytes", snapshot.maxBytes());
    json.put("sizeBytes", snapshot.sizeBytes());
    json.put("text", snapshot.text());
    json.put("lastModifiedAt", instantText(snapshot.lastModifiedAt()));
    return json;
  }

  private static String instantText(Instant instant) {
    return instant == null ? null : instant.toString();
  }

  /**
   * Builds a fallback summary for operations that succeed after manifest reads already failed.
   *
   * <p>This keeps the response envelope stable for operator cleanup flows such as uninstalling a
   * damaged app bundle whose manifest can no longer be parsed.
   *
   * @param appId normalized application identifier
   * @return ordered JSON-compatible summary map with unknown manifest fields set to {@code null}
   */
  private Map<String, Object> summarizeUnknown(String appId, boolean installed) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put(FIELD_APP_ID, appId);
    json.put("name", null);
    json.put("version", null);
    json.put("uiMode", "none");
    json.put("uiEntry", null);
    json.put("uiUrl", null);
    json.put(FIELD_PERMISSIONS, List.of());
    json.put(FIELD_QUOTA, unknownQuota());
    json.put(
        FIELD_SANDBOX,
        summarizeSandbox(AppSandboxProviders.inactiveStatus(AppSandboxPolicy.defaults())));
    json.put("installed", installed);
    json.put(FIELD_RUNNING, false);
    json.put("pid", null);
    json.put(FIELD_STARTED_AT, null);
    json.put(FIELD_RECENT_DENIED_COUNT, auditLog.deniedCountForApp(appId));
    json.put("audit", auditSummary(appId));
    return json;
  }

  private Map<String, Object> auditSummary(String appId) {
    List<AppAuditEvent> recent = auditLog.recentForApp(appId, AppAuditLog.DEFAULT_APP_EVENT_LIMIT);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put(FIELD_APP_ID, appId);
    json.put("boundedEventLimit", AppAuditLog.DEFAULT_APP_EVENT_LIMIT);
    json.put(FIELD_RECENT_DENIED_COUNT, auditLog.deniedCountForApp(appId));
    json.put("events", recent.stream().map(AppsApiHandler::summarizeAuditEvent).toList());
    return json;
  }

  private static Map<String, Object> summarizeAuditEvent(AppAuditEvent event) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("timestamp", event.timestamp().toString());
    json.put(FIELD_APP_ID, event.appId());
    json.put("method", event.method());
    json.put("endpointFamily", event.endpointFamily());
    json.put("action", event.action());
    json.put("requiredCapabilities", event.requiredCapabilities());
    json.put("authSource", event.authSource().name());
    json.put("decision", event.decision().name());
    json.put("statusCode", event.statusCode());
    json.put("reasonCode", event.reasonCode());
    return json;
  }

  /**
   * Builds the quota sub-object for one app manifest.
   *
   * @param manifest normalized application manifest
   * @return ordered JSON-compatible quota map
   */
  private static Map<String, Object> quota(AppManifest manifest, AppQuotaStatus quotaStatus) {
    AppQuotaPolicy policy =
        quotaStatus == null ? AppQuotaPolicy.fromManifest(manifest) : quotaStatus.policy();
    LinkedHashMap<String, Object> json = new LinkedHashMap<>(quota(policy, quotaStatus));
    json.put(FIELD_DATA_BYTES, manifest.dataQuotaBytes());
    json.put(FIELD_CACHE_BYTES, manifest.cacheQuotaBytes());
    return json;
  }

  private static Map<String, Object> unknownQuota() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(13);
    json.put(FIELD_DATA_BYTES, null);
    json.put(FIELD_CACHE_BYTES, null);
    json.put("effectiveDataBytes", null);
    json.put("effectiveCacheBytes", null);
    json.put("dataUsageBytes", null);
    json.put("cacheUsageBytes", null);
    json.put("dataQuotaEnforced", false);
    json.put("cacheQuotaEnforced", false);
    json.put("dataOverLimit", false);
    json.put("cacheOverLimit", false);
    json.put("processLogMaxBytes", AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES);
    json.put("processLogSizeBytes", null);
    json.put(FIELD_WARNINGS, List.of());
    return json;
  }

  private static Map<String, Object> quota(AppQuotaStatus quotaStatus) {
    return quota(quotaStatus.policy(), quotaStatus);
  }

  private static Map<String, Object> quota(AppQuotaPolicy policy, AppQuotaStatus quotaStatus) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(13);
    json.put(FIELD_DATA_BYTES, policy.dataQuotaBytes());
    json.put(FIELD_CACHE_BYTES, policy.cacheQuotaBytes());
    json.put("effectiveDataBytes", policy.effectiveDataQuotaBytes());
    json.put("effectiveCacheBytes", policy.effectiveCacheQuotaBytes());
    json.put("dataUsageBytes", quotaStatus == null ? null : quotaStatus.usage().dataUsageBytes());
    json.put("cacheUsageBytes", quotaStatus == null ? null : quotaStatus.usage().cacheUsageBytes());
    json.put("dataQuotaEnforced", policy.dataQuotaEnforced());
    json.put("cacheQuotaEnforced", policy.cacheQuotaEnforced());
    json.put("dataOverLimit", quotaStatus != null && quotaStatus.dataOverLimit());
    json.put("cacheOverLimit", quotaStatus != null && quotaStatus.cacheOverLimit());
    json.put("processLogMaxBytes", policy.processLogMaxBytes());
    json.put(
        "processLogSizeBytes",
        quotaStatus == null ? null : quotaStatus.usage().processLogSizeBytes());
    json.put(FIELD_WARNINGS, quotaStatus == null ? List.of() : quotaStatus.warningMessages());
    return json;
  }

  private static AppSandboxStatus sandboxStatus(AppManifest manifest, RunningAppSnapshot running) {
    return running == null
        ? AppSandboxProviders.inactiveStatus(manifest.sandboxPolicy())
        : running.sandboxStatus();
  }

  private static Map<String, Object> summarizeSandbox(AppSandboxStatus status) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("mode", status.mode().manifestValue());
    json.put("required", status.required());
    json.put("supportLevel", status.supportLevel().manifestValue());
    json.put("provider", status.providerName());
    json.put("active", status.active());
    json.put("reason", status.reason());
    json.put(FIELD_WARNINGS, status.warnings());
    return json;
  }

  private static int parseMaxBytes(Map<String, List<String>> queryParameters) {
    String rawMaxBytes = PlatformApiParameters.readOptionalString(queryParameters, "maxBytes");
    if (rawMaxBytes == null) {
      return AppHost.DEFAULT_PROCESS_LOG_TAIL_BYTES;
    }
    if (rawMaxBytes.isBlank()) {
      throw invalidQuery(MAX_BYTES_POSITIVE_INTEGER_MESSAGE);
    }
    try {
      int parsed = Integer.parseInt(rawMaxBytes);
      if (parsed <= 0) {
        throw invalidQuery(MAX_BYTES_POSITIVE_INTEGER_MESSAGE);
      }
      return Math.min(parsed, AppHost.MAX_PROCESS_LOG_TAIL_BYTES);
    } catch (NumberFormatException _) {
      throw invalidQuery(MAX_BYTES_POSITIVE_INTEGER_MESSAGE);
    }
  }

  /**
   * Creates the standard 400 error for malformed app-management requests.
   *
   * @param message validation failure message
   * @return structured Platform API exception
   */
  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }

  /**
   * Creates the standard 400 error for staged bundles that fail AppHost validation.
   *
   * @param message validation failure message from the AppHost
   * @return structured Platform API exception
   */
  private static PlatformApiException invalidBundle(String message) {
    return new PlatformApiException(400, "invalid_app_bundle", message);
  }

  /**
   * Creates the standard 404 error for missing app identifiers.
   *
   * @return structured Platform API exception
   */
  private static PlatformApiException appNotFound() {
    return new PlatformApiException(404, "app_not_found", "App not found.");
  }

  /**
   * Normalizes one path-supplied app identifier into the canonical AppHost form.
   *
   * @param appId raw application identifier extracted from the request path
   * @return normalized lower-case app identifier
   */
  private static String normalizeAppId(String appId) {
    try {
      return AppManifest.normalizeAppId(appId);
    } catch (IllegalArgumentException _) {
      throw new PlatformApiException(
          400, "invalid_app_id", "App identifier is not a valid AppHost id.");
    }
  }

  /**
   * Creates the standard 409 error for app state conflicts.
   *
   * @param message conflict message
   * @return structured Platform API exception
   */
  private static PlatformApiException conflict(String message) {
    return new PlatformApiException(409, "app_conflict", message);
  }

  /**
   * Maps install-time AppHost contract failures onto stable client-facing status codes.
   *
   * <p>AppHost validation failures are caller-fixable 4xx responses. A concurrent reinstalling race
   * is still reported as a conflict when the app became installed before the failed installation
   * returned.
   *
   * @param appId manifest-derived application identifier for the staged bundle
   * @param failure AppHost contract failure thrown during installation
   * @return structured Platform API exception
   */
  private PlatformApiException installFailure(String appId, AppHostException failure) {
    if (isAlreadyInstalledFailure(failure)) {
      return conflict(messageOrDefault(failure, "App already installed."));
    }
    if (installed(appId)) {
      return conflict(APP_ALREADY_INSTALLED_PREFIX + appId);
    }
    if (isSignedBundleVerificationFailure(failure)) {
      return invalidBundle(SIGNED_BUNDLE_FAILURE_MESSAGE);
    }
    if (isInvalidAppBundleFailure(failure)) {
      return invalidBundle(
          messageOrDefault(failure, "Staged app bundle failed AppHost validation."));
    }
    return internalError("Failed to install app.");
  }

  /**
   * Maps update-time AppHost contract failures onto stable client-facing status codes.
   *
   * <p>Update uses the same conflict and not-found contract as the other lifecycle operations.
   * Bundle validation failures stay in the {@code 400} family, while unexpected host-side errors
   * remain internal server failures.
   *
   * @param appId normalized application identifier for the current request
   * @param failure AppHost contract failure thrown during update
   * @return structured Platform API exception
   */
  private PlatformApiException updateFailure(String appId, AppHostException failure) {
    if (isRunningUpdateFailure(failure) || appHost.status(appId).isPresent()) {
      return conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + appId);
    }
    if (isMissingAppFailure(failure)) {
      return appNotFound();
    }
    if (isSignedBundleVerificationFailure(failure)) {
      return invalidBundle(SIGNED_BUNDLE_FAILURE_MESSAGE);
    }
    if (isInvalidAppBundleFailure(failure)) {
      return invalidBundle(
          messageOrDefault(failure, "Staged app bundle failed AppHost validation."));
    }
    return internalError("Failed to update app.");
  }

  private static boolean isRunningUpdateFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(CANNOT_UPDATE_RUNNING_APP_PREFIX);
  }

  private static boolean isMissingAppFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(APP_NOT_INSTALLED_PREFIX);
  }

  private static boolean isSignedBundleVerificationFailure(AppHostException failure) {
    return failure instanceof AppBundleVerificationException;
  }

  /**
   * Returns whether an install-time AppHost failure was caused by caller-supplied bundle input.
   *
   * <p>Install failures span both staged-bundle validation and host-managed layout validation. The
   * API keeps only the former in the {@code 400 invalid_app_bundle} class; broken managed
   * directories remain server-side {@code 500} errors so operators and automation do not treat them
   * as caller-fixable input problems.
   *
   * @param failure AppHost contract failure thrown during installation
   * @return {@code true} when the failure reflects staged-bundle or copied-bundle validation
   */
  private static boolean isInvalidAppBundleFailure(AppHostException failure) {
    if (failure instanceof network.crypta.platform.apphost.manifest.AppManifestException) {
      return true;
    }
    String message = failure.getMessage();
    if (message == null || message.isBlank()) {
      return false;
    }
    return message.startsWith("stagedAppDirectory ")
        || message.startsWith("staging directory ")
        || message.startsWith("copied manifest ")
        || message.startsWith("copied app.exec ")
        || message.startsWith("app.ui.entry ")
        || message.startsWith("app.exec ")
        || message.startsWith("staged app bundle ");
  }

  /**
   * Returns whether an install-time AppHost failure reported a concrete installation conflict.
   *
   * <p>This classifier trusts the AppHost failure that occurred during the actual installation
   * attempt, which avoids reclassifying concurrent staged-directory swaps against a stale
   * pre-validated app id from an earlier manifest parse.
   *
   * @param failure AppHost contract failure thrown during installation
   * @return {@code true} when the failure explicitly reports an installed-app conflict
   */
  private static boolean isAlreadyInstalledFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(APP_ALREADY_INSTALLED_PREFIX);
  }

  /**
   * Maps start-time AppHost contract failures onto stable client-facing status codes.
   *
   * <p>Concurrent lifecycle races are reclassified from AppHost exceptions into the same 404/409
   * API responses that precondition checks already use. Other start failures remain internal server
   * errors.
   *
   * @param appId normalized application identifier for the current request
   * @param failure AppHost contract failure thrown during start
   * @return structured Platform API exception
   */
  private PlatformApiException startFailure(String appId, AppHostException failure) {
    if (failure instanceof AppSandboxException sandboxFailure) {
      return new PlatformApiException(409, sandboxFailure.errorCode(), sandboxFailure.getMessage());
    }
    if (appHost.status(appId).isPresent()) {
      return conflict("app is already running: " + appId);
    }
    if (!installed(appId)) {
      return appNotFound();
    }
    if (isQuotaFailure(failure)) {
      return conflict(messageOrDefault(failure, "App quota exceeded."));
    }
    return internalError(messageOrDefault(failure, "Failed to start app."));
  }

  private static boolean isQuotaFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null
        && (message.startsWith("app data quota exceeded: ")
            || message.startsWith("app cache quota exceeded: ")
            || message.startsWith("app data quota scan incomplete: ")
            || message.startsWith("app cache quota scan incomplete: "));
  }

  /**
   * Maps uninstall-time AppHost contract failures onto stable client-facing status codes.
   *
   * <p>Concurrent uninstall or restart races are reclassified into the existing 404/409 contract
   * when the post-failure AppHost state is unambiguous. Other uninstall failures remain internal
   * server errors.
   *
   * @param appId normalized application identifier for the current request
   * @param failure AppHost contract failure thrown during uninstallation
   * @return structured Platform API exception
   */
  private PlatformApiException uninstallFailure(String appId, AppHostException failure) {
    if (appHost.status(appId).isPresent()) {
      return conflict("cannot uninstall a running app: " + appId);
    }
    if (!installed(appId)) {
      return appNotFound();
    }
    return internalError(messageOrDefault(failure, "Failed to uninstall app."));
  }

  /**
   * Returns the failure message when present, otherwise a caller-supplied fallback.
   *
   * @param failure failure that may or may not include a human-readable message
   * @param fallback fallback text for blank exception messages
   * @return non-blank message suitable for the API error response
   */
  private static String messageOrDefault(Throwable failure, String fallback) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? fallback : message;
  }

  /**
   * Creates the standard 500 error for unexpected AppHost failures.
   *
   * @param message operator-facing failure message
   * @return structured Platform API exception
   */
  private static PlatformApiException internalError(String message) {
    return new PlatformApiException(500, "internal_error", message);
  }
}
