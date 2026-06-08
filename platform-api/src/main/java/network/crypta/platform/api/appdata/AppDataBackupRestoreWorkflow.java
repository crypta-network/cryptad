package network.crypta.platform.api.appdata;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Operator backup and restore workflow for durable app-owned data.
 *
 * <p>This class owns the portable-backup envelope concerns that are not part of normal app-facing
 * app-data reads and writes: parsing operator backup options, assembling multi-app bundles,
 * decoding restore payloads, producing metadata-only restore previews, and building restore result
 * summaries. It delegates all store reads, writes, import projection, quota preflight, and
 * installed-app lookup to {@link AppDataService}, which remains the synchronized app-data mutation
 * boundary.
 *
 * <p>Serialized backup bundles may contain raw app-owned values by design. This workflow only
 * places those bytes in explicit backup responses or restore inputs; restore plans and results use
 * the metadata-only {@link AppDataRestorePlan} and {@link AppDataRestoreResult} shapes.
 */
final class AppDataBackupRestoreWorkflow {
  private static final String PARAM_APP_ID = "appId";
  private static final String PARAM_FORMAT = "format";
  private static final String PARAM_MODE = "mode";
  private static final String PARAM_PAYLOAD_BASE64 = "payloadBase64";
  private static final String PARAM_SCOPE = "scope";
  private static final String FIELD_BACKUP = "backup";
  private static final String FIELD_APPS = "apps";
  private static final String FIELD_EXPORT = "export";
  private static final String FIELD_PAYLOAD_BYTES = "payloadBytes";
  private static final String FIELD_RESTORE_PLAN = "restorePlan";
  private static final String FIELD_RESTORE_RESULT = "restoreResult";
  private static final String FIELD_SENSITIVE_USER_DATA = "sensitiveUserData";
  private static final String FORMAT_JSON = "json";
  private static final String SCOPE_ALL_SHORT = "all";
  private static final String SCOPE_SINGLE_SHORT = "single";
  private static final String STATUS_APP_ID_MISMATCH = "app_id_mismatch";
  private static final String STATUS_APP_NOT_INSTALLED_WARNING = "app_not_installed_warning";
  private static final String STATUS_INVALID_PAYLOAD = "invalid_payload";
  private static final String STATUS_MIGRATION_IN_PROGRESS = "app_data_migration_in_progress";
  private static final String STATUS_QUOTA_EXCEEDED = "quota_exceeded";
  private static final String STATUS_QUOTA_UNAVAILABLE = "app_data_quota_unavailable";
  private static final String STATUS_READY = "ready";
  private static final String STATUS_WOULD_MERGE = "would_merge";
  private static final String STATUS_WOULD_REPLACE_APP = "would_replace_app";
  private static final String STATUS_WOULD_REPLACE_NAMESPACES = "would_replace_namespaces";
  private static final String ERROR_IMPORT_APP_MISMATCH = "app_data_import_app_mismatch";
  private static final String ERROR_INVALID_QUERY_PARAMETER = "invalid_query_parameter";
  private static final String ERROR_QUOTA_EXCEEDED = "app_data_quota_exceeded";
  private static final String ERROR_RESTORE_APP_MISMATCH = "app_data_restore_app_mismatch";
  private static final String DIGEST_LENGTH_PLACEHOLDER = "0".repeat(64);

  private final AppDataService appDataService;

  /**
   * Creates a workflow backed by the synchronized app-data service.
   *
   * @param appDataService service that owns store mutation, quota preflight, and installed-app
   *     lookup
   */
  AppDataBackupRestoreWorkflow(AppDataService appDataService) {
    this.appDataService = Objects.requireNonNull(appDataService, "appDataService");
  }

  /**
   * Exports one app or all known app-data state as a portable backup response.
   *
   * @param parameters decoded operator route parameters
   * @param sourceCryptaVersion path-free daemon version label for the backup manifest
   * @return response envelope containing the sensitive backup object and URL-safe payload
   */
  Map<String, Object> exportBackup(
      Map<String, List<String>> parameters, String sourceCryptaVersion) {
    AppDataBackupOptions options = backupOptions(parameters, sourceCryptaVersion);
    AppDataBackupBundle bundle = createBackupBundle(options);
    byte[] payloadBytes = bundle.toJsonBytes();
    if (payloadBytes.length > appDataService.maxBackupExportBytes()) {
      throw backupTooLarge();
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put(FIELD_BACKUP, bundle.toJsonValue());
    json.put(PARAM_FORMAT, FORMAT_JSON);
    json.put(FIELD_PAYLOAD_BYTES, payloadBytes.length);
    json.put(
        PARAM_PAYLOAD_BASE64, Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBytes));
    json.put(FIELD_SENSITIVE_USER_DATA, true);
    return json;
  }

  /**
   * Builds a metadata-only restore plan without mutating durable app-data.
   *
   * @param parameters decoded operator route parameters containing a backup payload
   * @return response envelope containing a redacted restore plan
   */
  Map<String, Object> planRestore(Map<String, List<String>> parameters) {
    RestoreRequest request = restoreRequest(parameters);
    AppDataRestorePlan plan = restorePlan(request.bundle(), request.mode(), request.targetAppId());
    return envelope(FIELD_RESTORE_PLAN, plan.toJsonValue());
  }

  /**
   * Restores a portable app-data backup after repeating restore preflight.
   *
   * @param parameters decoded operator route parameters containing a backup payload and mode
   * @return response envelope containing a metadata-only restore result
   */
  Map<String, Object> restoreBackup(Map<String, List<String>> parameters) {
    RestoreRequest request = restoreRequest(parameters);
    AppDataRestorePlan plan = restorePlan(request.bundle(), request.mode(), request.targetAppId());
    if (!plan.ready()) {
      return envelope(FIELD_RESTORE_RESULT, blockedRestoreResult(plan).toJsonValue());
    }
    ArrayList<AppDataRestoreResult.AppResult> appResults = new ArrayList<>();
    for (int index = 0; index < request.bundle().apps().size(); index++) {
      AppDataBackupEntry entry = request.bundle().apps().get(index);
      AppDataRestorePlan.AppPlan appPlan = plan.apps().get(index);
      appDataService.commitRestorePayload(
          entry.appId(),
          entry.export(),
          importMode(request.mode()),
          replacesWholeApp(request.mode()));
      appResults.add(restoredAppResult(entry, appPlan, request.mode()));
    }
    AppDataRestoreResult result =
        new AppDataRestoreResult(
            true,
            AppDataRestoreResult.STATUS_RESTORED,
            request.mode(),
            request.bundle().manifest().scope(),
            request.bundle().apps().size(),
            request.bundle().apps().stream().mapToInt(AppDataBackupEntry::recordCount).sum(),
            request.bundle().apps().stream().mapToLong(AppDataBackupEntry::totalBytes).sum(),
            appResults);
    return envelope(FIELD_RESTORE_RESULT, result.toJsonValue());
  }

  private AppDataBackupOptions backupOptions(
      Map<String, List<String>> parameters, String sourceCryptaVersion) {
    String appId = PlatformApiParameters.readOptionalString(parameters, PARAM_APP_ID);
    String scope = PlatformApiParameters.readOptionalString(parameters, PARAM_SCOPE);
    if (appId != null) {
      if (scope != null
          && !scope.equals(AppDataBackupOptions.SCOPE_SINGLE_APP)
          && !scope.equals(SCOPE_SINGLE_SHORT)) {
        throw new PlatformApiException(
            400,
            ERROR_INVALID_QUERY_PARAMETER,
            "Single-app app-data backup must not request all-app scope.");
      }
      return AppDataBackupOptions.singleApp(appId, sourceCryptaVersion);
    }
    if (SCOPE_ALL_SHORT.equals(scope) || AppDataBackupOptions.SCOPE_ALL_APPS.equals(scope)) {
      return AppDataBackupOptions.allApps(sourceCryptaVersion);
    }
    throw new PlatformApiException(
        400, ERROR_INVALID_QUERY_PARAMETER, "App-data backup requires appId or scope=all.");
  }

  private AppDataBackupBundle createBackupBundle(AppDataBackupOptions options) {
    Instant createdAt = appDataService.currentBackupInstant();
    AppDataBackupManifest manifest =
        AppDataBackupManifest.create(options.scope(), createdAt, options.sourceCryptaVersion());
    BackupBundleSizeBudget sizeBudget =
        new BackupBundleSizeBudget(manifest, appDataService.maxBackupExportBytes());
    List<String> appIds =
        AppDataBackupOptions.SCOPE_SINGLE_APP.equals(options.scope())
            ? List.of(options.appId())
            : appDataService.listStoreAppIds();
    ArrayList<AppDataBackupEntry> entries = new ArrayList<>();
    for (String appId : appIds) {
      BackupEntryProjection projection = backupEntryProjection(appId, createdAt);
      sizeBudget.requireProjectedEntryFits(projection.projectedJsonBytes());
      AppDataBackupEntry entry = createBackupEntry(projection);
      sizeBudget.addActualEntry(entry);
      entries.add(entry);
    }
    return new AppDataBackupBundle(manifest, entries);
  }

  private BackupEntryProjection backupEntryProjection(String appId, Instant exportedAt) {
    AppDataService.ExportProjection exportProjection =
        appDataService.exportProjection(AppDataRecord.normalizeAppId(appId), exportedAt);
    InstalledAppSnapshot installed =
        appDataService.installedAppForBackup(exportProjection.appId()).orElse(null);
    String appName = installed == null ? null : installed.manifest().appName();
    String appVersion = installed == null ? null : installed.manifest().appVersion();
    Map<String, Object> schemaSummary = AppDataBackupMetadata.schemaSummary(installed);
    long projectedJsonBytes =
        projectedBackupEntryBytes(
            exportProjection, installed != null, appName, appVersion, schemaSummary);
    return new BackupEntryProjection(
        exportProjection,
        installed != null,
        appName,
        appVersion,
        schemaSummary,
        projectedJsonBytes);
  }

  private AppDataBackupEntry createBackupEntry(BackupEntryProjection projection) {
    AppDataService.ExportProjection exportProjection = projection.exportProjection();
    AppDataExportPayload export = appDataService.exportPayload(exportProjection);
    return AppDataBackupEntry.fromExport(
        exportProjection.appId(),
        projection.installed(),
        projection.appName(),
        projection.appVersion(),
        projection.schemaSummary(),
        export);
  }

  private static long projectedBackupEntryBytes(
      AppDataService.ExportProjection projection,
      boolean installed,
      String appName,
      String appVersion,
      Map<String, Object> schemaSummary) {
    Map<String, Object> exportJson = projectedExportJson(projection);
    long emptyExportBytes = utf8Length(PlatformApiJsonWriter.write(exportJson));
    LinkedHashMap<String, Object> entryJson = LinkedHashMap.newLinkedHashMap(10);
    entryJson.put(PARAM_APP_ID, projection.appId());
    entryJson.put("installed", installed);
    entryJson.put("appName", appName);
    entryJson.put("appVersion", appVersion);
    entryJson.put("schemaSummary", schemaSummary);
    entryJson.put("namespaceCount", projection.namespaceCount());
    entryJson.put("recordCount", projection.recordCount());
    entryJson.put("totalBytes", projection.totalBytes());
    entryJson.put("payloadSha256", DIGEST_LENGTH_PLACEHOLDER);
    entryJson.put(FIELD_EXPORT, exportJson);
    return utf8Length(PlatformApiJsonWriter.write(entryJson))
        - emptyExportBytes
        + projection.projectedBytes();
  }

  private static Map<String, Object> projectedExportJson(
      AppDataService.ExportProjection projection) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("exportVersion", AppDataExportPayload.CURRENT_EXPORT_VERSION);
    json.put(PARAM_APP_ID, projection.appId());
    json.put("exportedAt", projection.exportedAt().toString());
    json.put("namespaceCount", projection.namespaceCount());
    json.put("recordCount", projection.recordCount());
    json.put(
        "namespaces",
        projection.namespaces().stream().map(namespace -> namespace.toJsonValue(true)).toList());
    json.put("records", List.of());
    return json;
  }

  private RestoreRequest restoreRequest(Map<String, List<String>> parameters) {
    byte[] payloadBytes = decodeBackupPayloadBase64(parameters);
    if (payloadBytes.length > appDataService.maxBackupImportBytes()) {
      throw backupTooLarge();
    }
    AppDataRestoreMode mode =
        AppDataRestoreMode.parse(PlatformApiParameters.readOptionalString(parameters, PARAM_MODE));
    AppDataBackupBundle bundle = AppDataBackupBundle.parse(payloadBytes);
    String targetAppId = PlatformApiParameters.readOptionalString(parameters, PARAM_APP_ID);
    if (targetAppId != null) {
      targetAppId = AppDataRecord.normalizeAppId(targetAppId);
      if (bundle.apps().size() != 1 || !targetAppId.equals(bundle.apps().getFirst().appId())) {
        throw new PlatformApiException(
            400,
            ERROR_RESTORE_APP_MISMATCH,
            "App-data restore target must match the backup app id.");
      }
    }
    return new RestoreRequest(bundle, mode, targetAppId);
  }

  private AppDataRestorePlan restorePlan(
      AppDataBackupBundle bundle, AppDataRestoreMode mode, String targetAppId) {
    ArrayList<AppDataRestorePlan.AppPlan> appPlans = new ArrayList<>();
    boolean blocked = false;
    for (AppDataBackupEntry entry : bundle.apps()) {
      AppDataRestorePlan.AppPlan appPlan = restoreAppPlan(entry, mode, targetAppId);
      blocked = blocked || !appPlan.blockers().isEmpty();
      appPlans.add(appPlan);
    }
    return new AppDataRestorePlan(
        blocked ? AppDataRestorePlan.STATUS_BLOCKED : AppDataRestorePlan.STATUS_READY,
        mode,
        bundle.manifest().scope(),
        bundle.manifest().backupVersion(),
        bundle.apps().size(),
        bundle.apps().stream().mapToInt(AppDataBackupEntry::recordCount).sum(),
        bundle.apps().stream().mapToLong(AppDataBackupEntry::totalBytes).sum(),
        appPlans);
  }

  private AppDataRestorePlan.AppPlan restoreAppPlan(
      AppDataBackupEntry entry, AppDataRestoreMode mode, String targetAppId) {
    ArrayList<String> statuses = new ArrayList<>();
    ArrayList<String> warnings = new ArrayList<>();
    ArrayList<String> blockers = new ArrayList<>();
    statuses.add(modeStatus(mode));
    if (targetAppId != null && !targetAppId.equals(entry.appId())) {
      blockers.add(STATUS_APP_ID_MISMATCH);
    }
    InstalledAppSnapshot installed =
        appDataService.installedAppForBackup(entry.appId()).orElse(null);
    if (installed == null) {
      warnings.add(STATUS_APP_NOT_INSTALLED_WARNING);
      statuses.add(AppDataBackupMetadata.STATUS_SCHEMA_WARNING);
    } else {
      statuses.add(AppDataBackupMetadata.schemaCompatibilityStatus(installed, entry));
    }
    try {
      appDataService.preflightRestorePayload(
          entry.appId(), entry.export(), importMode(mode), replacesWholeApp(mode));
    } catch (PlatformApiException exception) {
      blockers.add(restoreBlocker(exception));
    }
    statuses.add(blockers.isEmpty() ? STATUS_READY : AppDataRestorePlan.STATUS_BLOCKED);
    return new AppDataRestorePlan.AppPlan(
        entry.appId(),
        installed != null,
        installed == null ? null : installed.manifest().appName(),
        installed == null ? null : installed.manifest().appVersion(),
        blockers.isEmpty() ? STATUS_READY : AppDataRestorePlan.STATUS_BLOCKED,
        statuses,
        warnings,
        blockers,
        entry.namespaceCount(),
        entry.recordCount(),
        entry.totalBytes(),
        appDataService.conflictCount(entry.appId(), entry.export()),
        entry.namespaceSummaries());
  }

  private AppDataRestoreResult.AppResult restoredAppResult(
      AppDataBackupEntry entry, AppDataRestorePlan.AppPlan appPlan, AppDataRestoreMode mode) {
    return new AppDataRestoreResult.AppResult(
        entry.appId(),
        appPlan.installed(),
        true,
        AppDataRestoreResult.STATUS_RESTORED,
        List.of(STATUS_READY, modeStatus(mode)),
        appPlan.warnings(),
        List.of(),
        entry.namespaceCount(),
        entry.recordCount(),
        entry.totalBytes());
  }

  private AppDataRestoreResult blockedRestoreResult(AppDataRestorePlan plan) {
    List<AppDataRestoreResult.AppResult> appResults =
        plan.apps().stream()
            .map(
                appPlan ->
                    new AppDataRestoreResult.AppResult(
                        appPlan.appId(),
                        appPlan.installed(),
                        false,
                        AppDataRestoreResult.STATUS_BLOCKED,
                        appPlan.statuses(),
                        appPlan.warnings(),
                        appPlan.blockers(),
                        appPlan.namespaceCount(),
                        appPlan.recordCount(),
                        appPlan.totalBytes()))
            .toList();
    return new AppDataRestoreResult(
        false,
        AppDataRestoreResult.STATUS_BLOCKED,
        plan.mode(),
        plan.scope(),
        plan.appCount(),
        plan.recordCount(),
        plan.totalBytes(),
        appResults);
  }

  private static String importMode(AppDataRestoreMode mode) {
    return mode == AppDataRestoreMode.REPLACE_NAMESPACE
        ? AppDataRestoreMode.REPLACE_NAMESPACE.apiValue()
        : AppDataRestoreMode.MERGE.apiValue();
  }

  private static boolean replacesWholeApp(AppDataRestoreMode mode) {
    return mode == AppDataRestoreMode.REPLACE_APP;
  }

  private static String modeStatus(AppDataRestoreMode mode) {
    return switch (mode) {
      case MERGE -> STATUS_WOULD_MERGE;
      case REPLACE_NAMESPACE -> STATUS_WOULD_REPLACE_NAMESPACES;
      case REPLACE_APP -> STATUS_WOULD_REPLACE_APP;
    };
  }

  private static String restoreBlocker(PlatformApiException exception) {
    return switch (exception.errorCode()) {
      case ERROR_QUOTA_EXCEEDED -> STATUS_QUOTA_EXCEEDED;
      case STATUS_QUOTA_UNAVAILABLE -> STATUS_QUOTA_UNAVAILABLE;
      case ERROR_IMPORT_APP_MISMATCH, ERROR_RESTORE_APP_MISMATCH -> STATUS_APP_ID_MISMATCH;
      case STATUS_MIGRATION_IN_PROGRESS -> STATUS_MIGRATION_IN_PROGRESS;
      default -> STATUS_INVALID_PAYLOAD;
    };
  }

  private static byte[] decodeBackupPayloadBase64(Map<String, List<String>> parameters) {
    String value = PlatformApiParameters.requireString(parameters, PARAM_PAYLOAD_BASE64);
    try {
      return Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException _) {
      try {
        return Base64.getUrlDecoder().decode(value);
      } catch (IllegalArgumentException _) {
        throw AppDataBackupManifest.invalidBackupPayload();
      }
    }
  }

  private static PlatformApiException backupTooLarge() {
    return new PlatformApiException(
        400, "app_data_backup_too_large", "App-data backup payload exceeds the configured limit.");
  }

  private static long utf8Length(String value) {
    return value.getBytes(StandardCharsets.UTF_8).length;
  }

  private static Map<String, Object> envelope(String key, Object value) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put(key, value);
    return envelope;
  }

  private record RestoreRequest(
      AppDataBackupBundle bundle, AppDataRestoreMode mode, String targetAppId) {}

  private record BackupEntryProjection(
      AppDataService.ExportProjection exportProjection,
      boolean installed,
      String appName,
      String appVersion,
      Map<String, Object> schemaSummary,
      long projectedJsonBytes) {}

  private static final class BackupBundleSizeBudget {
    private final long emptyBundleBytes;
    private final long maxBytes;
    private long entryBytes;
    private int entryCount;

    private BackupBundleSizeBudget(AppDataBackupManifest manifest, long maxBytes) {
      LinkedHashMap<String, Object> emptyBundle = new LinkedHashMap<>(manifest.toJsonValue());
      emptyBundle.put(FIELD_APPS, List.of());
      emptyBundleBytes = utf8Length(PlatformApiJsonWriter.write(emptyBundle));
      this.maxBytes = maxBytes;
    }

    private void requireProjectedEntryFits(long projectedEntryBytes) {
      requireBundleFits(entryBytes + projectedEntryBytes, entryCount + 1);
    }

    private void addActualEntry(AppDataBackupEntry entry) {
      entryBytes += utf8Length(PlatformApiJsonWriter.write(entry.toJsonValue()));
      entryCount++;
      requireBundleFits(entryBytes, entryCount);
    }

    private void requireBundleFits(long candidateEntryBytes, int candidateEntryCount) {
      long separatorBytes = Math.max(0L, candidateEntryCount - 1L);
      if (emptyBundleBytes + candidateEntryBytes + separatorBytes > maxBytes) {
        throw backupTooLarge();
      }
    }
  }
}
