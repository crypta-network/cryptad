package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppQuotaWarning;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Synchronized service for bounded app-scoped durable records.
 *
 * <p>The service is the policy layer above {@link AppDataStore}. It validates app/namespace/key
 * identifiers, parses form/query parameters, enforces record, count, import/export, and
 * manifest-aware data quota limits, and converts store failures into path-free Platform API errors.
 * All public methods scope operations to the app id supplied by the authenticated principal; no app
 * id is ever accepted from request parameters.
 *
 * <p>Instances are intended to be shared by the Platform API router for one daemon runtime. Public
 * methods are synchronized because file-backed app-data writes, import preflight, and namespace
 * metadata updates must observe a consistent store view. The synchronization does not make the
 * underlying filesystem a database; it provides a simple local consistency boundary for bounded
 * app-owned state.
 *
 * <p>The service enforces two quota layers. Store-level limits from {@link AppDataStoreConfig}
 * always apply, even when a manifest omits {@code quota.data.bytes} or sets it to zero. When an
 * installed app has a positive manifest data quota, writes and imports also preflight app data
 * usage through {@link AppDiskUsageScanner}; host-managed durable-store bytes are added separately
 * when the store is outside the app-visible data directory.
 *
 * <p>Errors intentionally use stable Platform API codes and sanitized messages. Store roots,
 * installed app paths, staging paths, raw request bodies, record values, private insert URIs, and
 * secret material are never included in responses produced by this layer.
 */
public final class AppDataService {
  /**
   * Manifest permission that allows app principals to read their own durable app data.
   *
   * <p>Routes guarded by this capability can return metadata, one-record values, and bounded export
   * payloads for the authenticated app only.
   */
  public static final String CAPABILITY_APP_DATA_READ = "app.data.read";

  /**
   * Manifest permission that allows app principals to write their own durable app data.
   *
   * <p>Routes guarded by this capability can create, replace, delete, import, or clear records
   * within the authenticated app scope. It does not grant access to another app's store.
   */
  public static final String CAPABILITY_APP_DATA_WRITE = "app.data.write";

  private static final String PARAM_NAMESPACE = "namespace";
  private static final String PARAM_KEY = "key";
  private static final String PARAM_CONTENT_TYPE = "contentType";
  private static final String PARAM_SCHEMA_VERSION = "schemaVersion";
  private static final String PARAM_VALUE_BASE64 = "valueBase64";
  private static final String PARAM_VALUE_TEXT = "valueText";
  private static final String PARAM_VALUE_JSON = "valueJson";
  private static final String PARAM_IF_MATCH_SHA_256 = "ifMatchSha256";
  private static final String PARAM_LIMIT = "limit";
  private static final String PARAM_CURSOR = "cursor";
  private static final String PARAM_FORMAT = "format";
  private static final String PARAM_PAYLOAD_BASE64 = "payloadBase64";
  private static final String PARAM_MODE = "mode";
  private static final String PARAM_APP_ID = "appId";
  private static final String FIELD_NAMESPACE_COUNT = "namespaceCount";
  private static final String FIELD_PAYLOAD_BYTES = "payloadBytes";
  private static final String FIELD_RECORD_COUNT = "recordCount";
  private static final String STATUS_QUOTA_UNAVAILABLE = "app_data_quota_unavailable";
  private static final String IMPORT_MODE_MERGE = "merge";
  private static final String IMPORT_MODE_REPLACE_NAMESPACE = "replaceNamespace";
  private static final long RECORD_METADATA_QUOTA_RESERVE_BYTES = 2_048L;
  private static final long NAMESPACE_METADATA_QUOTA_RESERVE_BYTES = 8_192L;
  private static final long MIGRATION_METADATA_QUOTA_RESERVE_BYTES = 512L;

  private final AppDataStore store;
  private final AppHost appHost;
  private final AppDataStoreConfig config;
  private final Clock clock;
  private final AppDiskUsageScanner diskUsageScanner;
  private final boolean storeUsageOutsideAppDataDir;
  private final AppDataBackupRestoreWorkflow backupRestoreWorkflow;
  private final Map<String, Integer> updateMigrationWriteBarriers = new LinkedHashMap<>();

  /**
   * Creates a service using system UTC time and the default quota scanner.
   *
   * <p>This constructor is suitable when the store root is already counted by the installed app's
   * data-directory scan, such as an implementation placed directly under AppHost-managed app data.
   *
   * @param store durable app-data store used for all app-scoped records
   * @param appHost optional AppHost used to find installed manifests and manifest data quotas
   * @param config positive app-data store limits enforced before writes and imports
   */
  public AppDataService(AppDataStore store, AppHost appHost, AppDataStoreConfig config) {
    this(store, appHost, config, false);
  }

  /**
   * Creates a service using system UTC time and the default quota scanner.
   *
   * <p>Use this constructor when runtime composition decides whether durable-store usage is already
   * visible to AppHost quota scanning. The HTTP bridge passes {@code true} for the host-managed
   * durable-store root so manifest quota accounting includes both app-visible data and daemon-owned
   * durable records.
   *
   * @param store durable app-data store used for all app-scoped records
   * @param appHost optional AppHost used to find installed manifests and manifest data quotas
   * @param config positive app-data store limits enforced before writes and imports
   * @param storeUsageOutsideAppDataDir whether the store root is outside the app-visible data
   *     directory and must be added to manifest data-quota accounting separately
   */
  public AppDataService(
      AppDataStore store,
      AppHost appHost,
      AppDataStoreConfig config,
      boolean storeUsageOutsideAppDataDir) {
    this(
        store,
        appHost,
        config,
        Clock.systemUTC(),
        new AppDiskUsageScanner(),
        storeUsageOutsideAppDataDir);
  }

  /**
   * Creates a service with explicit time and quota scanner dependencies.
   *
   * <p>Tests use this constructor to supply deterministic timestamps and quota-scan results. The
   * store is treated as already included in AppHost data usage unless the six-argument constructor
   * is used.
   *
   * @param store durable app-data store used for all app-scoped records
   * @param appHost optional AppHost used to find installed manifests and manifest data quotas
   * @param config positive app-data store limits enforced before writes and imports
   * @param clock timestamp source for records, deletes, exports, and migrations
   * @param diskUsageScanner scanner used for manifest quota preflight
   */
  public AppDataService(
      AppDataStore store,
      AppHost appHost,
      AppDataStoreConfig config,
      Clock clock,
      AppDiskUsageScanner diskUsageScanner) {
    this(store, appHost, config, clock, diskUsageScanner, false);
  }

  /**
   * Creates a service with explicit time, quota scanner, and store placement dependencies.
   *
   * <p>This is the full dependency-injection constructor used by focused tests and runtime wiring.
   * It performs no I/O at construction time; store availability is checked when a route invokes a
   * read or write operation.
   *
   * @param store durable app-data store used for all app-scoped records
   * @param appHost optional AppHost used to find installed manifests and manifest data quotas
   * @param config positive app-data store limits enforced before writes and imports
   * @param clock timestamp source for records, deletes, exports, and migrations
   * @param diskUsageScanner scanner used for manifest quota preflight
   * @param storeUsageOutsideAppDataDir whether the store root is outside the app-visible data
   *     directory and must be added to manifest data-quota accounting separately
   * @throws NullPointerException if store, config, clock, or diskUsageScanner is {@code null}
   */
  public AppDataService(
      AppDataStore store,
      AppHost appHost,
      AppDataStoreConfig config,
      Clock clock,
      AppDiskUsageScanner diskUsageScanner,
      boolean storeUsageOutsideAppDataDir) {
    this.store = Objects.requireNonNull(store, "store");
    this.appHost = appHost;
    this.config = Objects.requireNonNull(config, "config");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.diskUsageScanner = Objects.requireNonNull(diskUsageScanner, "diskUsageScanner");
    this.storeUsageOutsideAppDataDir = storeUsageOutsideAppDataDir;
    backupRestoreWorkflow = new AppDataBackupRestoreWorkflow(this);
  }

  /**
   * Returns path-free status for the calling app's durable data.
   *
   * <p>Status is a summary endpoint. It reports namespace count, record count, total stored value
   * bytes, configured limits, manifest quota state, and sanitized quota warnings. It does not read
   * or return record values.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @return status map with counts, byte totals, limits, quota state, and sanitized warnings
   */
  public synchronized Map<String, Object> status(String appId) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    List<AppDataNamespaceMetadata> namespaces = listNamespaceMetadata(normalizedAppId);
    List<AppDataRecordSummary> records = listStoredRecordSummaries(normalizedAppId, null);
    long totalBytes = records.stream().mapToLong(AppDataRecordSummary::valueBytes).sum();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put(PARAM_APP_ID, normalizedAppId);
    json.put(FIELD_RECORD_COUNT, records.size());
    json.put(FIELD_NAMESPACE_COUNT, namespaces.size());
    json.put("totalBytes", totalBytes);
    json.put("limits", limitsJson());
    json.put("quota", quotaJson(normalizedAppId));
    json.put("warnings", quotaWarnings(normalizedAppId));
    json.put("storeAvailable", true);
    return json;
  }

  /**
   * Lists namespace metadata for the calling app.
   *
   * <p>The list form omits migration history to keep summary responses compact. Use {@link
   * #getNamespace(String, String)} when an app needs the bounded migration history for one
   * namespace.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @return path-free namespace metadata summaries sorted by the store implementation
   */
  public synchronized List<Map<String, Object>> listNamespaces(String appId) {
    return listNamespaceMetadata(appId).stream()
        .map(namespace -> namespace.toJsonValue(false))
        .toList();
  }

  /**
   * Reads one namespace metadata record for the calling app.
   *
   * <p>The namespace is normalized before lookup, and missing metadata is reported with {@code
   * app_data_namespace_not_found}. The response includes migration history because this endpoint is
   * the app-facing source of schema transition metadata.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param namespace route namespace supplied by the app
   * @return path-free namespace metadata with bounded migration history
   */
  public synchronized Map<String, Object> getNamespace(String appId, String namespace) {
    return readNamespaceRequired(appId, namespace).toJsonValue(true);
  }

  /**
   * Records a namespace schema migration/update for the calling app.
   *
   * <p>The platform records schema metadata only. It validates {@code fromSchemaVersion}, {@code
   * toSchemaVersion}, and the current namespace version, then appends a bounded migration record.
   * It does not inspect or transform app record values; apps must update their own records using
   * normal record writes.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param namespace route namespace supplied by the app
   * @param parameters decoded form parameters containing schema versions and optional summary
   * @return updated namespace metadata including bounded migration history
   */
  public synchronized Map<String, Object> updateSchema(
      String appId, String namespace, Map<String, List<String>> parameters) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    rejectIfUpdateMigrationWriteBarrierActive(normalizedAppId);
    return updateSchemaInternal(normalizedAppId, normalizedNamespace, parameters);
  }

  private Map<String, Object> updateSchemaInternal(
      String normalizedAppId, String normalizedNamespace, Map<String, List<String>> parameters) {
    int fromVersion = readRequiredPositiveInt(parameters, "fromSchemaVersion");
    int toVersion = readRequiredPositiveInt(parameters, "toSchemaVersion");
    String summary = PlatformApiParameters.readOptionalString(parameters, "summary");
    if (toVersion < fromVersion) {
      throw new PlatformApiException(
          400, "invalid_app_data_schema", "App-data schema downgrades are not supported.");
    }
    Instant now = clock.instant();
    Optional<AppDataNamespaceMetadata> existingNamespace =
        readNamespaceOptional(normalizedAppId, normalizedNamespace);
    AppDataNamespaceMetadata current =
        existingNamespace.orElseGet(
            () ->
                new AppDataNamespaceMetadata(
                    normalizedAppId,
                    normalizedNamespace,
                    fromVersion,
                    0,
                    0L,
                    now,
                    now,
                    null,
                    List.of()));
    if (current.schemaVersion() != fromVersion) {
      throw new PlatformApiException(
          409,
          "app_data_schema_conflict",
          "Namespace schema version does not match the migration precondition.");
    }
    ensureNamespaceLimitForWrite(normalizedAppId, normalizedNamespace);
    AppDataMigrationRecord migration =
        new AppDataMigrationRecord(fromVersion, toVersion, summary, now);
    AppDataNamespaceMetadata updated =
        current.withMigration(migration, config.maxMigrationHistory());
    long metadataDelta =
        existingNamespace.isPresent()
            ? positiveNamespaceMetadataDelta(current, updated)
            : namespaceMetadataQuotaReserve(updated);
    enforceManifestQuota(normalizedAppId, metadataDelta);
    writeNamespace(updated);
    return readNamespaceRequired(normalizedAppId, normalizedNamespace).toJsonValue(true);
  }

  /**
   * Deletes all records and metadata for one app-owned namespace.
   *
   * <p>The deletion is scoped to the authenticated app id and returns the pre-delete namespace
   * metadata with a {@code deleted} marker. Missing namespaces are reported before the store delete
   * is attempted.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param namespace route namespace supplied by the app
   * @return deleted namespace summary without migration history
   */
  public synchronized Map<String, Object> deleteNamespace(String appId, String namespace) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    rejectIfUpdateMigrationWriteBarrierActive(normalizedAppId);
    AppDataNamespaceMetadata existing = readNamespaceRequired(normalizedAppId, normalizedNamespace);
    try {
      store.deleteNamespace(normalizedAppId, normalizedNamespace);
    } catch (IOException _) {
      throw storeUnavailable();
    }
    LinkedHashMap<String, Object> json = new LinkedHashMap<>(existing.toJsonValue(false));
    json.put("deleted", true);
    return json;
  }

  /**
   * Lists bounded record summaries for the calling app.
   *
   * <p>This endpoint is metadata-only. It supports optional namespace filtering plus cursor/limit
   * pagination, and it never returns raw values. The implementation uses store summaries so
   * permitted apps cannot force value-file reads through a list route.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param parameters decoded query parameters such as namespace, limit, and cursor
   * @return paged record summary response with optional next cursor
   */
  public synchronized Map<String, Object> listRecords(
      String appId, Map<String, List<String>> parameters) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String namespace = PlatformApiParameters.readOptionalString(parameters, PARAM_NAMESPACE);
    String normalizedNamespace =
        namespace == null ? null : AppDataRecord.normalizeNamespace(namespace);
    int limit = readLimit(parameters);
    int cursor = readCursor(parameters);
    List<AppDataRecordSummary> summaries =
        listStoredRecordSummaries(normalizedAppId, normalizedNamespace);
    int fromIndex = Math.min(cursor, summaries.size());
    int toIndex = Math.min(fromIndex + limit, summaries.size());
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put(
        "records",
        summaries.subList(fromIndex, toIndex).stream()
            .map(AppDataRecordSummary::toJsonValue)
            .toList());
    json.put("nextCursor", toIndex < summaries.size() ? Integer.toString(toIndex) : null);
    json.put(PARAM_LIMIT, limit);
    json.put("totalRecords", summaries.size());
    return json;
  }

  /**
   * Reads one record for the calling app.
   *
   * <p>Record reads are the app-data route that may return a stored value. The value remains scoped
   * to the authenticated app, and the store validates metadata, length, and digest before returning
   * file-backed bytes.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param namespace route namespace supplied by the app
   * @param key route key supplied by the app
   * @return metadata plus bounded value for the owning app
   */
  public synchronized Map<String, Object> getRecord(String appId, String namespace, String key) {
    return readRecordRequired(appId, namespace, key).toReadJson();
  }

  /**
   * Creates or replaces one app-owned record.
   *
   * <p>The request must supply exactly one of {@code valueBase64}, {@code valueText}, or {@code
   * valueJson}. The service enforces per-record bytes, record count, namespace count, total stored
   * value bytes, manifest data quota when available, and an optional {@code ifMatchSha256}
   * precondition before committing the record through the store.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param parameters decoded form parameters for namespace, key, schema, content type, and value
   * @return metadata plus bounded value for the stored record
   */
  public synchronized Map<String, Object> putRecord(
      String appId, Map<String, List<String>> parameters) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    rejectIfUpdateMigrationWriteBarrierActive(normalizedAppId);
    String namespace =
        AppDataRecord.normalizeNamespace(
            PlatformApiParameters.requireString(parameters, PARAM_NAMESPACE));
    String key =
        AppDataRecord.normalizeKey(PlatformApiParameters.requireString(parameters, PARAM_KEY));
    int schemaVersion = readRequiredPositiveInt(parameters, PARAM_SCHEMA_VERSION);
    ValueInput valueInput = valueInput(parameters);
    if (valueInput.value().length > config.maxRecordBytes()) {
      throw new PlatformApiException(
          400, "app_data_record_too_large", "App-data record exceeds the per-record limit.");
    }
    Optional<AppDataRecord> existing = readRecordOptional(normalizedAppId, namespace, key);
    String ifMatchSha256 =
        PlatformApiParameters.readOptionalString(parameters, PARAM_IF_MATCH_SHA_256);
    if (ifMatchSha256 != null
        && existing.map(AppDataRecord::sha256).filter(ifMatchSha256::equals).isEmpty()) {
      throw new PlatformApiException(
          409, "app_data_write_conflict", "App-data record precondition failed.");
    }
    enforceWriteQuotas(
        normalizedAppId, namespace, existing.orElse(null), valueInput.value().length);
    Instant now = clock.instant();
    AppDataRecord appDataRecord =
        new AppDataRecord(
            normalizedAppId,
            namespace,
            key,
            new AppDataRecord.Payload(valueInput.contentType(), schemaVersion, valueInput.value()),
            existing.map(AppDataRecord::createdAt).orElse(now),
            now);
    ensureNamespaceForRecord(appDataRecord);
    writeRecord(appDataRecord);
    return readRecordRequired(normalizedAppId, namespace, key).toReadJson();
  }

  /**
   * Deletes one app-owned record.
   *
   * <p>The service reads the record first so the response can return the deleted record summary and
   * namespace metadata can be timestamped after a successful delete. The response does not include
   * the deleted value.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param namespace route namespace supplied by the app
   * @param key route key supplied by the app
   * @return deleted record summary with a {@code deleted} marker
   */
  public synchronized Map<String, Object> deleteRecord(String appId, String namespace, String key) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    rejectIfUpdateMigrationWriteBarrierActive(normalizedAppId);
    AppDataRecord existing = readRecordRequired(normalizedAppId, namespace, key);
    Optional<AppDataNamespaceMetadata> namespaceBeforeDelete =
        readNamespaceOptional(existing.appId(), existing.namespace());
    boolean deleted;
    try {
      deleted = store.deleteRecord(existing.appId(), existing.namespace(), existing.key());
    } catch (IOException _) {
      throw storeUnavailable();
    }
    if (deleted && namespaceBeforeDelete.isPresent()) {
      AppDataNamespaceMetadata metadata = namespaceBeforeDelete.get();
      writeNamespace(
          metadata.withTotals(
              Math.max(0, metadata.recordCount() - 1),
              Math.max(0L, metadata.totalBytes() - existing.valueBytes()),
              clock.instant()));
    }
    LinkedHashMap<String, Object> json = new LinkedHashMap<>(existing.toSummaryJson());
    json.put("deleted", true);
    return json;
  }

  /**
   * Exports bounded app-owned data.
   *
   * <p>The service first projects the serialized export size from metadata and summaries before it
   * reads record values. That keeps oversized exports from materializing a large payload in memory.
   * The response includes the structured JSON-compatible fields plus a URL-safe {@code
   * payloadBase64} representation intended for the import route.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param parameters decoded query parameters such as namespace and format
   * @return export payload and metadata for the authenticated app
   */
  public synchronized Map<String, Object> exportData(
      String appId, Map<String, List<String>> parameters) {
    String format = PlatformApiParameters.readOptionalString(parameters, PARAM_FORMAT);
    if (format != null && !format.equals("json")) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "App-data export format must be json.");
    }
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String namespace = PlatformApiParameters.readOptionalString(parameters, PARAM_NAMESPACE);
    String normalizedNamespace =
        namespace == null ? null : AppDataRecord.normalizeNamespace(namespace);
    List<AppDataRecordSummary> summaries =
        listStoredRecordSummaries(normalizedAppId, normalizedNamespace);
    List<AppDataNamespaceMetadata> namespaces =
        normalizedNamespace == null
            ? listNamespaceMetadata(normalizedAppId)
            : readNamespaceOptional(normalizedAppId, normalizedNamespace).stream().toList();
    Instant exportedAt = clock.instant();
    enforceExportLimit(normalizedAppId, exportedAt, namespaces, summaries);
    List<AppDataRecord> records = listStoredRecords(normalizedAppId, normalizedNamespace);
    AppDataExportPayload payload =
        new AppDataExportPayload(
            AppDataExportPayload.CURRENT_EXPORT_VERSION,
            normalizedAppId,
            exportedAt,
            namespaces,
            records);
    byte[] payloadBytes = payload.toJsonBytes();
    if (payloadBytes.length > config.maxExportBytes()) {
      throw new PlatformApiException(
          400, "app_data_export_too_large", "App-data export exceeds the configured limit.");
    }
    LinkedHashMap<String, Object> json = new LinkedHashMap<>(payload.toJsonValue());
    json.put(PARAM_FORMAT, "json");
    json.put(FIELD_PAYLOAD_BYTES, payloadBytes.length);
    json.put(
        PARAM_PAYLOAD_BASE64, Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBytes));
    return json;
  }

  /**
   * Imports bounded app-owned data from an export payload.
   *
   * <p>Imports accept the URL-safe or standard base64 form of an {@link AppDataExportPayload}.
   * Payloads that name another app are rejected. Before committing, the service validates record
   * sizes, namespace and record counts, total stored value bytes, migration-history limits, and
   * manifest data quota. {@code merge} writes imported records over matching keys; {@code
   * replaceNamespace} replaces only the namespaces named by the import payload.
   *
   * @param appId app principal id supplied by the authenticated Platform API principal
   * @param parameters decoded form parameters containing payloadBase64 and optional mode
   * @return import summary with mode, namespace count, record count, and payload size
   */
  public synchronized Map<String, Object> importData(
      String appId, Map<String, List<String>> parameters) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    rejectIfUpdateMigrationWriteBarrierActive(normalizedAppId);
    byte[] payloadBytes = decodeRequiredPayloadBase64(parameters);
    if (payloadBytes.length > config.maxImportBytes()) {
      throw new PlatformApiException(
          400, "app_data_import_too_large", "App-data import exceeds the configured limit.");
    }
    String mode =
        Optional.ofNullable(PlatformApiParameters.readOptionalString(parameters, PARAM_MODE))
            .orElse(IMPORT_MODE_MERGE);
    if (!mode.equals(IMPORT_MODE_MERGE) && !mode.equals(IMPORT_MODE_REPLACE_NAMESPACE)) {
      throw new PlatformApiException(
          400,
          "invalid_query_parameter",
          "App-data import mode must be merge or replaceNamespace.");
    }
    AppDataExportPayload payload =
        AppDataExportPayload.parseForImport(payloadBytes, normalizedAppId);
    List<AppDataNamespaceMetadata> importedNamespacesMetadata =
        payload.namespaces().stream()
            .map(metadata -> withCallerAppId(metadata, normalizedAppId))
            .toList();
    List<AppDataRecord> importedRecords =
        payload.records().stream()
            .map(appDataRecord -> withCallerAppId(appDataRecord, normalizedAppId))
            .toList();
    preflightImport(normalizedAppId, importedNamespacesMetadata, importedRecords, mode);
    LinkedHashSet<String> importedNamespaces = new LinkedHashSet<>();
    importedNamespacesMetadata.stream()
        .map(AppDataNamespaceMetadata::namespace)
        .forEach(importedNamespaces::add);
    importedRecords.stream().map(AppDataRecord::namespace).forEach(importedNamespaces::add);
    if (mode.equals(IMPORT_MODE_REPLACE_NAMESPACE)) {
      replaceImportedNamespaces(
          normalizedAppId, importedNamespacesMetadata, importedRecords, importedNamespaces);
    } else {
      for (AppDataNamespaceMetadata metadata : importedNamespacesMetadata) {
        writeNamespace(metadata);
      }
      for (AppDataRecord appDataRecord : importedRecords) {
        ensureNamespaceForRecord(appDataRecord);
        writeRecord(appDataRecord);
      }
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("imported", true);
    json.put("mode", mode);
    json.put(FIELD_NAMESPACE_COUNT, importedNamespaces.size());
    json.put(FIELD_RECORD_COUNT, importedRecords.size());
    json.put(FIELD_PAYLOAD_BYTES, payloadBytes.length);
    return json;
  }

  /**
   * Exports one operator-visible portable app-data backup bundle.
   *
   * <p>This route-level helper is host/operator-only in the router. It can export a single app id
   * or every app id safely known to the store, including preserved data for apps that are no longer
   * installed. The returned {@code backup} object and {@code payloadBase64} contain raw app-owned
   * values and must be handled as sensitive user backup data, not support diagnostics.
   *
   * @param parameters decoded query parameters; supply {@code appId} for one app or {@code
   *     scope=all} for all known app-data state
   * @param sourceCryptaVersion path-free daemon version label
   * @return backup response envelope containing the bundle and URL-safe payload base64
   */
  public synchronized Map<String, Object> exportBackup(
      Map<String, List<String>> parameters, String sourceCryptaVersion) {
    return backupRestoreWorkflow.exportBackup(parameters, sourceCryptaVersion);
  }

  /**
   * Builds a metadata-only restore plan for an operator backup payload.
   *
   * <p>The plan route decodes and validates the backup envelope, then runs the same identifier,
   * size, count, import, and quota preflight used by commit. It does not write app data and does
   * not expose record values from the backup payload.
   *
   * @param parameters decoded form/query fields containing {@code payloadBase64}, optional {@code
   *     mode}, and optional same-id {@code appId}
   * @return response envelope containing the metadata-only restore plan
   */
  public synchronized Map<String, Object> planRestore(Map<String, List<String>> parameters) {
    return backupRestoreWorkflow.planRestore(parameters);
  }

  /**
   * Restores an operator backup payload after preflight.
   *
   * <p>The method plans first and returns a blocked metadata result without writing when any app
   * entry cannot be restored. Successful commits use the requested restore mode and return only
   * counts, byte totals, app ids, and status codes.
   *
   * @param parameters decoded form/query fields containing {@code payloadBase64}, optional {@code
   *     mode}, and optional same-id {@code appId}
   * @return response envelope containing the metadata-only restore result
   */
  public synchronized Map<String, Object> restoreBackup(Map<String, List<String>> parameters) {
    return backupRestoreWorkflow.restoreBackup(parameters);
  }

  /**
   * Lists namespace metadata for update migration planning.
   *
   * <p>This internal path is metadata-only and remains scoped to one normalized app id. It exposes
   * the same path-free namespace records used by app-facing list routes, but keeps migration
   * planning inside the daemon instead of requiring update code to inspect store paths or values.
   *
   * @param appId app id whose namespace schemas should be inspected
   * @return deterministic namespace metadata for the app
   */
  public synchronized List<AppDataNamespaceMetadata> listNamespaceMetadataForUpdate(String appId) {
    return List.copyOf(listNamespaceMetadata(AppDataRecord.normalizeAppId(appId)));
  }

  /**
   * Begins an internal app-scoped write barrier for a schema-changing update migration.
   *
   * <p>The barrier is deliberately app-scoped rather than namespace-scoped because the update
   * lifecycle snapshots and restores app data as a whole. While the barrier is active, app-facing
   * writes for this app are rejected with {@code app_data_migration_in_progress}; internal update
   * migration import and snapshot restore methods remain available to the update lifecycle.
   *
   * @param appId app id whose app-facing writes must be blocked
   * @return closeable barrier token; closing releases one nested barrier
   */
  public synchronized UpdateMigrationWriteBarrier beginUpdateMigrationWriteBarrier(String appId) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    updateMigrationWriteBarriers.merge(normalizedAppId, 1, Integer::sum);
    return new UpdateMigrationWriteBarrier(normalizedAppId);
  }

  /**
   * Exports one namespace for an internal signed update migration command.
   *
   * <p>This method is app-scoped and reuses the normal export payload format so migration commands
   * receive bounded JSON data rather than store paths. The returned bytes are for the update
   * lifecycle only and must not be copied into public summaries.
   *
   * @param appId app id whose namespace should be exported
   * @param namespace namespace being migrated
   * @return UTF-8 app-data export payload bytes for the namespace
   */
  public synchronized byte[] exportUpdateMigrationPayload(String appId, String namespace) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    List<AppDataNamespaceMetadata> namespaces =
        readNamespaceOptional(normalizedAppId, normalizedNamespace).stream().toList();
    List<AppDataRecordSummary> summaries =
        listStoredRecordSummaries(normalizedAppId, normalizedNamespace);
    Instant exportedAt = clock.instant();
    enforceExportLimit(normalizedAppId, exportedAt, namespaces, summaries);
    AppDataExportPayload payload =
        new AppDataExportPayload(
            AppDataExportPayload.CURRENT_EXPORT_VERSION,
            normalizedAppId,
            exportedAt,
            namespaces,
            listStoredRecords(normalizedAppId, normalizedNamespace));
    byte[] payloadBytes = payload.toJsonBytes();
    if (payloadBytes.length > config.maxExportBytes()) {
      throw new PlatformApiException(
          400, "app_data_export_too_large", "App-data export exceeds the configured limit.");
    }
    return payloadBytes;
  }

  /**
   * Returns the maximum accepted migration output payload size.
   *
   * @return configured app-data import byte cap
   */
  public synchronized int maxUpdateMigrationPayloadBytes() {
    return config.maxImportBytes();
  }

  /**
   * Validates one dry-run migration output and returns the payload shape for the next chained step.
   *
   * <p>The returned bytes are not committed to durable app data. They contain the same migrated
   * records from the command output, with namespace metadata advanced to the step target so a later
   * dry-run step for the same namespace sees the schema precondition it declared.
   *
   * @param appId app id whose namespace is being dry-run migrated
   * @param namespace namespace being migrated
   * @param fromSchemaVersion current namespace schema version for this step
   * @param toSchemaVersion target namespace schema version for this step
   * @param summary bounded migration summary to attach to temporary metadata
   * @param payloadBytes command output payload bytes
   * @return validated export payload bytes suitable as the next dry-run input
   */
  public synchronized byte[] advanceUpdateMigrationDryRunPayload(
      String appId,
      String namespace,
      int fromSchemaVersion,
      int toSchemaVersion,
      String summary,
      byte[] payloadBytes) {
    return advanceUpdateMigrationDryRunPayload(
        appId,
        namespace,
        fromSchemaVersion,
        toSchemaVersion,
        summary,
        payloadBytes,
        ManifestQuotaCheck.installedManifest());
  }

  /**
   * Validates one dry-run migration output against the target manifest quota for an update.
   *
   * <p>This variant is used before the updated bundle is installed. Store-level limits still apply,
   * but positive manifest data-quota checks use the candidate manifest's {@code quota.data.bytes}
   * declaration instead of the old installed bundle's quota.
   *
   * @param appId app id whose namespace is being dry-run migrated
   * @param namespace namespace being migrated
   * @param fromSchemaVersion current namespace schema version for this step
   * @param toSchemaVersion target namespace schema version for this step
   * @param summary bounded migration summary to attach to temporary metadata
   * @param payloadBytes command output payload bytes
   * @param targetDataQuotaBytes candidate manifest quota, or {@code null} when the target has no
   *     positive manifest data quota
   * @return validated export payload bytes suitable as the next dry-run input
   */
  public synchronized byte[] advanceUpdateMigrationDryRunPayload(
      String appId,
      String namespace,
      int fromSchemaVersion,
      int toSchemaVersion,
      String summary,
      byte[] payloadBytes,
      Long targetDataQuotaBytes) {
    return advanceUpdateMigrationDryRunPayload(
        appId,
        namespace,
        fromSchemaVersion,
        toSchemaVersion,
        summary,
        payloadBytes,
        ManifestQuotaCheck.targetManifest(targetDataQuotaBytes));
  }

  private byte[] advanceUpdateMigrationDryRunPayload(
      String appId,
      String namespace,
      int fromSchemaVersion,
      int toSchemaVersion,
      String summary,
      byte[] payloadBytes,
      ManifestQuotaCheck manifestQuotaCheck) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    UpdateMigrationPayload payload =
        updateMigrationPayload(
            normalizedAppId, namespace, fromSchemaVersion, toSchemaVersion, payloadBytes);
    AppDataMigrationRecord migration =
        new AppDataMigrationRecord(
            fromSchemaVersion, toSchemaVersion, summary == null ? "" : summary, clock.instant());
    List<AppDataNamespaceMetadata> advancedNamespaces =
        payload.importedNamespacesMetadata().stream()
            .map(metadata -> withImportedRecordTotals(metadata, payload.importedRecords()))
            .map(metadata -> metadata.withMigration(migration, config.maxMigrationHistory()))
            .toList();
    preflightImport(
        normalizedAppId,
        advancedNamespaces,
        payload.importedRecords(),
        IMPORT_MODE_REPLACE_NAMESPACE,
        manifestQuotaCheck);
    byte[] advancedPayload =
        new AppDataExportPayload(
                AppDataExportPayload.CURRENT_EXPORT_VERSION,
                normalizedAppId,
                clock.instant(),
                advancedNamespaces,
                payload.importedRecords())
            .toJsonBytes();
    if (advancedPayload.length > config.maxImportBytes()) {
      throw new PlatformApiException(
          400, "app_data_import_too_large", "App-data import exceeds the configured limit.");
    }
    return advancedPayload;
  }

  /**
   * Validates the combined projected output of all dry-run migrated namespaces.
   *
   * <p>Each payload must already have passed {@link #advanceUpdateMigrationDryRunPayload(String,
   * String, int, int, String, byte[])} for its namespace. This method reparses those advanced
   * payloads together and applies the normal replace-namespace import preflight once, so a dry-run
   * that grows several namespaces cannot pass independently and then fail during apply after the
   * first namespace has already been committed.
   *
   * @param appId app id whose namespace outputs are being projected
   * @param payloads advanced dry-run payload bytes keyed by migrated namespace in caller order
   */
  public synchronized void preflightUpdateMigrationDryRunPayloads(
      String appId, Collection<byte[]> payloads) {
    preflightUpdateMigrationDryRunPayloads(appId, payloads, ManifestQuotaCheck.installedManifest());
  }

  /**
   * Validates combined dry-run outputs against the target manifest quota for an update.
   *
   * <p>This variant is used while the candidate bundle is still staged. Store-level import limits
   * are enforced from the durable app-data configuration, while positive manifest data-quota checks
   * use the candidate manifest quota supplied by the update lifecycle.
   *
   * @param appId app id whose namespace outputs are being projected
   * @param payloads advanced dry-run payload bytes keyed by migrated namespace in caller order
   * @param targetDataQuotaBytes candidate manifest quota, or {@code null} when the target has no
   *     positive manifest data quota
   */
  public synchronized void preflightUpdateMigrationDryRunPayloads(
      String appId, Collection<byte[]> payloads, Long targetDataQuotaBytes) {
    preflightUpdateMigrationDryRunPayloads(
        appId, payloads, ManifestQuotaCheck.targetManifest(targetDataQuotaBytes));
  }

  private void preflightUpdateMigrationDryRunPayloads(
      String appId, Collection<byte[]> payloads, ManifestQuotaCheck manifestQuotaCheck) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    Objects.requireNonNull(payloads, "payloads");
    ArrayList<AppDataNamespaceMetadata> importedNamespacesMetadata = new ArrayList<>();
    ArrayList<AppDataRecord> importedRecords = new ArrayList<>();
    LinkedHashSet<String> seenNamespaces = new LinkedHashSet<>();
    for (byte[] payloadBytes : payloads) {
      AppDataExportPayload payload = parseAdvancedMigrationPayload(normalizedAppId, payloadBytes);
      List<AppDataNamespaceMetadata> payloadNamespacesMetadata =
          payload.namespaces().stream()
              .map(metadata -> withCallerAppId(metadata, normalizedAppId))
              .toList();
      List<AppDataRecord> payloadRecords =
          payload.records().stream()
              .map(appDataRecord -> withCallerAppId(appDataRecord, normalizedAppId))
              .toList();
      Set<String> payloadNamespaces =
          collectImportedNamespaces(payloadNamespacesMetadata, payloadRecords);
      if (payloadNamespaces.size() != 1 || payloadNamespacesMetadata.size() != 1) {
        throw invalidMigrationOutput();
      }
      for (String namespace : payloadNamespaces) {
        if (!seenNamespaces.add(namespace)) {
          throw invalidMigrationOutput();
        }
      }
      importedNamespacesMetadata.addAll(payloadNamespacesMetadata);
      importedRecords.addAll(payloadRecords);
    }
    preflightImport(
        normalizedAppId,
        importedNamespacesMetadata,
        importedRecords,
        IMPORT_MODE_REPLACE_NAMESPACE,
        manifestQuotaCheck);
  }

  private AppDataExportPayload parseAdvancedMigrationPayload(String appId, byte[] payloadBytes) {
    Objects.requireNonNull(payloadBytes, FIELD_PAYLOAD_BYTES);
    if (payloadBytes.length > config.maxImportBytes()) {
      throw new PlatformApiException(
          400, "app_data_import_too_large", "App-data import exceeds the configured limit.");
    }
    return AppDataExportPayload.parseForImport(payloadBytes, appId);
  }

  /**
   * Imports one namespace migration output payload after a successful apply command.
   *
   * <p>The output must contain only the namespace being migrated. Namespace metadata must still be
   * at the pre-migration schema version so the platform can append the signed migration record
   * immediately afterward; all records in the namespace must already carry the target schema
   * version.
   *
   * @param appId app id whose namespace is being migrated
   * @param namespace namespace being migrated
   * @param fromSchemaVersion current namespace schema version
   * @param toSchemaVersion target record schema version
   * @param payloadBytes command output payload bytes
   */
  public synchronized void importUpdateMigrationPayload(
      String appId,
      String namespace,
      int fromSchemaVersion,
      int toSchemaVersion,
      byte[] payloadBytes) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    UpdateMigrationPayload payload =
        updateMigrationPayload(
            normalizedAppId, namespace, fromSchemaVersion, toSchemaVersion, payloadBytes);
    preflightImport(
        normalizedAppId,
        payload.importedNamespacesMetadata(),
        payload.importedRecords(),
        IMPORT_MODE_REPLACE_NAMESPACE);
    replaceImportedNamespaces(
        normalizedAppId,
        payload.importedNamespacesMetadata(),
        payload.importedRecords(),
        payload.importedNamespaces());
  }

  /**
   * Creates an internal app-data snapshot for a schema-changing app update.
   *
   * <p>The snapshot reuses the export payload validation and configured export size limit. It is
   * returned as an in-memory object owned by the update lifecycle; no app-facing route is added and
   * raw values must not be copied into public update summaries.
   *
   * @param appId app id whose durable app-data state should be snapshotted
   * @return bounded internal update snapshot
   */
  public synchronized AppDataUpdateSnapshot createUpdateSnapshot(String appId) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    List<AppDataNamespaceMetadata> namespaces = listNamespaceMetadata(normalizedAppId);
    List<AppDataRecordSummary> summaries = listStoredRecordSummaries(normalizedAppId, null);
    Instant exportedAt = clock.instant();
    if (projectedExportBytes(normalizedAppId, exportedAt, namespaces, summaries)
        > config.maxExportBytes()) {
      throw new PlatformApiException(
          400,
          "app_data_snapshot_too_large",
          "App-data update snapshot exceeds the configured limit.");
    }
    List<AppDataRecord> records = listStoredRecords(normalizedAppId, null);
    AppDataExportPayload payload =
        new AppDataExportPayload(
            AppDataExportPayload.CURRENT_EXPORT_VERSION,
            normalizedAppId,
            exportedAt,
            namespaces,
            records);
    byte[] payloadBytes = payload.toJsonBytes();
    if (payloadBytes.length > config.maxExportBytes()) {
      throw new PlatformApiException(
          400,
          "app_data_snapshot_too_large",
          "App-data update snapshot exceeds the configured limit.");
    }
    return new AppDataUpdateSnapshot(payload, payloadBytes.length, exportedAt);
  }

  /**
   * Restores a previously created internal app-data update snapshot.
   *
   * <p>The snapshot must belong to the requested app. The method validates record sizes,
   * namespace/record counts, and migration-history bounds before deleting current app state and
   * writing the snapshot records back. It does not accept arbitrary user-supplied payloads.
   *
   * @param appId app id whose snapshot should be restored
   * @param snapshot internal update snapshot created by {@link #createUpdateSnapshot(String)}
   */
  public synchronized void restoreUpdateSnapshot(String appId, AppDataUpdateSnapshot snapshot) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    AppDataUpdateSnapshot checkedSnapshot = Objects.requireNonNull(snapshot, "snapshot");
    if (!normalizedAppId.equals(checkedSnapshot.appId())) {
      throw new PlatformApiException(
          400, "app_data_snapshot_app_mismatch", "App-data snapshot belongs to another app.");
    }
    List<AppDataNamespaceMetadata> namespaces =
        checkedSnapshot.payload().namespaces().stream()
            .map(metadata -> withCallerAppId(metadata, normalizedAppId))
            .toList();
    List<AppDataRecord> records =
        checkedSnapshot.payload().records().stream()
            .map(appDataRecord -> withCallerAppId(appDataRecord, normalizedAppId))
            .toList();
    rejectOversizedImportedRecords(records);
    validateImportedNamespaceMetadata(namespaces);
    if (namespaces.size() > config.maxNamespacesPerApp()
        || records.size() > config.maxRecordsPerApp()) {
      throw quotaExceeded();
    }
    long totalBytes = records.stream().mapToLong(AppDataRecord::valueBytes).sum();
    if (totalBytes > config.maxStoredValueBytesPerApp()) {
      throw quotaExceeded();
    }
    try {
      store.deleteAllForApp(normalizedAppId);
    } catch (IOException _) {
      throw storeUnavailable();
    }
    for (AppDataNamespaceMetadata metadata : namespaces) {
      writeNamespace(metadata);
    }
    for (AppDataRecord appDataRecord : records) {
      ensureNamespaceForRecord(appDataRecord);
      writeRecord(appDataRecord);
    }
  }

  /**
   * Discards an internal app-data update snapshot.
   *
   * <p>Snapshots are currently in-memory, so discard is a validation point and future extension
   * hook rather than an I/O operation.
   *
   * @param snapshot snapshot no longer needed by the update lifecycle
   */
  public synchronized void discardUpdateSnapshot(AppDataUpdateSnapshot snapshot) {
    Objects.requireNonNull(snapshot, "snapshot");
  }

  /**
   * Records app-data schema metadata after a signed update migration step has completed.
   *
   * @param appId app id whose namespace migrated
   * @param namespace app-data namespace
   * @param fromSchemaVersion previous namespace schema version
   * @param toSchemaVersion target namespace schema version
   * @param summary bounded migration summary
   */
  public synchronized void recordUpdateMigration(
      String appId, String namespace, int fromSchemaVersion, int toSchemaVersion, String summary) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    Map<String, List<String>> parameters =
        Map.of(
            "fromSchemaVersion",
            List.of(Integer.toString(fromSchemaVersion)),
            "toSchemaVersion",
            List.of(Integer.toString(toSchemaVersion)),
            "summary",
            List.of(summary == null ? "" : summary));
    updateSchemaInternal(normalizedAppId, normalizedNamespace, parameters);
  }

  /**
   * Clears all durable app-data state for an app after uninstall.
   *
   * <p>This method is used by operator-driven uninstall cleanup when data preservation is not
   * requested. It is intentionally coarse-grained and bypasses per-namespace responses because the
   * app is being removed from the local AppHost.
   *
   * @param appId app id whose durable app-data state should be removed
   */
  public synchronized void clearAppState(String appId) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    rejectIfUpdateMigrationWriteBarrierActive(normalizedAppId);
    try {
      store.deleteAllForApp(normalizedAppId);
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  Instant currentBackupInstant() {
    return clock.instant();
  }

  int maxBackupExportBytes() {
    return config.maxExportBytes();
  }

  int maxBackupImportBytes() {
    return config.maxImportBytes();
  }

  AppDataExportPayload exportPayload(String normalizedAppId, Instant exportedAt) {
    List<AppDataRecordSummary> summaries = listStoredRecordSummaries(normalizedAppId, null);
    List<AppDataNamespaceMetadata> namespaces = listNamespaceMetadata(normalizedAppId);
    enforceExportLimit(normalizedAppId, exportedAt, namespaces, summaries);
    return new AppDataExportPayload(
        AppDataExportPayload.CURRENT_EXPORT_VERSION,
        normalizedAppId,
        exportedAt,
        namespaces,
        listStoredRecords(normalizedAppId, null));
  }

  void preflightRestorePayload(
      String appId, AppDataExportPayload exportPayload, String importMode, boolean replaceApp) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    rejectIfUpdateMigrationWriteBarrierActive(normalizedAppId);
    List<AppDataNamespaceMetadata> importedNamespacesMetadata =
        exportPayload.namespaces().stream()
            .map(metadata -> withCallerAppId(metadata, normalizedAppId))
            .toList();
    List<AppDataRecord> importedRecords =
        exportPayload.records().stream()
            .map(appDataRecord -> withCallerAppId(appDataRecord, normalizedAppId))
            .toList();
    if (replaceApp) {
      preflightReplaceApp(normalizedAppId, importedNamespacesMetadata, importedRecords);
      return;
    }
    preflightImport(normalizedAppId, importedNamespacesMetadata, importedRecords, importMode);
  }

  private void preflightReplaceApp(
      String appId,
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      List<AppDataRecord> importedRecords) {
    rejectOversizedImportedRecords(importedRecords);
    validateImportedNamespaceMetadata(importedNamespacesMetadata);
    Set<String> importedNamespaces =
        collectImportedNamespaces(importedNamespacesMetadata, importedRecords);
    Map<String, Long> projectedRecordBytes = new LinkedHashMap<>();
    for (AppDataRecord appDataRecord : importedRecords) {
      projectedRecordBytes.put(recordKey(appDataRecord), (long) appDataRecord.valueBytes());
    }
    ProjectedImport projected = new ProjectedImport(projectedRecordBytes, importedNamespaces);
    enforceProjectedImportLimits(projected);
    Map<String, AppDataNamespaceMetadata> noCurrentMetadata = Map.of();
    long projectedStoreUsageBytes =
        projectedStoreQuotaUsageBytes(importedNamespacesMetadata, noCurrentMetadata, projected);
    long currentStoreUsageBytes = currentStoreQuotaUsageBytes(appId);
    enforceManifestQuota(
        appId,
        Math.max(0L, projectedStoreUsageBytes - currentStoreUsageBytes),
        ManifestQuotaCheck.installedManifest(),
        projectedStoreUsageBytes);
  }

  void commitRestorePayload(
      String appId, AppDataExportPayload exportPayload, String importMode, boolean replaceApp) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    preflightRestorePayload(normalizedAppId, exportPayload, importMode, replaceApp);
    List<AppDataNamespaceMetadata> importedNamespacesMetadata =
        exportPayload.namespaces().stream()
            .map(metadata -> withCallerAppId(metadata, normalizedAppId))
            .toList();
    List<AppDataRecord> importedRecords =
        exportPayload.records().stream()
            .map(appDataRecord -> withCallerAppId(appDataRecord, normalizedAppId))
            .toList();
    Set<String> importedNamespaces =
        collectImportedNamespaces(importedNamespacesMetadata, importedRecords);
    if (replaceApp) {
      replaceAppData(
          normalizedAppId, importedNamespacesMetadata, importedRecords, importedNamespaces);
      return;
    }
    if (IMPORT_MODE_REPLACE_NAMESPACE.equals(importMode)) {
      replaceImportedNamespaces(
          normalizedAppId, importedNamespacesMetadata, importedRecords, importedNamespaces);
      return;
    }
    for (AppDataNamespaceMetadata metadata : importedNamespacesMetadata) {
      writeNamespace(metadata);
    }
    for (AppDataRecord appDataRecord : importedRecords) {
      ensureNamespaceForRecord(appDataRecord);
      writeRecord(appDataRecord);
    }
  }

  private void replaceAppData(
      String appId,
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      List<AppDataRecord> importedRecords,
      Set<String> importedNamespaces) {
    if (importedNamespaces.isEmpty()) {
      try {
        store.deleteAllForApp(appId);
      } catch (IOException _) {
        throw storeUnavailable();
      }
      return;
    }
    Map<String, AppDataRecordSummary> existingRecords = currentRecordSummaryMap(appId);
    LinkedHashSet<String> importedRecordKeys = new LinkedHashSet<>();
    for (AppDataRecord appDataRecord : importedRecords) {
      importedRecordKeys.add(recordKey(appDataRecord));
      ensureNamespaceForRecord(appDataRecord);
      writeRecord(appDataRecord);
    }
    for (AppDataNamespaceMetadata metadata : importedNamespacesMetadata) {
      writeNamespace(metadata);
    }
    for (AppDataRecordSummary summary : existingRecords.values()) {
      if (!importedRecordKeys.contains(recordKey(summary))) {
        deleteStoredRecord(appId, summary.namespace(), summary.key());
      }
    }
    for (AppDataNamespaceMetadata namespace : listNamespaceMetadata(appId)) {
      if (!importedNamespaces.contains(namespace.namespace())) {
        deleteStoredNamespace(appId, namespace.namespace());
      }
    }
  }

  int conflictCount(String appId, AppDataExportPayload exportPayload) {
    Set<String> currentRecordKeys = currentRecordSummaryMap(appId).keySet();
    int conflicts = 0;
    for (AppDataRecord appDataRecord : exportPayload.records()) {
      if (currentRecordKeys.contains(recordKey(appDataRecord))) {
        conflicts++;
      }
    }
    return conflicts;
  }

  Optional<InstalledAppSnapshot> installedAppForBackup(String appId) {
    if (appHost == null) {
      return Optional.empty();
    }
    try {
      return appHost.describe(AppDataRecord.normalizeAppId(appId));
    } catch (IOException _) {
      throw new PlatformApiException(
          503, "app_data_backup_unavailable", "App-data backup metadata is unavailable.");
    }
  }

  List<String> listStoreAppIds() {
    try {
      return store.listAppIds().stream().map(AppDataRecord::normalizeAppId).sorted().toList();
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private void rejectIfUpdateMigrationWriteBarrierActive(String normalizedAppId) {
    if (updateMigrationWriteBarriers.getOrDefault(normalizedAppId, 0) <= 0) {
      return;
    }
    throw new PlatformApiException(
        409,
        "app_data_migration_in_progress",
        "App-data writes are blocked while an update migration is in progress.");
  }

  /** App-scoped write barrier token for internal update migrations. */
  public final class UpdateMigrationWriteBarrier implements AutoCloseable {
    private final String appId;
    private boolean closed;

    private UpdateMigrationWriteBarrier(String appId) {
      this.appId = appId;
    }

    @Override
    public void close() {
      synchronized (AppDataService.this) {
        if (closed) {
          return;
        }
        closed = true;
        release();
      }
    }

    private void release() {
      Integer count = updateMigrationWriteBarriers.get(appId);
      if (count == null) {
        return;
      }
      if (count <= 1) {
        updateMigrationWriteBarriers.remove(appId);
        return;
      }
      updateMigrationWriteBarriers.put(appId, count - 1);
    }
  }

  private void ensureNamespaceForRecord(AppDataRecord appDataRecord) {
    AppDataNamespaceMetadata existing =
        readNamespaceOptional(appDataRecord.appId(), appDataRecord.namespace()).orElse(null);
    if (existing != null) {
      return;
    }
    Instant now = clock.instant();
    writeNamespace(
        new AppDataNamespaceMetadata(
            appDataRecord.appId(),
            appDataRecord.namespace(),
            appDataRecord.schemaVersion(),
            0,
            0L,
            now,
            now,
            null,
            List.of()));
  }

  private void replaceImportedNamespaces(
      String appId,
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      List<AppDataRecord> importedRecords,
      Set<String> importedNamespaces) {
    Map<String, AppDataRecordSummary> existingRecords = new LinkedHashMap<>();
    for (String namespace : importedNamespaces) {
      for (AppDataRecordSummary summary : listStoredRecordSummaries(appId, namespace)) {
        existingRecords.put(recordKey(summary), summary);
      }
    }
    LinkedHashSet<String> importedRecordKeys = new LinkedHashSet<>();
    for (AppDataRecord appDataRecord : importedRecords) {
      importedRecordKeys.add(recordKey(appDataRecord));
      ensureNamespaceForRecord(appDataRecord);
      writeRecord(appDataRecord);
    }
    for (AppDataNamespaceMetadata metadata : importedNamespacesMetadata) {
      writeNamespace(metadata);
    }
    for (AppDataRecordSummary summary : existingRecords.values()) {
      if (!importedRecordKeys.contains(recordKey(summary))) {
        deleteStoredRecord(appId, summary.namespace(), summary.key());
      }
    }
  }

  private void enforceExportLimit(
      String appId,
      Instant exportedAt,
      List<AppDataNamespaceMetadata> namespaces,
      List<AppDataRecordSummary> summaries) {
    if (projectedExportBytes(appId, exportedAt, namespaces, summaries) > config.maxExportBytes()) {
      throw new PlatformApiException(
          400, "app_data_export_too_large", "App-data export exceeds the configured limit.");
    }
  }

  private static long projectedExportBytes(
      String appId,
      Instant exportedAt,
      List<AppDataNamespaceMetadata> namespaces,
      List<AppDataRecordSummary> summaries) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("exportVersion", AppDataExportPayload.CURRENT_EXPORT_VERSION);
    json.put(PARAM_APP_ID, appId);
    json.put("exportedAt", exportedAt.toString());
    json.put(FIELD_NAMESPACE_COUNT, namespaces.size());
    json.put(FIELD_RECORD_COUNT, summaries.size());
    json.put(
        "namespaces", namespaces.stream().map(namespace -> namespace.toJsonValue(true)).toList());
    json.put("records", List.of());
    long bytesWithoutRecords = utf8Length(PlatformApiJsonWriter.write(json)) - 2L;
    if (summaries.isEmpty()) {
      return bytesWithoutRecords + 2L;
    }
    long recordsBytes = summaries.size() - 1L;
    for (AppDataRecordSummary summary : summaries) {
      recordsBytes += projectedRecordExportBytes(summary);
    }
    return bytesWithoutRecords + 1L + recordsBytes + 1L;
  }

  private static long projectedRecordExportBytes(AppDataRecordSummary summary) {
    String summaryJson = PlatformApiJsonWriter.write(summary.toJsonValue());
    return utf8Length(summaryJson)
        - 1L
        + utf8Length(",\"valueBase64\":\"")
        + base64EncodedLength(summary.valueBytes())
        + utf8Length("\"}");
  }

  private static long base64EncodedLength(int valueBytes) {
    return (valueBytes + 2L) / 3L * 4L;
  }

  private static long utf8Length(String value) {
    return value.getBytes(StandardCharsets.UTF_8).length;
  }

  private void enforceWriteQuotas(
      String appId, String namespace, AppDataRecord existing, int newValueBytes) {
    ensureNamespaceLimitForWrite(appId, namespace);
    List<AppDataRecordSummary> allRecords = listStoredRecordSummaries(appId, null);
    boolean replacing = existing != null;
    if (!replacing && allRecords.size() >= config.maxRecordsPerApp()) {
      throw quotaExceeded();
    }
    long currentBytes = allRecords.stream().mapToLong(AppDataRecordSummary::valueBytes).sum();
    long projectedStoreBytes =
        currentBytes - (existing == null ? 0L : existing.valueBytes()) + newValueBytes;
    if (projectedStoreBytes > config.maxStoredValueBytesPerApp()) {
      throw quotaExceeded();
    }
    long manifestDelta =
        Math.max(0L, newValueBytes - (existing == null ? 0L : existing.valueBytes()));
    if (!replacing) {
      manifestDelta += RECORD_METADATA_QUOTA_RESERVE_BYTES;
    }
    if (readNamespaceOptional(appId, namespace).isEmpty()) {
      manifestDelta += NAMESPACE_METADATA_QUOTA_RESERVE_BYTES;
    }
    enforceManifestQuota(appId, manifestDelta);
  }

  private void preflightImport(
      String appId,
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      List<AppDataRecord> importedRecords,
      String mode) {
    preflightImport(
        appId,
        importedNamespacesMetadata,
        importedRecords,
        mode,
        ManifestQuotaCheck.installedManifest());
  }

  private void preflightImport(
      String appId,
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      List<AppDataRecord> importedRecords,
      String mode,
      ManifestQuotaCheck manifestQuotaCheck) {
    rejectOversizedImportedRecords(importedRecords);
    validateImportedNamespaceMetadata(importedNamespacesMetadata);
    Set<String> importedNamespaces =
        collectImportedNamespaces(importedNamespacesMetadata, importedRecords);
    Map<String, AppDataRecordSummary> currentRecords = currentRecordSummaryMap(appId);
    Map<String, AppDataNamespaceMetadata> currentNamespaceMetadata =
        currentNamespaceMetadataMap(appId);
    LinkedHashSet<String> currentNamespaces =
        new LinkedHashSet<>(currentNamespaceMetadata.keySet());
    ProjectedImport projected =
        projectedImport(
            mode, importedRecords, importedNamespaces, currentRecords, currentNamespaces);
    enforceProjectedImportLimits(projected);
    long totalBytes =
        projected.recordBytesByKey().values().stream().mapToLong(Long::longValue).sum();
    long currentBytes =
        currentRecords.values().stream().mapToLong(AppDataRecordSummary::valueBytes).sum();
    long manifestDelta =
        importMetadataManifestDelta(
            importedNamespacesMetadata,
            currentRecords,
            currentNamespaceMetadata,
            currentNamespaces,
            projected,
            totalBytes,
            currentBytes);
    long projectedStoreUsageBytes =
        projectedStoreQuotaUsageBytes(
            importedNamespacesMetadata, currentNamespaceMetadata, projected);
    enforceManifestQuota(appId, manifestDelta, manifestQuotaCheck, projectedStoreUsageBytes);
  }

  private void rejectOversizedImportedRecords(List<AppDataRecord> importedRecords) {
    if (importedRecords.stream()
        .anyMatch(appDataRecord -> appDataRecord.valueBytes() > config.maxRecordBytes())) {
      throw new PlatformApiException(
          400, "app_data_record_too_large", "App-data import contains an oversized record.");
    }
  }

  private static Set<String> collectImportedNamespaces(
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      List<AppDataRecord> importedRecords) {
    LinkedHashSet<String> importedNamespaces = new LinkedHashSet<>();
    importedNamespacesMetadata.stream()
        .map(AppDataNamespaceMetadata::namespace)
        .forEach(importedNamespaces::add);
    importedRecords.stream().map(AppDataRecord::namespace).forEach(importedNamespaces::add);
    return importedNamespaces;
  }

  private Map<String, AppDataRecordSummary> currentRecordSummaryMap(String appId) {
    Map<String, AppDataRecordSummary> currentRecords = new LinkedHashMap<>();
    for (AppDataRecordSummary recordSummary : listStoredRecordSummaries(appId, null)) {
      currentRecords.put(recordKey(recordSummary), recordSummary);
    }
    return currentRecords;
  }

  private Map<String, AppDataNamespaceMetadata> currentNamespaceMetadataMap(String appId) {
    Map<String, AppDataNamespaceMetadata> currentNamespaceMetadata = new LinkedHashMap<>();
    for (AppDataNamespaceMetadata namespace : listNamespaceMetadata(appId)) {
      currentNamespaceMetadata.put(namespace.namespace(), namespace);
    }
    return currentNamespaceMetadata;
  }

  private static ProjectedImport projectedImport(
      String mode,
      List<AppDataRecord> importedRecords,
      Set<String> importedNamespaces,
      Map<String, AppDataRecordSummary> currentRecords,
      Set<String> currentNamespaces) {
    Map<String, Long> projectedRecordBytes = new LinkedHashMap<>();
    LinkedHashSet<String> projectedNamespaces = new LinkedHashSet<>();
    if (mode.equals(IMPORT_MODE_MERGE)) {
      projectedNamespaces.addAll(currentNamespaces);
      currentRecords.forEach(
          (key, summary) -> projectedRecordBytes.put(key, (long) summary.valueBytes()));
    } else {
      projectRecordsOutsideReplacedNamespaces(
          currentRecords, importedNamespaces, projectedRecordBytes, projectedNamespaces);
      currentNamespaces.stream()
          .filter(namespace -> !importedNamespaces.contains(namespace))
          .forEach(projectedNamespaces::add);
    }
    projectedNamespaces.addAll(importedNamespaces);
    importedRecords.forEach(
        appDataRecord ->
            projectedRecordBytes.put(recordKey(appDataRecord), (long) appDataRecord.valueBytes()));
    return new ProjectedImport(projectedRecordBytes, projectedNamespaces);
  }

  private static void projectRecordsOutsideReplacedNamespaces(
      Map<String, AppDataRecordSummary> currentRecords,
      Set<String> importedNamespaces,
      Map<String, Long> projectedRecordBytes,
      Set<String> projectedNamespaces) {
    for (AppDataRecordSummary recordSummary : currentRecords.values()) {
      if (!importedNamespaces.contains(recordSummary.namespace())) {
        projectedRecordBytes.put(recordKey(recordSummary), (long) recordSummary.valueBytes());
        projectedNamespaces.add(recordSummary.namespace());
      }
    }
  }

  private void enforceProjectedImportLimits(ProjectedImport projected) {
    if (projected.namespaces().size() > config.maxNamespacesPerApp()
        || projected.recordBytesByKey().size() > config.maxRecordsPerApp()) {
      throw quotaExceeded();
    }
    long totalBytes =
        projected.recordBytesByKey().values().stream().mapToLong(Long::longValue).sum();
    if (totalBytes > config.maxStoredValueBytesPerApp()) {
      throw quotaExceeded();
    }
  }

  private static long importMetadataManifestDelta(
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      Map<String, AppDataRecordSummary> currentRecords,
      Map<String, AppDataNamespaceMetadata> currentNamespaceMetadata,
      Set<String> currentNamespaces,
      ProjectedImport projected,
      long totalBytes,
      long currentBytes) {
    long manifestDelta = Math.max(0L, totalBytes - currentBytes);
    LinkedHashSet<String> namespacesWithImportedMetadata = new LinkedHashSet<>();
    for (AppDataNamespaceMetadata metadata : importedNamespacesMetadata) {
      namespacesWithImportedMetadata.add(metadata.namespace());
      AppDataNamespaceMetadata current = currentNamespaceMetadata.get(metadata.namespace());
      manifestDelta +=
          current == null
              ? namespaceMetadataQuotaReserve(metadata)
              : positiveNamespaceMetadataDelta(current, metadata);
    }
    for (String namespace : projected.namespaces()) {
      if (!currentNamespaces.contains(namespace)
          && !namespacesWithImportedMetadata.contains(namespace)) {
        manifestDelta += NAMESPACE_METADATA_QUOTA_RESERVE_BYTES;
      }
    }
    for (String recordKey : projected.recordBytesByKey().keySet()) {
      if (!currentRecords.containsKey(recordKey)) {
        manifestDelta += RECORD_METADATA_QUOTA_RESERVE_BYTES;
      }
    }
    return manifestDelta;
  }

  private static long projectedStoreQuotaUsageBytes(
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      Map<String, AppDataNamespaceMetadata> currentNamespaceMetadata,
      ProjectedImport projected) {
    long total =
        projected.recordBytesByKey().values().stream()
            .mapToLong(valueBytes -> valueBytes + RECORD_METADATA_QUOTA_RESERVE_BYTES)
            .sum();
    Map<String, AppDataNamespaceMetadata> importedNamespaceMetadataByName =
        importedNamespaceMetadataByName(importedNamespacesMetadata);
    for (String namespace : projected.namespaces()) {
      AppDataNamespaceMetadata importedMetadata = importedNamespaceMetadataByName.get(namespace);
      if (importedMetadata != null) {
        total += namespaceMetadataQuotaReserve(importedMetadata);
        continue;
      }
      AppDataNamespaceMetadata currentMetadata = currentNamespaceMetadata.get(namespace);
      total +=
          currentMetadata == null
              ? NAMESPACE_METADATA_QUOTA_RESERVE_BYTES
              : namespaceMetadataQuotaReserve(currentMetadata);
    }
    return total;
  }

  private static Map<String, AppDataNamespaceMetadata> importedNamespaceMetadataByName(
      List<AppDataNamespaceMetadata> importedNamespacesMetadata) {
    Map<String, AppDataNamespaceMetadata> metadataByName = new LinkedHashMap<>();
    for (AppDataNamespaceMetadata metadata : importedNamespacesMetadata) {
      metadataByName.put(metadata.namespace(), metadata);
    }
    return metadataByName;
  }

  private void validateImportedNamespaceMetadata(List<AppDataNamespaceMetadata> metadata) {
    for (AppDataNamespaceMetadata namespace : metadata) {
      if (namespace.migrationHistory().size() > config.maxMigrationHistory()) {
        throw new PlatformApiException(
            400,
            "invalid_app_data_import",
            "App-data import migration history exceeds the configured limit.");
      }
    }
  }

  private UpdateMigrationPayload updateMigrationPayload(
      String appId,
      String namespace,
      int fromSchemaVersion,
      int toSchemaVersion,
      byte[] payloadBytes) {
    String normalizedAppId = AppDataRecord.normalizeAppId(appId);
    String normalizedNamespace = AppDataRecord.normalizeNamespace(namespace);
    if (fromSchemaVersion <= 0 || toSchemaVersion <= fromSchemaVersion) {
      throw invalidMigrationOutput();
    }
    Objects.requireNonNull(payloadBytes, FIELD_PAYLOAD_BYTES);
    if (payloadBytes.length > config.maxImportBytes()) {
      throw new PlatformApiException(
          400, "app_data_import_too_large", "App-data import exceeds the configured limit.");
    }
    AppDataExportPayload payload =
        AppDataExportPayload.parseForImport(payloadBytes, normalizedAppId);
    List<AppDataNamespaceMetadata> importedNamespacesMetadata =
        payload.namespaces().stream()
            .map(metadata -> withCallerAppId(metadata, normalizedAppId))
            .toList();
    List<AppDataRecord> importedRecords =
        payload.records().stream()
            .map(appDataRecord -> withCallerAppId(appDataRecord, normalizedAppId))
            .toList();
    Set<String> importedNamespaces =
        collectImportedNamespaces(importedNamespacesMetadata, importedRecords);
    validateUpdateMigrationScope(
        normalizedNamespace,
        fromSchemaVersion,
        toSchemaVersion,
        importedNamespacesMetadata,
        importedRecords,
        importedNamespaces);
    return new UpdateMigrationPayload(
        importedNamespacesMetadata, importedRecords, importedNamespaces);
  }

  private static void validateUpdateMigrationScope(
      String namespace,
      int fromSchemaVersion,
      int toSchemaVersion,
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      List<AppDataRecord> importedRecords,
      Set<String> importedNamespaces) {
    if (importedNamespaces.size() != 1 || !importedNamespaces.contains(namespace)) {
      throw invalidMigrationOutput();
    }
    if (importedNamespacesMetadata.size() != 1
        || !namespace.equals(importedNamespacesMetadata.getFirst().namespace())
        || importedNamespacesMetadata.getFirst().schemaVersion() != fromSchemaVersion) {
      throw invalidMigrationOutput();
    }
    boolean recordsMigrated =
        importedRecords.stream()
            .allMatch(
                importedRecord ->
                    namespace.equals(importedRecord.namespace())
                        && importedRecord.schemaVersion() == toSchemaVersion);
    if (!recordsMigrated) {
      throw invalidMigrationOutput();
    }
  }

  private static PlatformApiException invalidMigrationOutput() {
    return new PlatformApiException(
        400,
        "invalid_app_data_migration_output",
        "App-data migration output is invalid for the requested namespace.");
  }

  private static long positiveNamespaceMetadataDelta(
      AppDataNamespaceMetadata current, AppDataNamespaceMetadata updated) {
    return Math.max(
        0L, namespaceMetadataQuotaReserve(updated) - namespaceMetadataQuotaReserve(current));
  }

  private static long namespaceMetadataQuotaReserve(AppDataNamespaceMetadata metadata) {
    return NAMESPACE_METADATA_QUOTA_RESERVE_BYTES
        + metadata.migrationHistory().size() * MIGRATION_METADATA_QUOTA_RESERVE_BYTES
        + utf8Length(PlatformApiJsonWriter.write(metadata.toJsonValue(true)));
  }

  private static String recordKey(AppDataRecord appDataRecord) {
    return appDataRecord.namespace() + "\u0000" + appDataRecord.key();
  }

  private static String recordKey(AppDataRecordSummary summary) {
    return summary.namespace() + "\u0000" + summary.key();
  }

  private void ensureNamespaceLimitForWrite(String appId, String namespace) {
    if (readNamespaceOptional(appId, namespace).isPresent()) {
      return;
    }
    if (listNamespaceMetadata(appId).size() >= config.maxNamespacesPerApp()) {
      throw quotaExceeded();
    }
  }

  private void enforceManifestQuota(String appId, long positiveDeltaBytes) {
    enforceManifestQuota(appId, positiveDeltaBytes, ManifestQuotaCheck.installedManifest());
  }

  private void enforceManifestQuota(
      String appId, long positiveDeltaBytes, ManifestQuotaCheck manifestQuotaCheck) {
    enforceManifestQuota(appId, positiveDeltaBytes, manifestQuotaCheck, null);
  }

  private void enforceManifestQuota(
      String appId,
      long positiveDeltaBytes,
      ManifestQuotaCheck manifestQuotaCheck,
      Long projectedStoreUsageBytes) {
    if (appHost == null || shouldSkipManifestQuotaCheck(positiveDeltaBytes, manifestQuotaCheck)) {
      return;
    }
    InstalledAppSnapshot installed = installedApp(appId).orElse(null);
    if (installed == null) {
      return;
    }
    Long quotaBytes =
        manifestQuotaCheck.useOverride()
            ? manifestQuotaCheck.quotaBytes()
            : installed.manifest().dataQuotaBytes();
    if (quotaBytes == null || quotaBytes <= 0L) {
      return;
    }
    AppDiskUsageScanner.ScanResult scan = diskUsageScanner.scan(installed.paths(), null);
    if (hasDataScanWarning(scan.warnings())) {
      throw new PlatformApiException(
          503, STATUS_QUOTA_UNAVAILABLE, "App-data quota could not be measured.");
    }
    if (projectedManifestQuotaUsageBytes(appId, scan, positiveDeltaBytes, projectedStoreUsageBytes)
        > quotaBytes) {
      throw quotaExceeded();
    }
  }

  private static boolean shouldSkipManifestQuotaCheck(
      long positiveDeltaBytes, ManifestQuotaCheck manifestQuotaCheck) {
    return positiveDeltaBytes <= 0L && !manifestQuotaCheck.useOverride();
  }

  private Map<String, Object> quotaJson(String appId) {
    InstalledAppSnapshot installed = installedApp(appId).orElse(null);
    Long manifestDataQuotaBytes = installed == null ? null : installed.manifest().dataQuotaBytes();
    LinkedHashMap<String, Object> quota = LinkedHashMap.newLinkedHashMap(5);
    quota.put("manifestDataQuotaBytes", manifestDataQuotaBytes);
    quota.put(
        "manifestDataQuotaEnforced", manifestDataQuotaBytes != null && manifestDataQuotaBytes > 0L);
    if (installed != null) {
      AppDiskUsageScanner.ScanResult scan = diskUsageScanner.scan(installed.paths(), null);
      quota.put("dataUsageBytes", manifestQuotaUsageBytes(appId, scan));
      quota.put("dataQuotaAvailable", !hasDataScanWarning(scan.warnings()));
    } else {
      quota.put("dataUsageBytes", null);
      quota.put("dataQuotaAvailable", false);
    }
    return quota;
  }

  private long manifestQuotaUsageBytes(String appId, AppDiskUsageScanner.ScanResult scan) {
    long dataUsageBytes = scan.usage().dataUsageBytes();
    if (!storeUsageOutsideAppDataDir) {
      return dataUsageBytes;
    }
    return dataUsageBytes + currentStoreQuotaUsageBytes(appId);
  }

  private long projectedManifestQuotaUsageBytes(
      String appId,
      AppDiskUsageScanner.ScanResult scan,
      long positiveDeltaBytes,
      Long projectedStoreUsageBytes) {
    long currentUsageBytes = manifestQuotaUsageBytes(appId, scan);
    if (!storeUsageOutsideAppDataDir || projectedStoreUsageBytes == null) {
      return currentUsageBytes + Math.max(0L, positiveDeltaBytes);
    }
    return currentUsageBytes - currentStoreQuotaUsageBytes(appId) + projectedStoreUsageBytes;
  }

  private long currentStoreQuotaUsageBytes(String appId) {
    long total =
        listStoredRecordSummaries(appId, null).stream()
            .mapToLong(summary -> summary.valueBytes() + RECORD_METADATA_QUOTA_RESERVE_BYTES)
            .sum();
    for (AppDataNamespaceMetadata namespace : listNamespaceMetadata(appId)) {
      total += namespaceMetadataQuotaReserve(namespace);
    }
    return total;
  }

  private List<String> quotaWarnings(String appId) {
    InstalledAppSnapshot installed = installedApp(appId).orElse(null);
    if (installed == null) {
      return List.of();
    }
    return diskUsageScanner.scan(installed.paths(), null).warnings().stream()
        .map(AppQuotaWarning::message)
        .toList();
  }

  private Optional<InstalledAppSnapshot> installedApp(String appId) {
    if (appHost == null) {
      return Optional.empty();
    }
    try {
      return appHost.describe(AppDataRecord.normalizeAppId(appId));
    } catch (IOException _) {
      throw new PlatformApiException(
          503, STATUS_QUOTA_UNAVAILABLE, "App-data quota could not be measured.");
    }
  }

  private static boolean hasDataScanWarning(List<AppQuotaWarning> warnings) {
    return warnings.stream().anyMatch(warning -> warning.code().startsWith("data_"));
  }

  private Map<String, Object> limitsJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("maxRecordBytes", config.maxRecordBytes());
    json.put("maxRecordsPerApp", config.maxRecordsPerApp());
    json.put("maxNamespacesPerApp", config.maxNamespacesPerApp());
    json.put("maxExportBytes", config.maxExportBytes());
    json.put("maxImportBytes", config.maxImportBytes());
    json.put("maxStoredValueBytesPerApp", config.maxStoredValueBytesPerApp());
    return json;
  }

  private List<AppDataNamespaceMetadata> listNamespaceMetadata(String appId) {
    try {
      return store.listNamespaces(AppDataRecord.normalizeAppId(appId));
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private List<AppDataRecord> listStoredRecords(String appId, String namespace) {
    try {
      return store.listRecords(AppDataRecord.normalizeAppId(appId), namespace).stream()
          .sorted(Comparator.comparing(AppDataRecord::namespace).thenComparing(AppDataRecord::key))
          .toList();
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private List<AppDataRecordSummary> listStoredRecordSummaries(String appId, String namespace) {
    try {
      return store.listRecordSummaries(AppDataRecord.normalizeAppId(appId), namespace).stream()
          .sorted(
              Comparator.comparing(AppDataRecordSummary::namespace)
                  .thenComparing(AppDataRecordSummary::key))
          .toList();
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private AppDataNamespaceMetadata readNamespaceRequired(String appId, String namespace) {
    return readNamespaceOptional(appId, namespace)
        .orElseThrow(
            () ->
                new PlatformApiException(
                    404, "app_data_namespace_not_found", "App-data namespace not found."));
  }

  private Optional<AppDataNamespaceMetadata> readNamespaceOptional(String appId, String namespace) {
    try {
      return store.readNamespace(
          AppDataRecord.normalizeAppId(appId), AppDataRecord.normalizeNamespace(namespace));
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private AppDataRecord readRecordRequired(String appId, String namespace, String key) {
    return readRecordOptional(appId, namespace, key)
        .orElseThrow(
            () ->
                new PlatformApiException(
                    404, "app_data_record_not_found", "App-data record not found."));
  }

  private Optional<AppDataRecord> readRecordOptional(String appId, String namespace, String key) {
    try {
      return store.readRecord(
          AppDataRecord.normalizeAppId(appId),
          AppDataRecord.normalizeNamespace(namespace),
          AppDataRecord.normalizeKey(key));
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private void writeNamespace(AppDataNamespaceMetadata metadata) {
    try {
      store.writeNamespace(metadata);
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private void writeRecord(AppDataRecord appDataRecord) {
    try {
      store.writeRecord(appDataRecord);
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private void deleteStoredRecord(String appId, String namespace, String key) {
    try {
      store.deleteRecord(
          AppDataRecord.normalizeAppId(appId),
          AppDataRecord.normalizeNamespace(namespace),
          AppDataRecord.normalizeKey(key));
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private void deleteStoredNamespace(String appId, String namespace) {
    try {
      store.deleteNamespace(
          AppDataRecord.normalizeAppId(appId), AppDataRecord.normalizeNamespace(namespace));
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private static ValueInput valueInput(Map<String, List<String>> parameters) {
    String valueBase64 = PlatformApiParameters.readOptionalString(parameters, PARAM_VALUE_BASE64);
    String valueText = PlatformApiParameters.readOptionalString(parameters, PARAM_VALUE_TEXT);
    String valueJson = PlatformApiParameters.readOptionalString(parameters, PARAM_VALUE_JSON);
    int supplied =
        (valueBase64 == null ? 0 : 1) + (valueText == null ? 0 : 1) + (valueJson == null ? 0 : 1);
    if (supplied != 1) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "Exactly one app-data value field must be supplied.");
    }
    if (valueBase64 != null) {
      return new ValueInput(
          contentTypeOrDefault(parameters, AppDataRecord.DEFAULT_CONTENT_TYPE),
          decodeBase64(valueBase64, PARAM_VALUE_BASE64));
    }
    if (valueJson != null) {
      return new ValueInput(
          contentTypeOrDefault(parameters, AppDataRecord.JSON_CONTENT_TYPE),
          valueJson.getBytes(StandardCharsets.UTF_8));
    }
    return new ValueInput(
        contentTypeOrDefault(parameters, "text/plain;charset=utf-8"),
        valueText.getBytes(StandardCharsets.UTF_8));
  }

  private static String contentTypeOrDefault(
      Map<String, List<String>> parameters, String defaultContentType) {
    String supplied = PlatformApiParameters.readOptionalString(parameters, PARAM_CONTENT_TYPE);
    return AppDataRecord.normalizeContentType(supplied == null ? defaultContentType : supplied);
  }

  private static byte[] decodeRequiredPayloadBase64(Map<String, List<String>> parameters) {
    return decodeBase64(
        PlatformApiParameters.requireString(parameters, PARAM_PAYLOAD_BASE64),
        PARAM_PAYLOAD_BASE64);
  }

  private static byte[] decodeBase64(String value, String parameterName) {
    try {
      return Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException _) {
      try {
        return Base64.getUrlDecoder().decode(value);
      } catch (IllegalArgumentException _) {
        throw new PlatformApiException(
            400,
            "invalid_query_parameter",
            "Query parameter '" + parameterName + "' must be valid base64.");
      }
    }
  }

  private static int readLimit(Map<String, List<String>> parameters) {
    String raw = PlatformApiParameters.readOptionalString(parameters, PARAM_LIMIT);
    if (raw == null || raw.isBlank()) {
      return 100;
    }
    int limit = readPositiveInt(raw, PARAM_LIMIT);
    if (limit > 500) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "Query parameter 'limit' exceeds the app-data bound.");
    }
    return limit;
  }

  private static int readCursor(Map<String, List<String>> parameters) {
    String raw = PlatformApiParameters.readOptionalString(parameters, PARAM_CURSOR);
    if (raw == null || raw.isBlank()) {
      return 0;
    }
    try {
      int cursor = Integer.parseInt(raw.trim());
      if (cursor >= 0) {
        return cursor;
      }
    } catch (NumberFormatException _) {
      // handled below
    }
    throw new PlatformApiException(
        400,
        "invalid_query_parameter",
        "Query parameter '" + PARAM_CURSOR + "' must be a non-negative integer.");
  }

  private static int readRequiredPositiveInt(Map<String, List<String>> parameters, String name) {
    String raw = PlatformApiParameters.requireString(parameters, name);
    return readPositiveInt(raw, name);
  }

  private static int readPositiveInt(String raw, String name) {
    try {
      int parsed = Integer.parseInt(raw.trim());
      if (parsed > 0) {
        return parsed;
      }
    } catch (NumberFormatException _) {
      // handled below
    }
    throw new PlatformApiException(
        400,
        "invalid_query_parameter",
        "Query parameter '" + name + "' must be a positive integer.");
  }

  private static AppDataRecord withCallerAppId(AppDataRecord appDataRecord, String appId) {
    return new AppDataRecord(
        appId,
        appDataRecord.namespace(),
        appDataRecord.key(),
        new AppDataRecord.Payload(
            appDataRecord.contentType(), appDataRecord.schemaVersion(), appDataRecord.value()),
        appDataRecord.createdAt(),
        appDataRecord.updatedAt());
  }

  private static AppDataNamespaceMetadata withCallerAppId(
      AppDataNamespaceMetadata metadata, String appId) {
    return new AppDataNamespaceMetadata(
        appId,
        metadata.namespace(),
        metadata.schemaVersion(),
        metadata.recordCount(),
        metadata.totalBytes(),
        metadata.createdAt(),
        metadata.updatedAt(),
        metadata.lastMigrationAt(),
        metadata.migrationHistory());
  }

  private static AppDataNamespaceMetadata withImportedRecordTotals(
      AppDataNamespaceMetadata metadata, List<AppDataRecord> importedRecords) {
    int recordCount = 0;
    long totalBytes = 0L;
    for (AppDataRecord appDataRecord : importedRecords) {
      if (metadata.namespace().equals(appDataRecord.namespace())) {
        recordCount++;
        totalBytes += appDataRecord.valueBytes();
      }
    }
    return metadata.withTotals(recordCount, totalBytes, metadata.updatedAt());
  }

  private static PlatformApiException quotaExceeded() {
    return new PlatformApiException(
        400, "app_data_quota_exceeded", "App-data quota would be exceeded.");
  }

  private static PlatformApiException storeUnavailable() {
    return new PlatformApiException(
        503, "app_data_store_unavailable", "App-data store is unavailable.");
  }

  private record UpdateMigrationPayload(
      List<AppDataNamespaceMetadata> importedNamespacesMetadata,
      List<AppDataRecord> importedRecords,
      Set<String> importedNamespaces) {}

  private record ProjectedImport(Map<String, Long> recordBytesByKey, Set<String> namespaces) {
    private ProjectedImport {
      recordBytesByKey = Map.copyOf(Objects.requireNonNull(recordBytesByKey, "recordBytesByKey"));
      namespaces = Set.copyOf(Objects.requireNonNull(namespaces, "namespaces"));
    }
  }

  private record ManifestQuotaCheck(boolean useOverride, Long quotaBytes) {
    private static ManifestQuotaCheck installedManifest() {
      return new ManifestQuotaCheck(false, null);
    }

    private static ManifestQuotaCheck targetManifest(Long quotaBytes) {
      return new ManifestQuotaCheck(true, quotaBytes);
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class ValueInput {
    private final String storedContentType;
    private final byte[] storedValue;

    private ValueInput(String contentType, byte[] value) {
      storedContentType = Objects.requireNonNull(contentType, PARAM_CONTENT_TYPE);
      storedValue = Objects.requireNonNull(value, "value").clone();
    }

    private String contentType() {
      return storedContentType;
    }

    private byte[] value() {
      return storedValue.clone();
    }
  }
}
