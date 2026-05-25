package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
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
  private static final String FIELD_NAMESPACE_COUNT = "namespaceCount";
  private static final String FIELD_RECORD_COUNT = "recordCount";
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
    json.put("appId", normalizedAppId);
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
    AppDataRecord existing = readRecordRequired(appId, namespace, key);
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
    json.put("payloadBytes", payloadBytes.length);
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
    AppDataExportPayload payload = AppDataExportPayload.parse(payloadBytes);
    if (payload.appId() != null && !payload.appId().equals(normalizedAppId)) {
      throw new PlatformApiException(
          403, "app_data_import_app_mismatch", "App-data import belongs to another app.");
    }
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
    json.put("payloadBytes", payloadBytes.length);
    return json;
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
    try {
      store.deleteAllForApp(AppDataRecord.normalizeAppId(appId));
    } catch (IOException _) {
      throw storeUnavailable();
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
    json.put("appId", appId);
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
    manifestDelta += RECORD_METADATA_QUOTA_RESERVE_BYTES;
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
    enforceManifestQuota(appId, manifestDelta);
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
    if (positiveDeltaBytes <= 0L || appHost == null) {
      return;
    }
    InstalledAppSnapshot installed = installedApp(appId).orElse(null);
    if (installed == null) {
      return;
    }
    Long quotaBytes = installed.manifest().dataQuotaBytes();
    if (quotaBytes == null || quotaBytes <= 0L) {
      return;
    }
    AppDiskUsageScanner.ScanResult scan = diskUsageScanner.scan(installed.paths(), null);
    if (hasDataScanWarning(scan.warnings())) {
      throw new PlatformApiException(
          503, "app_data_quota_unavailable", "App-data quota could not be measured.");
    }
    if (manifestQuotaUsageBytes(appId, scan) + positiveDeltaBytes > quotaBytes) {
      throw quotaExceeded();
    }
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
          503, "app_data_quota_unavailable", "App-data quota could not be measured.");
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

  private static PlatformApiException quotaExceeded() {
    return new PlatformApiException(
        400, "app_data_quota_exceeded", "App-data quota would be exceeded.");
  }

  private static PlatformApiException storeUnavailable() {
    return new PlatformApiException(
        503, "app_data_store_unavailable", "App-data store is unavailable.");
  }

  private record ProjectedImport(Map<String, Long> recordBytesByKey, Set<String> namespaces) {
    private ProjectedImport {
      recordBytesByKey = Map.copyOf(Objects.requireNonNull(recordBytesByKey, "recordBytesByKey"));
      namespaces = Set.copyOf(Objects.requireNonNull(namespaces, "namespaces"));
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
