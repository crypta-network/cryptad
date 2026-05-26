package network.crypta.platform.api.appdata;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Structured JSON export payload for one app's bounded durable data.
 *
 * <p>The payload is the durable app-data interchange format used by {@code GET /app-data/export}
 * and {@code POST /app-data/import}. It is intentionally narrow: it carries namespace metadata and
 * record values for one app, not a filesystem snapshot, database dump, vault export, or trust graph
 * replication stream. Values are encoded as base64 so the JSON format can represent binary records
 * without requiring transport-specific escaping rules.
 *
 * <p>The serialized map is deterministic enough for tests, release evidence, and backup tooling:
 * namespace and record lists are sorted during parsing, counts are included as explicit metadata,
 * and timestamps are formatted as ISO-8601 instants. Import still revalidates every app id,
 * namespace, key, content type, schema version, and migration entry through the model constructors
 * and service preflight checks.
 *
 * <p>The payload never includes host paths, staging paths, browser-session tokens, raw request
 * bodies, private insert URIs, private keys, or vault material. Those values are outside the
 * durable app-data contract and must not be introduced into this format by future export versions.
 *
 * @param exportVersion payload schema version understood by this daemon
 * @param appId normalized app id, or {@code null} when an import payload intentionally omits it
 * @param exportedAt timestamp recorded by the exporting daemon
 * @param namespaces namespace metadata included in the payload
 * @param records exported records whose values are serialized as base64
 */
public record AppDataExportPayload(
    int exportVersion,
    String appId,
    Instant exportedAt,
    List<AppDataNamespaceMetadata> namespaces,
    List<AppDataRecord> records) {
  private static final String FIELD_APP_ID = "appId";
  private static final String FIELD_EXPORTED_AT = "exportedAt";
  private static final String FIELD_EXPORT_VERSION = "exportVersion";
  private static final String FIELD_NAMESPACES = "namespaces";
  private static final String FIELD_RECORDS = "records";
  private static final String FIELD_SCHEMA_VERSION = "schemaVersion";

  /**
   * Current export payload schema version.
   *
   * <p>Version {@code 1} represents the first PR-240 durable app-data interchange format. Bumping
   * this value requires an explicit parser branch so older exports either continue to import safely
   * or fail with {@code unsupported_app_data_export}.
   */
  public static final int CURRENT_EXPORT_VERSION = 1;

  /**
   * Creates a validated export payload.
   *
   * <p>The constructor normalizes the optional app id and takes defensive copies of namespace and
   * record lists. It does not rewrite record ownership to match {@code appId}; callers that import
   * untrusted payloads must still run the service-level app-id and quota preflight before
   * committing records.
   *
   * @throws PlatformApiException if the export version is not supported
   * @throws NullPointerException if required timestamp or list fields are {@code null}
   */
  public AppDataExportPayload {
    if (exportVersion != CURRENT_EXPORT_VERSION) {
      throw new PlatformApiException(
          400, "unsupported_app_data_export", "Unsupported app-data export version.");
    }
    if (appId != null) {
      appId = AppDataRecord.normalizeAppId(appId);
    }
    Objects.requireNonNull(exportedAt, FIELD_EXPORTED_AT);
    namespaces = List.copyOf(Objects.requireNonNull(namespaces, FIELD_NAMESPACES));
    records = List.copyOf(Objects.requireNonNull(records, FIELD_RECORDS));
  }

  /**
   * Converts this payload to a deterministic JSON-compatible map.
   *
   * <p>The returned map is safe to pass to {@link PlatformApiJsonWriter}. Record values are emitted
   * only as {@code valueBase64}, and namespace metadata uses the export form that includes bounded
   * migration history. The map is detached from the record's internal lists but still contains byte
   * content encoded for the owning app's export response.
   *
   * @return export payload map with metadata counts and base64 record values
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put(FIELD_EXPORT_VERSION, exportVersion);
    json.put(FIELD_APP_ID, appId);
    json.put(FIELD_EXPORTED_AT, exportedAt.toString());
    json.put("namespaceCount", namespaces.size());
    json.put("recordCount", records.size());
    json.put(
        FIELD_NAMESPACES,
        namespaces.stream().map(namespace -> namespace.toJsonValue(true)).toList());
    json.put(FIELD_RECORDS, records.stream().map(AppDataExportPayload::recordJson).toList());
    return json;
  }

  /**
   * Serializes this export payload to JSON bytes.
   *
   * <p>The Platform API import route measures the resulting UTF-8 byte length against the
   * configured export/import caps. Callers should use these bytes, or the URL-safe base64 wrapper
   * derived from them, rather than re-serializing arbitrary maps with a different field order.
   *
   * @return UTF-8 JSON export payload bytes
   */
  public byte[] toJsonBytes() {
    return PlatformApiJsonWriter.write(toJsonValue()).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Parses one JSON export payload.
   *
   * <p>The parser accepts the JSON shape produced by {@link #toJsonValue()} and rejects malformed
   * or unsupported input with the app-data import error vocabulary. When the top-level payload
   * omits {@code appId}, individual namespace and record entries may also omit it; the service will
   * later rewrite imported records to the caller's authenticated app id after cross-app checks
   * pass.
   *
   * @param bytes UTF-8 JSON payload bytes after transport-level base64 decoding
   * @return parsed export payload ready for service-level import preflight
   * @throws PlatformApiException if the payload is not valid app-data export JSON
   */
  public static AppDataExportPayload parse(byte[] bytes) {
    return parse(bytes, null);
  }

  /*
   * Parses an import for the authenticated caller. Top-level and per-entry app ids must either be
   * absent or match the caller; omitted entry ids are filled with the caller before the service
   * performs quota preflight and commits records.
   */
  static AppDataExportPayload parseForImport(byte[] bytes, String callerAppId) {
    return parse(bytes, AppDataRecord.normalizeAppId(callerAppId));
  }

  private static AppDataExportPayload parse(byte[] bytes, String callerAppId) {
    Object parsed = AppDataJsonParser.parse(new String(bytes, StandardCharsets.UTF_8));
    if (!(parsed instanceof Map<?, ?> map)) {
      throw invalidPayload();
    }
    int exportVersion = positiveInt(number(map.get(FIELD_EXPORT_VERSION)), FIELD_EXPORT_VERSION);
    String appId = stringOrNull(map.get(FIELD_APP_ID));
    if (appId != null) {
      appId = AppDataRecord.normalizeAppId(appId);
    }
    if (callerAppId != null && appId != null && !appId.equals(callerAppId)) {
      throw appMismatch();
    }
    String effectiveAppId = callerAppId == null ? appId : callerAppId;
    Instant exportedAt = instant(string(map.get(FIELD_EXPORTED_AT)));
    List<AppDataNamespaceMetadata> namespaces =
        namespaces(list(map.get(FIELD_NAMESPACES)), appId, callerAppId);
    List<AppDataRecord> records =
        records(list(map.get(FIELD_RECORDS)), appId, exportedAt, callerAppId);
    return new AppDataExportPayload(exportVersion, effectiveAppId, exportedAt, namespaces, records);
  }

  private static Map<String, Object> recordJson(AppDataRecord appDataRecord) {
    LinkedHashMap<String, Object> json = new LinkedHashMap<>(appDataRecord.toSummaryJson());
    json.put("valueBase64", Base64.getEncoder().encodeToString(appDataRecord.value()));
    return json;
  }

  private static List<AppDataNamespaceMetadata> namespaces(
      List<?> rawNamespaces, String appId, String callerAppId) {
    return rawNamespaces.stream()
        .map(item -> namespace(asMap(item), appId, callerAppId))
        .sorted(java.util.Comparator.comparing(AppDataNamespaceMetadata::namespace))
        .toList();
  }

  private static AppDataNamespaceMetadata namespace(
      Map<?, ?> map, String payloadAppId, String callerAppId) {
    String namespace = string(map.get("namespace"));
    String appId = entryAppId(payloadAppId, stringOrNull(map.get(FIELD_APP_ID)), callerAppId);
    if (appId == null) {
      appId = "import-app";
    }
    int schemaVersion = positiveInt(number(map.get(FIELD_SCHEMA_VERSION)), FIELD_SCHEMA_VERSION);
    Instant createdAt = instant(string(map.get("createdAt")));
    Instant updatedAt = instant(string(map.get("updatedAt")));
    List<AppDataMigrationRecord> migrationHistory =
        list(map.get("migrationHistory")).stream().map(item -> migration(asMap(item))).toList();
    Instant lastMigrationAt =
        migrationHistory.isEmpty() ? null : migrationHistory.getLast().migratedAt();
    return new AppDataNamespaceMetadata(
        appId,
        namespace,
        schemaVersion,
        0,
        0L,
        createdAt,
        updatedAt,
        lastMigrationAt,
        migrationHistory);
  }

  private static AppDataMigrationRecord migration(Map<?, ?> map) {
    int fromSchemaVersion = positiveInt(number(map.get("fromSchemaVersion")), "fromSchemaVersion");
    int toSchemaVersion = positiveInt(number(map.get("toSchemaVersion")), "toSchemaVersion");
    if (toSchemaVersion < fromSchemaVersion) {
      throw invalidPayload();
    }
    try {
      return new AppDataMigrationRecord(
          fromSchemaVersion,
          toSchemaVersion,
          stringOrEmpty(map.get("summary")),
          instant(string(map.get("migratedAt"))));
    } catch (IllegalArgumentException _) {
      throw invalidPayload();
    }
  }

  private static List<AppDataRecord> records(
      List<?> rawRecords, String appId, Instant fallbackAt, String callerAppId) {
    return rawRecords.stream()
        .map(item -> parseRecord(asMap(item), appId, fallbackAt, callerAppId))
        .sorted(
            java.util.Comparator.comparing(AppDataRecord::namespace)
                .thenComparing(AppDataRecord::key))
        .toList();
  }

  private static AppDataRecord parseRecord(
      Map<?, ?> map, String payloadAppId, Instant fallbackAt, String callerAppId) {
    String appId = entryAppId(payloadAppId, stringOrNull(map.get(FIELD_APP_ID)), callerAppId);
    if (appId == null) {
      appId = "import-app";
    }
    byte[] value;
    try {
      value = Base64.getDecoder().decode(requiredString(map.get("valueBase64")));
    } catch (IllegalArgumentException _) {
      throw invalidPayload();
    }
    Instant createdAt = optionalInstant(map.get("createdAt"), fallbackAt);
    Instant updatedAt = optionalInstant(map.get("updatedAt"), fallbackAt);
    return new AppDataRecord(
        appId,
        string(map.get("namespace")),
        string(map.get("key")),
        new AppDataRecord.Payload(
            string(map.get("contentType")),
            positiveInt(number(map.get(FIELD_SCHEMA_VERSION)), FIELD_SCHEMA_VERSION),
            value),
        createdAt,
        updatedAt);
  }

  private static String entryAppId(String payloadAppId, String declaredAppId, String callerAppId) {
    if (callerAppId == null) {
      return declaredAppId == null ? payloadAppId : declaredAppId;
    }
    if (declaredAppId != null && !AppDataRecord.normalizeAppId(declaredAppId).equals(callerAppId)) {
      throw appMismatch();
    }
    return callerAppId;
  }

  private static Map<?, ?> asMap(Object item) {
    if (item instanceof Map<?, ?> map) {
      return map;
    }
    throw invalidPayload();
  }

  private static List<?> list(Object item) {
    if (item == null) {
      return List.of();
    }
    if (item instanceof List<?> list) {
      return list;
    }
    throw invalidPayload();
  }

  private static Number number(Object item) {
    if (item instanceof Number number) {
      return number;
    }
    throw invalidPayload();
  }

  private static int positiveInt(Number number, String fieldName) {
    long value = number.longValue();
    if (value <= 0L || value > Integer.MAX_VALUE) {
      throw new PlatformApiException(
          400, "invalid_app_data_import", "Invalid app-data " + fieldName + ".");
    }
    return (int) value;
  }

  private static String string(Object item) {
    if (item instanceof String value && !value.isBlank()) {
      return value;
    }
    throw invalidPayload();
  }

  private static String requiredString(Object item) {
    if (item instanceof String value) {
      return value;
    }
    throw invalidPayload();
  }

  private static String stringOrNull(Object item) {
    if (item == null) {
      return null;
    }
    if (item instanceof String value && !value.isBlank()) {
      return value;
    }
    throw invalidPayload();
  }

  private static String stringOrEmpty(Object item) {
    if (item == null) {
      return "";
    }
    if (item instanceof String value) {
      return value;
    }
    throw invalidPayload();
  }

  private static Instant optionalInstant(Object item, Instant fallback) {
    return item == null ? fallback : instant(string(item));
  }

  private static Instant instant(String value) {
    try {
      return Instant.parse(value);
    } catch (RuntimeException _) {
      throw invalidPayload();
    }
  }

  private static PlatformApiException invalidPayload() {
    return new PlatformApiException(
        400, "invalid_app_data_import", "Invalid app-data import payload.");
  }

  private static PlatformApiException appMismatch() {
    return new PlatformApiException(
        403, "app_data_import_app_mismatch", "App-data import belongs to another app.");
  }
}
