package network.crypta.platform.api.appdata;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Path-free summary of one durable app-data record.
 *
 * <p>Record summaries are used by list, status, export evidence, and certification checks. They
 * include the logical app-owned key, byte length, schema version, content type, SHA-256 digest, and
 * timestamps, but never include raw values, request bodies, filesystem paths, tokens, or secret
 * material.
 *
 * <p>The file-backed store can construct summaries from record metadata without reading {@code
 * value.bin}. That distinction matters for bounded API behavior: summary routes and quota preflight
 * can handle many records without materializing every app-owned value in the daemon heap.
 *
 * <p>The SHA-256 digest is a stable value identifier used for summaries, export metadata, and
 * optimistic write preconditions. It is not an authorization token and does not make record values
 * secret.
 *
 * @param namespace namespace that owns the record
 * @param key logical app-owned key
 * @param contentType stored content type
 * @param schemaVersion positive record schema version
 * @param valueBytes stored value byte length
 * @param sha256 lowercase SHA-256 digest of the value
 * @param createdAt record creation time
 * @param updatedAt last successful write time
 */
public record AppDataRecordSummary(
    String namespace,
    String key,
    String contentType,
    int schemaVersion,
    int valueBytes,
    String sha256,
    Instant createdAt,
    Instant updatedAt) {
  /**
   * Creates a validated summary.
   *
   * <p>Identifier and content-type validation matches {@link AppDataRecord}, so summaries remain
   * safe to expose in app-facing responses even when they were reconstructed from store metadata.
   *
   * @throws network.crypta.platform.api.PlatformApiException if namespace, key, or content type is
   *     invalid
   * @throws IllegalArgumentException if schema version or value length is out of range
   * @throws NullPointerException if digest or timestamps are {@code null}
   */
  public AppDataRecordSummary {
    namespace = AppDataRecord.normalizeNamespace(namespace);
    key = AppDataRecord.normalizeKey(key);
    contentType = AppDataRecord.normalizeContentType(contentType);
    if (schemaVersion <= 0) {
      throw new IllegalArgumentException("schemaVersion must be positive");
    }
    if (valueBytes < 0) {
      throw new IllegalArgumentException("valueBytes must be non-negative");
    }
    Objects.requireNonNull(sha256, "sha256");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
  }

  /**
   * Builds a summary from a full record.
   *
   * <p>This helper is used when the service already has a full record, such as immediately after a
   * writing or during export serialization. Summary-only store paths should prefer constructing
   * this value from metadata so values do not need to be read.
   *
   * @param appDataRecord durable record whose value digest and metadata should be summarized
   * @return path-free record summary
   */
  public static AppDataRecordSummary from(AppDataRecord appDataRecord) {
    Objects.requireNonNull(appDataRecord, "appDataRecord");
    return new AppDataRecordSummary(
        appDataRecord.namespace(),
        appDataRecord.key(),
        appDataRecord.contentType(),
        appDataRecord.schemaVersion(),
        appDataRecord.valueBytes(),
        appDataRecord.sha256(),
        appDataRecord.createdAt(),
        appDataRecord.updatedAt());
  }

  /**
   * Converts this summary to a deterministic JSON-compatible map.
   *
   * <p>The map shape is shared by list responses, read responses, and export record metadata. Read
   * responses add value fields on top of this map; summary responses do not.
   *
   * @return path-free record summary in stable field order
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("namespace", namespace);
    json.put("key", key);
    json.put("contentType", contentType);
    json.put("schemaVersion", schemaVersion);
    json.put("valueBytes", valueBytes);
    json.put("sha256", sha256);
    json.put("createdAt", createdAt.toString());
    json.put("updatedAt", updatedAt.toString());
    return json;
  }
}
