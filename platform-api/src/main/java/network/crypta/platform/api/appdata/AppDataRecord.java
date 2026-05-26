package network.crypta.platform.api.appdata;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Durable app-owned record stored under one app-data namespace.
 *
 * <p>The logical key is app-visible metadata, not a filesystem path. File-backed stores hash the
 * key before it becomes an on-disk directory name, so a record can never request an absolute path,
 * traversal segment, symlink target, or host source path. Values are returned only to the owning
 * app through read/export routes; list/status responses expose summaries, byte counts, hashes, and
 * timestamps instead of raw values.
 *
 * <p>A record is immutable after construction. The constructor normalizes identifiers and content
 * type, copies the supplied value bytes, and requires service-provided timestamps. It does not
 * perform quota checks because quota decisions need store-wide context; callers must run the
 * service preflight before writing records to a store.
 *
 * <p>Record values are not secrets. Apps may store bounded local state such as drafts, feed source
 * metadata, read markers, and UI selections, but private keys, identity seeds, browser-session
 * tokens, and private insert URIs belong outside this model.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class AppDataRecord {
  /**
   * Default content type when a request supplies only base64 bytes.
   *
   * <p>The default avoids implying text encoding when an app uses {@code valueBase64}. SDK helpers
   * that write JSON records set {@link #JSON_CONTENT_TYPE} explicitly.
   */
  public static final String DEFAULT_CONTENT_TYPE = "application/octet-stream";

  /**
   * JSON content type used by SDK convenience helpers.
   *
   * <p>Records with this content type are returned with both {@code valueBase64} and {@code
   * valueText} when read by the owning app.
   */
  public static final String JSON_CONTENT_TYPE = "application/json";

  private static final HexFormat HEX = HexFormat.of();
  private static final Pattern SAFE_SEGMENT = Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final int MAX_NAMESPACE_LENGTH = 64;
  private static final int MAX_KEY_LENGTH = 128;
  private static final int MAX_CONTENT_TYPE_LENGTH = 120;
  private static final String FIELD_CONTENT_TYPE = "contentType";

  private final String appId;
  private final String namespace;
  private final String key;
  private final String contentType;
  private final int schemaVersion;
  private final byte[] value;
  private final Instant createdAt;
  private final Instant updatedAt;

  /**
   * Immutable value metadata and bytes for an app-data record.
   *
   * <p>The payload groups the fields that describe and carry the record value. Keeping them
   * together makes construction call sites less error-prone: the schema version and content type
   * travel with the byte array they describe. The payload performs the same validation as the
   * enclosing record and defensively copies value bytes on construction and access.
   */
  public static final class Payload {
    private final String contentType;
    private final int schemaVersion;
    private final byte[] value;

    /**
     * Creates a validated record payload.
     *
     * @param contentType bounded media type supplied by the app
     * @param schemaVersion positive record schema version declared by the app
     * @param value stored value bytes, defensively copied on construction and access
     * @throws PlatformApiException if the content type is invalid
     * @throws IllegalArgumentException if {@code schemaVersion} is not positive
     * @throws NullPointerException if value bytes are {@code null}
     */
    public Payload(String contentType, int schemaVersion, byte[] value) {
      this.contentType = normalizeContentType(contentType);
      if (schemaVersion <= 0) {
        throw new IllegalArgumentException("schemaVersion must be positive");
      }
      this.schemaVersion = schemaVersion;
      this.value = Arrays.copyOf(Objects.requireNonNull(value, "value"), value.length);
    }

    /**
     * Returns the normalized content type for the stored value.
     *
     * @return bounded media type supplied by the app or defaulted by the service
     */
    public String contentType() {
      return contentType;
    }

    /**
     * Returns the positive app-declared schema version for this payload.
     *
     * @return positive record schema version
     */
    public int schemaVersion() {
      return schemaVersion;
    }

    /**
     * Returns a defensive copy of the payload bytes.
     *
     * @return copy of the bounded stored value bytes
     */
    public byte[] value() {
      return Arrays.copyOf(value, value.length);
    }
  }

  /**
   * Creates a validated durable app-data record.
   *
   * <p>The constructor is intentionally strict about identifiers because the same model is used by
   * in-memory tests, file-store persistence, imports, and API writes. Values are accepted as
   * already bounded byte arrays; oversized records are rejected by {@link AppDataService} before
   * construction reaches a store write.
   *
   * @param appId normalized owner app id
   * @param namespace normalized namespace label within the app
   * @param key normalized logical record key visible to the app
   * @param payload value metadata and bytes, defensively copied on construction and access
   * @param createdAt record creation timestamp
   * @param updatedAt last successful write timestamp
   * @throws PlatformApiException if app id, namespace, key, or content type is invalid
   * @throws NullPointerException if payload or timestamps are {@code null}
   */
  public AppDataRecord(
      String appId,
      String namespace,
      String key,
      Payload payload,
      Instant createdAt,
      Instant updatedAt) {
    Payload checkedPayload = Objects.requireNonNull(payload, "payload");
    this.appId = normalizeAppId(appId);
    this.namespace = normalizeNamespace(namespace);
    this.key = normalizeKey(key);
    contentType = checkedPayload.contentType();
    schemaVersion = checkedPayload.schemaVersion();
    value = checkedPayload.value();
    this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
    this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt");
  }

  /**
   * Returns the normalized app id that owns this record.
   *
   * @return normalized owner app id
   */
  public String appId() {
    return appId;
  }

  /**
   * Returns the normalized namespace containing this record.
   *
   * @return normalized namespace label within the app
   */
  public String namespace() {
    return namespace;
  }

  /**
   * Returns the normalized logical key for this record.
   *
   * @return normalized logical record key visible to the app
   */
  public String key() {
    return key;
  }

  /**
   * Returns the normalized content type for the stored value.
   *
   * @return bounded media type supplied by the app or defaulted by the service
   */
  public String contentType() {
    return contentType;
  }

  /**
   * Returns the positive app-declared schema version for this record.
   *
   * @return positive record schema version
   */
  public int schemaVersion() {
    return schemaVersion;
  }

  /**
   * Returns a defensive copy of the stored value bytes.
   *
   * <p>Callers that need to expose the value through an API response should still rely on {@link
   * #toReadJson()} so the response includes consistent metadata, base64 encoding, and content-type
   * handling. The copy keeps the record immutable even when callers mutate the returned array.
   *
   * @return copy of the bounded stored value bytes
   */
  public byte[] value() {
    return Arrays.copyOf(value, value.length);
  }

  /**
   * Returns the timestamp when this record was first created.
   *
   * @return record creation timestamp
   */
  public Instant createdAt() {
    return createdAt;
  }

  /**
   * Returns the timestamp of the last successful write.
   *
   * @return last successful write timestamp
   */
  public Instant updatedAt() {
    return updatedAt;
  }

  /**
   * Returns the byte length of this record's value.
   *
   * @return non-negative stored value length
   */
  public int valueBytes() {
    return value.length;
  }

  /**
   * Returns the SHA-256 digest of this record's value as lowercase hex.
   *
   * @return value digest suitable for summaries and optimistic writes
   */
  public String sha256() {
    return sha256(value);
  }

  /**
   * Returns a deterministic summary map without raw value bytes.
   *
   * <p>The summary representation is used by list, status, quota preflight, and export-size
   * preflight paths. It exposes enough metadata for sync and optimistic writes without forcing the
   * caller to load or disclose the value itself.
   *
   * @return path-free record summary with digest, byte count, schema, and timestamps
   */
  public Map<String, Object> toSummaryJson() {
    return AppDataRecordSummary.from(this).toJsonValue();
  }

  /**
   * Returns a deterministic read response map including the bounded value.
   *
   * <p>The map always includes {@code valueBase64}. It also includes {@code valueText} for JSON and
   * text media types when the bytes are valid UTF-8, which keeps binary and textual callers on the
   * same route without guessing from host state.
   *
   * @return record metadata and value for the owning app
   */
  public Map<String, Object> toReadJson() {
    LinkedHashMap<String, Object> json = new LinkedHashMap<>(toSummaryJson());
    json.put("valueBase64", Base64.getEncoder().encodeToString(value));
    if (isTextContentType(contentType)) {
      json.put("valueText", new String(value, StandardCharsets.UTF_8));
    }
    return json;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof AppDataRecord that)) {
      return false;
    }
    return schemaVersion == that.schemaVersion
        && appId.equals(that.appId)
        && namespace.equals(that.namespace)
        && key.equals(that.key)
        && contentType.equals(that.contentType)
        && Arrays.equals(value, that.value)
        && createdAt.equals(that.createdAt)
        && updatedAt.equals(that.updatedAt);
  }

  @Override
  public int hashCode() {
    int result =
        Objects.hash(appId, namespace, key, contentType, schemaVersion, createdAt, updatedAt);
    result = 31 * result + Arrays.hashCode(value);
    return result;
  }

  @Override
  public String toString() {
    return "AppDataRecord[appId="
        + appId
        + ", namespace="
        + namespace
        + ", key="
        + key
        + ", contentType="
        + contentType
        + ", schemaVersion="
        + schemaVersion
        + ", valueBytes="
        + value.length
        + ", sha256="
        + sha256()
        + ", createdAt="
        + createdAt
        + ", updatedAt="
        + updatedAt
        + "]";
  }

  /**
   * Normalizes an AppHost app id for store scoping.
   *
   * <p>This method delegates to {@link AppManifest#normalizeAppId(String)} so durable app-data
   * records use the same app-id rules as installed app manifests and AppHost runtime state.
   * Failures are converted to the app-data identifier error code used by API responses.
   *
   * @param appId app id to normalize for store scoping
   * @return normalized path-safe app id
   */
  public static String normalizeAppId(String appId) {
    try {
      return AppManifest.normalizeAppId(appId);
    } catch (RuntimeException _) {
      throw new PlatformApiException(400, "invalid_app_data_identifier", "Invalid app id.");
    }
  }

  /**
   * Normalizes and validates one namespace label.
   *
   * <p>Namespaces are lowercase safe segments with a fixed maximum length. They group records for
   * app-side schemas and migration metadata, but they are not trusted as host filesystem names.
   *
   * @param namespace namespace supplied by the app
   * @return normalized safe namespace
   */
  public static String normalizeNamespace(String namespace) {
    return normalizeSafeSegment(namespace, MAX_NAMESPACE_LENGTH, "namespace");
  }

  /**
   * Normalizes and validates one logical record key.
   *
   * <p>Keys are app-visible logical identifiers. File-backed stores hash them before using them in
   * directory names, but the model still bounds and normalizes them so API responses and exports
   * stay predictable.
   *
   * @param key logical key supplied by the app
   * @return normalized safe key
   */
  public static String normalizeKey(String key) {
    return normalizeSafeSegment(key, MAX_KEY_LENGTH, "key");
  }

  /**
   * Normalizes and validates one content type token.
   *
   * <p>The accepted token is intentionally simple: it is lowercased, bounded, must contain a slash,
   * and must not contain control characters or quoting characters that would make JSON or evidence
   * output ambiguous. Blank values fall back to {@link #DEFAULT_CONTENT_TYPE}.
   *
   * @param contentType content type supplied by the app, or blank for the default
   * @return bounded normalized content type
   */
  public static String normalizeContentType(String contentType) {
    String normalized =
        contentType == null || contentType.isBlank()
            ? DEFAULT_CONTENT_TYPE
            : contentType.trim().toLowerCase(Locale.ROOT);
    if (normalized.length() > MAX_CONTENT_TYPE_LENGTH) {
      throw invalidIdentifier(FIELD_CONTENT_TYPE);
    }
    for (int index = 0; index < normalized.length(); index++) {
      char ch = normalized.charAt(index);
      if (ch <= 0x20 || ch == '"' || ch == '\\') {
        throw invalidIdentifier(FIELD_CONTENT_TYPE);
      }
    }
    if (!normalized.contains("/")) {
      throw invalidIdentifier(FIELD_CONTENT_TYPE);
    }
    return normalized;
  }

  /**
   * Returns the SHA-256 digest of arbitrary bytes as lowercase hex.
   *
   * <p>The digest appears in record summaries, export metadata, and optimistic-write preconditions.
   * It is a value integrity identifier, not a secret or access token.
   *
   * @param bytes bytes to hash
   * @return lowercase SHA-256 digest
   */
  public static String sha256(byte[] bytes) {
    try {
      return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static boolean isTextContentType(String value) {
    return value.startsWith("text/") || JSON_CONTENT_TYPE.equals(value) || value.endsWith("+json");
  }

  private static String normalizeSafeSegment(String value, int maxLength, String fieldName) {
    String normalized = Objects.requireNonNull(value, fieldName).trim().toLowerCase(Locale.ROOT);
    if (normalized.length() > maxLength || !SAFE_SEGMENT.matcher(normalized).matches()) {
      throw invalidIdentifier(fieldName);
    }
    return normalized;
  }

  private static PlatformApiException invalidIdentifier(String fieldName) {
    return new PlatformApiException(
        400,
        "invalid_app_data_identifier",
        "App data " + fieldName + " must be a bounded normalized identifier.");
  }
}
