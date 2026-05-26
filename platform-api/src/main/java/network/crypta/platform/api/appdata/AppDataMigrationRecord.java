package network.crypta.platform.api.appdata;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Path-free metadata describing one app-declared namespace schema transition.
 *
 * <p>The platform never executes app-provided migration code. A migration record only captures the
 * app's declared schema movement and a bounded human-readable summary so app updates can coordinate
 * their own durable state changes across restarts. Summaries are sanitized into a single line and
 * are safe for app-facing API responses, but callers should still avoid putting secrets, private
 * insert URIs, raw request bodies, or local filesystem details into them.
 *
 * <p>Schema versions are positive integers and must move forward or stay equal. Equal versions are
 * useful when an app wants to annotate a metadata refresh without claiming that record values have
 * changed schema. Downgrades are rejected because the platform cannot prove that app-owned record
 * values were transformed safely.
 *
 * <p>Instances are immutable after construction. The summary is normalized before storage, and the
 * timestamp is supplied by the service layer for locally recorded migrations or by a validated
 * import payload during restore.
 *
 * @param fromSchemaVersion positive schema version the app migrated from
 * @param toSchemaVersion positive schema version the app migrated to
 * @param summary bounded app-supplied summary of the migration, normalized to one line
 * @param migratedAt time when the platform recorded or imported the migration metadata
 */
public record AppDataMigrationRecord(
    int fromSchemaVersion, int toSchemaVersion, String summary, Instant migratedAt) {
  private static final int MAX_SUMMARY_LENGTH = 240;

  /**
   * Creates a validated migration metadata record.
   *
   * <p>The constructor enforces positive, non-decreasing schema versions and normalizes the summary
   * into the bounded one-line form returned by app-data status, namespace, and export responses.
   *
   * @throws IllegalArgumentException if schema versions are non-positive or represent a downgrade
   * @throws NullPointerException if {@code migratedAt} is {@code null}
   */
  public AppDataMigrationRecord {
    if (fromSchemaVersion <= 0) {
      throw new IllegalArgumentException("fromSchemaVersion must be positive");
    }
    if (toSchemaVersion <= 0) {
      throw new IllegalArgumentException("toSchemaVersion must be positive");
    }
    if (toSchemaVersion < fromSchemaVersion) {
      throw new IllegalArgumentException("schema version downgrades are not supported");
    }
    summary = boundedSingleLine(summary);
    Objects.requireNonNull(migratedAt, "migratedAt");
  }

  /**
   * Converts this migration to a deterministic JSON-compatible map.
   *
   * <p>The map is the representation used both by namespace responses and app-data exports. It
   * contains only schema numbers, the bounded summary, and the recorded timestamp; it never exposes
   * host paths or app record values.
   *
   * @return path-free migration metadata in stable field order
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("fromSchemaVersion", fromSchemaVersion);
    json.put("toSchemaVersion", toSchemaVersion);
    json.put("summary", summary);
    json.put("migratedAt", migratedAt.toString());
    return json;
  }

  /**
   * Normalizes migration summaries into the stored single-line form.
   *
   * <p>This helper is package-visible so import parsing and tests can use the same summary
   * sanitation behavior as the record constructor without duplicating the length cap. It removes
   * line breaks, trims outer whitespace, and truncates overlong summaries.
   *
   * @param value summary text supplied by an app or import payload
   * @return bounded one-line summary safe for metadata responses
   */
  static String boundedSingleLine(String value) {
    String normalized = value == null ? "" : value.replace('\r', ' ').replace('\n', ' ').trim();
    if (normalized.length() > MAX_SUMMARY_LENGTH) {
      return normalized.substring(0, MAX_SUMMARY_LENGTH);
    }
    return normalized;
  }
}
