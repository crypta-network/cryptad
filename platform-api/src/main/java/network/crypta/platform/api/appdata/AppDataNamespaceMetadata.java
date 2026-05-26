package network.crypta.platform.api.appdata;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * App-data namespace metadata derived from durable records and schema state.
 *
 * <p>A namespace groups logical records for one app. Metadata is scoped by app id, but app-facing
 * namespace responses omit host paths and include only the app id already bound to the caller,
 * schema version, byte/count totals, timestamps, and bounded migration history.
 *
 * <p>The file-backed store persists namespace metadata separately from individual record values,
 * while the service derives current {@code recordCount}, {@code totalBytes}, and effective {@code
 * updatedAt} values from record summaries when it serves status, namespace, and export responses.
 * That keeps summary routes metadata-only and avoids reading every value just to answer namespace
 * queries.
 *
 * <p>Instances are immutable value objects. Methods such as {@link #withTotals(int, long, Instant)}
 * and {@link #withMigration(AppDataMigrationRecord, int)} return replacement metadata rather than
 * mutating the current instance, which makes in-memory tests and file-store writes use the same
 * state transition model.
 *
 * @param appId normalized owner app id for this namespace
 * @param namespace normalized namespace label within the owning app
 * @param schemaVersion current positive namespace schema version
 * @param recordCount number of records currently in the namespace
 * @param totalBytes total value bytes currently stored in the namespace
 * @param createdAt time when the namespace metadata was first created
 * @param updatedAt time when records or namespace metadata last changed
 * @param lastMigrationAt time of the most recent recorded migration, or {@code null}
 * @param migrationHistory bounded namespace migration metadata in recorded order
 */
public record AppDataNamespaceMetadata(
    String appId,
    String namespace,
    int schemaVersion,
    int recordCount,
    long totalBytes,
    Instant createdAt,
    Instant updatedAt,
    Instant lastMigrationAt,
    List<AppDataMigrationRecord> migrationHistory) {
  /**
   * Creates a validated namespace metadata value.
   *
   * <p>The constructor normalizes app and namespace identifiers, checks that counters cannot become
   * negative, and defensively copies migration history. It does not enforce the service-level
   * migration-history cap; import and schema-update paths perform that policy check before writing
   * metadata.
   *
   * @throws IllegalArgumentException if identifiers are invalid or numeric fields are out of range
   * @throws NullPointerException if required timestamps or migration history are {@code null}
   */
  public AppDataNamespaceMetadata {
    appId = AppDataRecord.normalizeAppId(appId);
    namespace = AppDataRecord.normalizeNamespace(namespace);
    if (schemaVersion <= 0) {
      throw new IllegalArgumentException("schemaVersion must be positive");
    }
    if (recordCount < 0) {
      throw new IllegalArgumentException("recordCount must be non-negative");
    }
    if (totalBytes < 0L) {
      throw new IllegalArgumentException("totalBytes must be non-negative");
    }
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    migrationHistory = List.copyOf(Objects.requireNonNull(migrationHistory, "migrationHistory"));
  }

  /**
   * Returns this metadata with current count and byte totals.
   *
   * <p>Stores use this method when composing namespace responses from persisted metadata plus
   * current record summaries. The schema version, creation timestamp, last migration timestamp, and
   * migration history are preserved exactly; only the derived totals and externally visible update
   * timestamp change.
   *
   * @param newRecordCount current non-negative record count
   * @param newTotalBytes current non-negative total value bytes
   * @param newUpdatedAt updated timestamp to expose for this namespace
   * @return metadata value carrying the supplied derived totals
   */
  public AppDataNamespaceMetadata withTotals(
      int newRecordCount, long newTotalBytes, Instant newUpdatedAt) {
    return new AppDataNamespaceMetadata(
        appId,
        namespace,
        schemaVersion,
        newRecordCount,
        newTotalBytes,
        createdAt,
        newUpdatedAt,
        lastMigrationAt,
        migrationHistory);
  }

  /**
   * Returns this metadata after recording a schema migration.
   *
   * <p>The returned value adopts the migration's target schema version, records the migration time
   * as both {@code updatedAt} and {@code lastMigrationAt}, and trims the oldest history entries
   * when the configured cap is exceeded. Record counts and value bytes are left unchanged because
   * schema metadata updates do not by themselves prove that app-owned records were rewritten.
   *
   * @param migration migration metadata to append to the namespace history
   * @param maxHistory positive maximum retained migration records
   * @return metadata with updated schema version and bounded history
   */
  public AppDataNamespaceMetadata withMigration(AppDataMigrationRecord migration, int maxHistory) {
    Objects.requireNonNull(migration, "migration");
    if (maxHistory <= 0) {
      throw new IllegalArgumentException("maxHistory must be positive");
    }
    java.util.ArrayList<AppDataMigrationRecord> history =
        new java.util.ArrayList<>(migrationHistory);
    history.add(migration);
    while (history.size() > maxHistory) {
      history.removeFirst();
    }
    return new AppDataNamespaceMetadata(
        appId,
        namespace,
        migration.toSchemaVersion(),
        recordCount,
        totalBytes,
        createdAt,
        migration.migratedAt(),
        migration.migratedAt(),
        history);
  }

  /**
   * Converts this metadata to a deterministic JSON-compatible map.
   *
   * <p>List endpoints can omit migration history for smaller metadata summaries, while namespace
   * reads and exports include it for migration-aware apps. Both forms are path-free and contain no
   * record values.
   *
   * @param includeMigrationHistory whether to include bounded migration history entries
   * @return path-free namespace metadata in stable field order
   */
  public Map<String, Object> toJsonValue(boolean includeMigrationHistory) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put("appId", appId);
    json.put("namespace", namespace);
    json.put("schemaVersion", schemaVersion);
    json.put("recordCount", recordCount);
    json.put("totalBytes", totalBytes);
    json.put("createdAt", createdAt.toString());
    json.put("updatedAt", updatedAt.toString());
    json.put("lastMigrationAt", lastMigrationAt == null ? null : lastMigrationAt.toString());
    if (includeMigrationHistory) {
      json.put(
          "migrationHistory",
          migrationHistory.stream().map(AppDataMigrationRecord::toJsonValue).toList());
    }
    return json;
  }
}
