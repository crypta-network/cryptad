package network.crypta.platform.api.appdata;

import java.util.Objects;

/**
 * Runtime limits for the bounded app-scoped durable data store.
 *
 * <p>The limits are host policy, not app-provided metadata. They remain positive even when an app
 * manifest omits {@code quota.data.bytes} or declares {@code quota.data.bytes=0}, so every app-data
 * route has a platform-level bound before any manifest-specific quota is considered. The defaults
 * are intentionally small enough for browser/static app state such as drafts, read markers, UI
 * filters, and publish summaries, and intentionally unsuitable for a generic database or file
 * storage API.
 *
 * <p>The import and export defaults are also chosen to fit the current URL-encoded Platform API
 * bridge body cap after base64 expansion. Operators can raise these values through system
 * properties, but larger values should be paired with an HTTP bridge body limit that can actually
 * carry the resulting payload.
 *
 * <p>The store-level total value cap is derived from {@code maxRecordBytes * maxRecordsPerApp};
 * namespace count, record count, per-record bytes, import bytes, export bytes, and migration
 * history are enforced independently. Manifest data quota enforcement is layered on top by {@link
 * AppDataService}.
 *
 * @param maxRecordBytes maximum bytes in one stored value
 * @param maxRecordsPerApp maximum number of records one app may own
 * @param maxNamespacesPerApp maximum number of namespaces one app may own
 * @param maxExportBytes maximum serialized export payload size in bytes
 * @param maxImportBytes maximum serialized import payload size after base64 decoding
 * @param maxMigrationHistory maximum migration metadata entries retained per namespace
 */
public record AppDataStoreConfig(
    int maxRecordBytes,
    int maxRecordsPerApp,
    int maxNamespacesPerApp,
    int maxExportBytes,
    int maxImportBytes,
    int maxMigrationHistory) {
  /**
   * Default maximum bytes in one app-data value.
   *
   * <p>This keeps individual records suitable for UI state, drafts, and summaries rather than bulk
   * files.
   */
  public static final int DEFAULT_MAX_RECORD_BYTES = 262_144;

  /**
   * Default maximum number of app-data records per app.
   *
   * <p>Record count remains independent of byte quotas so apps cannot create unbounded metadata
   * state with tiny values.
   */
  public static final int DEFAULT_MAX_RECORDS_PER_APP = 4_096;

  /**
   * Default maximum number of app-data namespaces per app.
   *
   * <p>Namespaces are intended for a small number of app-owned schema groups, not per-item
   * sharding.
   */
  public static final int DEFAULT_MAX_NAMESPACES_PER_APP = 64;

  /**
   * Default maximum serialized app-data export size.
   *
   * <p>The value is below one mebibyte so a URL-safe base64 export can round-trip through the
   * shipped form-encoded import route.
   */
  public static final int DEFAULT_MAX_EXPORT_BYTES = 778_240;

  /**
   * Default maximum serialized app-data import size after base64 decoding.
   *
   * <p>The matching export/import defaults keep backup and restore behavior symmetric for the
   * browser SDK.
   */
  public static final int DEFAULT_MAX_IMPORT_BYTES = 778_240;

  /**
   * Default maximum migration metadata history retained per namespace.
   *
   * <p>Older entries are dropped when new migrations exceed this count.
   */
  public static final int DEFAULT_MAX_MIGRATION_HISTORY = 16;

  private static final String PROPERTY_MAX_RECORD_BYTES = "cryptad.appData.maxRecordBytes";
  private static final String PROPERTY_MAX_RECORDS_PER_APP = "cryptad.appData.maxRecordsPerApp";
  private static final String PROPERTY_MAX_NAMESPACES_PER_APP =
      "cryptad.appData.maxNamespacesPerApp";
  private static final String PROPERTY_MAX_EXPORT_BYTES = "cryptad.appData.maxExportBytes";
  private static final String PROPERTY_MAX_IMPORT_BYTES = "cryptad.appData.maxImportBytes";
  private static final String PROPERTY_MAX_MIGRATION_HISTORY =
      "cryptad.appData.maxMigrationHistory";

  /**
   * Creates a validated positive limit set.
   *
   * <p>Zero and negative values are rejected instead of being interpreted as unlimited. That keeps
   * the durable app-data API bounded even when operators provide malformed overrides.
   *
   * @throws IllegalArgumentException if any configured limit is not positive
   */
  public AppDataStoreConfig {
    requirePositive(maxRecordBytes, "maxRecordBytes");
    requirePositive(maxRecordsPerApp, "maxRecordsPerApp");
    requirePositive(maxNamespacesPerApp, "maxNamespacesPerApp");
    requirePositive(maxExportBytes, "maxExportBytes");
    requirePositive(maxImportBytes, "maxImportBytes");
    requirePositive(maxMigrationHistory, "maxMigrationHistory");
  }

  /**
   * Returns the default app-data store limit set.
   *
   * <p>The returned instance is safe to use when no runtime properties are configured. It does not
   * inspect installed app manifests; manifest data quotas are enforced later by the service.
   *
   * @return default positive host limits for the durable app-data store
   */
  public static AppDataStoreConfig defaults() {
    return new AppDataStoreConfig(
        DEFAULT_MAX_RECORD_BYTES,
        DEFAULT_MAX_RECORDS_PER_APP,
        DEFAULT_MAX_NAMESPACES_PER_APP,
        DEFAULT_MAX_EXPORT_BYTES,
        DEFAULT_MAX_IMPORT_BYTES,
        DEFAULT_MAX_MIGRATION_HISTORY);
  }

  /**
   * Loads app-data limits from system properties, falling back to defaults.
   *
   * <p>Invalid, missing, blank, zero, or negative property values are ignored. That makes startup
   * fail closed to the built-in positive bounds instead of accidentally disabling quota checks.
   * Supported property names are {@code cryptad.appData.maxRecordBytes}, {@code
   * cryptad.appData.maxRecordsPerApp}, {@code cryptad.appData.maxNamespacesPerApp}, {@code
   * cryptad.appData.maxExportBytes}, {@code cryptad.appData.maxImportBytes}, and {@code
   * cryptad.appData.maxMigrationHistory}.
   *
   * @return host limit set derived from system properties and defaults
   */
  public static AppDataStoreConfig loadFromSystem() {
    AppDataStoreConfig defaults = defaults();
    return new AppDataStoreConfig(
        positiveIntProperty(PROPERTY_MAX_RECORD_BYTES, defaults.maxRecordBytes()),
        positiveIntProperty(PROPERTY_MAX_RECORDS_PER_APP, defaults.maxRecordsPerApp()),
        positiveIntProperty(PROPERTY_MAX_NAMESPACES_PER_APP, defaults.maxNamespacesPerApp()),
        positiveIntProperty(PROPERTY_MAX_EXPORT_BYTES, defaults.maxExportBytes()),
        positiveIntProperty(PROPERTY_MAX_IMPORT_BYTES, defaults.maxImportBytes()),
        positiveIntProperty(PROPERTY_MAX_MIGRATION_HISTORY, defaults.maxMigrationHistory()));
  }

  /**
   * Returns the largest possible total app-data value bytes implied by the record limits.
   *
   * <p>The durable store also enforces record and namespace counts independently. This derived
   * value is useful in status responses and for import/write preflight checks because it gives apps
   * a positive store-level total bound even when their manifest data quota is unlimited.
   *
   * @return positive derived maximum value bytes per app
   */
  public long maxStoredValueBytesPerApp() {
    return Math.multiplyExact(maxRecordBytes, (long) maxRecordsPerApp);
  }

  private static int positiveIntProperty(String name, int fallback) {
    String raw = System.getProperty(Objects.requireNonNull(name, "name"));
    if (raw == null || raw.isBlank()) {
      return fallback;
    }
    try {
      int parsed = Integer.parseInt(raw.trim());
      return parsed > 0 ? parsed : fallback;
    } catch (NumberFormatException _) {
      return fallback;
    }
  }

  private static void requirePositive(int value, String name) {
    if (value <= 0) {
      throw new IllegalArgumentException(name + " must be positive");
    }
  }
}
