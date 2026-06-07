package network.crypta.platform.api.appdata;

import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.platform.appdist.AppDataNamespaceSchema;
import network.crypta.platform.appdist.AppDataSchemaContract;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Builds metadata-only schema summaries for app-data backup and restore planning.
 *
 * <p>The backup/restore service needs a small amount of installed-app manifest information when it
 * creates a backup entry or previews a restore: whether an app declares durable app-data schema,
 * the current schema version, namespace declaration counts, migration declaration counts, and
 * whether the backup entry's namespace schema versions can fit the installed manifest. Keeping that
 * logic here narrows {@link AppDataService} to app-data store policy and mutation sequencing while
 * this helper owns manifest-schema interpretation.
 *
 * <p>Every value returned by this class is metadata-only. It does not include host paths, bundle
 * paths, app tokens, private insert URIs, raw record values, nested backup payloads, or vault
 * material. The maps are suitable for backup manifests, restore plans, and release-certification
 * source checks.
 */
final class AppDataBackupMetadata {
  /**
   * Restore-plan status used when installed schema compatibility cannot be proven.
   *
   * <p>The value is shared with {@link AppDataService} so uninstalled-app previews and installed
   * manifest checks use one stable reason code.
   */
  static final String STATUS_SCHEMA_WARNING = "schema_warning";

  /**
   * Schema-summary field for the manifest-wide current schema version.
   *
   * <p>The value is {@code null} when no installed manifest is available.
   */
  private static final String FIELD_CURRENT = "current";

  /**
   * Schema-summary field indicating whether the installed manifest declares app-data schema.
   *
   * <p>Preserved data for an uninstalled app reports {@code false}.
   */
  private static final String FIELD_DECLARED = "declared";

  /**
   * Schema-summary field for the number of declared migration records.
   *
   * <p>The count is metadata only and never includes migration command paths or logs.
   */
  private static final String FIELD_MIGRATION_COUNT = "migrationCount";

  /**
   * Schema-summary field for the number of declared app-data namespaces.
   *
   * <p>The count is safe for backup manifests and restore plans because it does not expose record
   * values.
   */
  private static final String FIELD_NAMESPACE_COUNT = "namespaceCount";

  /**
   * Restore-plan status used when the backup entry fits the installed schema declaration.
   *
   * <p>This status is informational and does not replace quota or payload preflight checks.
   */
  private static final String STATUS_SCHEMA_COMPATIBLE = "schema_compatible";

  /**
   * Prevents instantiation of this metadata-only helper.
   *
   * <p>All behavior is stateless and scoped to the supplied installed-app snapshot or backup entry.
   */
  private AppDataBackupMetadata() {}

  /**
   * Builds a path-free schema summary for a backup entry.
   *
   * <p>Installed apps contribute the app-data schema declaration from their manifest. Preserved
   * app-data for an uninstalled app has no manifest to compare against, so the summary explicitly
   * reports {@code declared=false}, {@code current=null}, and zero declaration counts.
   *
   * @param installed installed app snapshot, or {@code null} for preserved uninstalled app-data
   * @return deterministic metadata map without app-data values or host paths
   */
  static Map<String, Object> schemaSummary(InstalledAppSnapshot installed) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    if (installed == null) {
      json.put(FIELD_DECLARED, false);
      json.put(FIELD_CURRENT, null);
      json.put(FIELD_NAMESPACE_COUNT, 0);
      json.put(FIELD_MIGRATION_COUNT, 0);
      return json;
    }
    AppDataSchemaContract contract = installed.manifest().dataSchemaContract();
    json.put(FIELD_DECLARED, contract.declared());
    json.put(FIELD_CURRENT, contract.currentSchemaVersion());
    json.put(FIELD_NAMESPACE_COUNT, contract.namespaces().size());
    json.put(FIELD_MIGRATION_COUNT, contract.migrations().size());
    return json;
  }

  /**
   * Reports whether a backup entry is schema-compatible with an installed app manifest.
   *
   * <p>The method is deliberately conservative. If the installed manifest does not declare an
   * app-data schema, an entry with namespaces becomes a warning because the operator can still
   * restore the data but compatibility is not proven. When a namespace-specific schema declaration
   * exists, that namespace's current version is authoritative; otherwise the manifest-wide current
   * version is used. A backup namespace whose schema version is newer than the target declaration
   * also becomes a warning.
   *
   * @param installed installed app snapshot on the restore target
   * @param entry backup entry being previewed
   * @return stable schema status code for restore plan metadata
   */
  static String schemaCompatibilityStatus(
      InstalledAppSnapshot installed, AppDataBackupEntry entry) {
    AppDataSchemaContract contract = installed.manifest().dataSchemaContract();
    if (contract == null || !contract.declared()) {
      return entry.namespaceCount() == 0 ? STATUS_SCHEMA_COMPATIBLE : STATUS_SCHEMA_WARNING;
    }
    for (AppDataNamespaceMetadata namespace : entry.export().namespaces()) {
      Integer targetSchemaVersion = contract.currentSchemaVersion();
      AppDataNamespaceSchema namespaceSchema = contract.namespace(namespace.namespace());
      if (namespaceSchema != null) {
        targetSchemaVersion = namespaceSchema.currentSchemaVersion();
      }
      if (targetSchemaVersion == null || namespace.schemaVersion() > targetSchemaVersion) {
        return STATUS_SCHEMA_WARNING;
      }
    }
    return STATUS_SCHEMA_COMPATIBLE;
  }
}
