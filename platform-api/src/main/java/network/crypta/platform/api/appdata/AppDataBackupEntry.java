package network.crypta.platform.api.appdata;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * One app-scoped export inside a portable app-data backup bundle.
 *
 * <p>An entry is the unit that restore planning and restore execution handle for one app id. It
 * combines path-free operator metadata with the exact single-app {@link AppDataExportPayload} that
 * would be accepted by the app-facing import path after host/operator preflight. The metadata
 * fields give the Web Shell and release-certification checks enough information to discuss the
 * backup without printing record values: installation state, display name, version, schema
 * declaration summary, namespace count, record count, byte total, and a digest of the nested
 * payload.
 *
 * <p>The {@code export} component is intentionally sensitive. It may contain raw user drafts,
 * read-state, source lists, or other app-owned values because portability requires those values.
 * The surrounding metadata must remain safe to place in restore plans and results, while the nested
 * export is only for explicit backup download or restore commit paths. The record is immutable
 * after construction, and the constructor verifies that counts, app id, byte totals, and digest all
 * describe the nested export.
 *
 * @param appId normalized app id that owns the nested export payload
 * @param installed whether the app was installed when the backup was created
 * @param appName installed app display name, or {@code null} for preserved uninstalled data
 * @param appVersion installed app version, or {@code null} for preserved uninstalled data
 * @param schemaSummary path-free summary of the installed app-data schema declaration
 * @param namespaceCount number of namespaces in the nested export
 * @param recordCount number of records in the nested export
 * @param totalBytes total stored value bytes in the nested export
 * @param payloadSha256 SHA-256 digest of the nested export JSON bytes
 * @param export single-app app-data export payload, including raw app-owned values
 * @see AppDataBackupBundle
 * @see AppDataRestorePlan.AppPlan
 */
public record AppDataBackupEntry(
    String appId,
    boolean installed,
    String appName,
    String appVersion,
    Map<String, Object> schemaSummary,
    int namespaceCount,
    int recordCount,
    long totalBytes,
    String payloadSha256,
    AppDataExportPayload export) {
  private static final String FIELD_EXPORT = "export";

  /**
   * Creates a validated backup entry.
   *
   * <p>The canonical constructor checks that the entry metadata is not merely descriptive but
   * consistent with the export payload that will be restored. The normalized app id must match the
   * export's app id, namespace and record counts must match the payload lists, total bytes must
   * match the sum of exported record values, and {@code payloadSha256} must match the deterministic
   * export JSON bytes. These checks detect tampering or stale metadata before restore planning uses
   * the entry for quota decisions.
   *
   * @throws network.crypta.platform.api.PlatformApiException if identifiers, counts, or digest do
   *     not match the nested export payload
   * @throws NullPointerException if schema metadata or the nested export is {@code null}
   */
  public AppDataBackupEntry {
    appId = AppDataRecord.normalizeAppId(appId);
    schemaSummary =
        java.util.Collections.unmodifiableMap(
            new LinkedHashMap<>(Objects.requireNonNull(schemaSummary, "schemaSummary")));
    Objects.requireNonNull(export, FIELD_EXPORT);
    if (!appId.equals(export.appId())) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
    if (namespaceCount != export.namespaces().size() || recordCount != export.records().size()) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
    long computedTotalBytes = export.records().stream().mapToLong(AppDataRecord::valueBytes).sum();
    if (totalBytes != computedTotalBytes) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
    String computedDigest = AppDataRecord.sha256(export.toJsonBytes());
    if (!computedDigest.equals(payloadSha256)) {
      throw AppDataBackupManifest.invalidBackupPayload();
    }
  }

  /**
   * Creates a backup entry from an existing export payload.
   *
   * <p>This factory is used when the service has already exported one app's durable state and needs
   * to wrap it in operator backup metadata. Counts, byte totals, and the SHA-256 digest are derived
   * from the export payload so callers cannot accidentally provide inconsistent metadata. The
   * resulting entry still runs through the canonical constructor, which performs the same
   * validation as parsed backup bundles.
   *
   * @param appId normalized app id expected to own the nested export payload
   * @param installed whether the app is currently installed on the exporting node
   * @param appName app display name, or {@code null} for preserved uninstalled data
   * @param appVersion app version, or {@code null} for preserved uninstalled data
   * @param schemaSummary path-free schema summary for operator restore planning
   * @param export single-app export payload that contains raw app-owned values
   * @return validated backup entry with derived counts and digest
   */
  public static AppDataBackupEntry fromExport(
      String appId,
      boolean installed,
      String appName,
      String appVersion,
      Map<String, Object> schemaSummary,
      AppDataExportPayload export) {
    AppDataExportPayload checkedExport = Objects.requireNonNull(export, FIELD_EXPORT);
    return new AppDataBackupEntry(
        appId,
        installed,
        appName,
        appVersion,
        schemaSummary,
        checkedExport.namespaces().size(),
        checkedExport.records().size(),
        checkedExport.records().stream().mapToLong(AppDataRecord::valueBytes).sum(),
        AppDataRecord.sha256(checkedExport.toJsonBytes()),
        checkedExport);
  }

  /**
   * Converts this entry to a deterministic JSON-compatible map.
   *
   * <p>The returned map keeps metadata fields before the nested export and preserves a stable field
   * order for reproducible backup bytes. It includes raw app-data values through {@code
   * export.toJsonValue()}, so callers should use it only when assembling the backup artifact
   * itself. Restore plans and results should use {@link #namespaceSummaries()} plus the scalar
   * metadata fields instead.
   *
   * @return backup entry JSON fields in stable order
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("appId", appId);
    json.put("installed", installed);
    json.put("appName", appName);
    json.put("appVersion", appVersion);
    json.put("schemaSummary", schemaSummary);
    json.put("namespaceCount", namespaceCount);
    json.put("recordCount", recordCount);
    json.put("totalBytes", totalBytes);
    json.put("payloadSha256", payloadSha256);
    json.put(FIELD_EXPORT, export.toJsonValue());
    return json;
  }

  /**
   * Returns metadata-only namespace summaries for restore plan/result responses.
   *
   * <p>Each namespace map uses the app-data export metadata shape without migration record values
   * or record payloads. This gives operator-facing code the namespace names, schema versions,
   * record counts, byte totals, and migration timestamps needed for a restore preview without
   * exposing user data that belongs only in the backup artifact.
   *
   * @return namespace summaries without record values
   */
  public List<Map<String, Object>> namespaceSummaries() {
    return export.namespaces().stream().map(namespace -> namespace.toJsonValue(false)).toList();
  }

  @Override
  public @NotNull String toString() {
    return "AppDataBackupEntry[appId="
        + appId
        + ", installed="
        + installed
        + ", appName="
        + appName
        + ", appVersion="
        + appVersion
        + ", namespaceCount="
        + namespaceCount
        + ", recordCount="
        + recordCount
        + ", totalBytes="
        + totalBytes
        + ", payloadSha256="
        + payloadSha256
        + "]";
  }
}
