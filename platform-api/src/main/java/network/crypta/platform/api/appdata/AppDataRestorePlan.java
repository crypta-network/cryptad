package network.crypta.platform.api.appdata;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Metadata-only preview for restoring an app-data backup bundle.
 *
 * <p>A restore plan is the operator-visible preflight result for one backup payload and requested
 * {@link AppDataRestoreMode}. It reports whether the restore can proceed, which apps and namespaces
 * would be affected, which records would conflict with existing keys, whether quota or schema
 * checks block the operation, and which non-blocking warnings the operator should see before
 * commit. The plan is computed before mutation and should be shown before any destructive {@code
 * replaceNamespace} or {@code replaceApp} restore.
 *
 * <p>The object is intentionally metadata-only. It never contains raw record values, nested export
 * payloads, backup base64, request bodies, filesystem paths, app tokens, private insert URIs, vault
 * material, or app-process environment values. That makes it appropriate for Web Shell panels,
 * release-certification evidence, tests, and support-oriented summaries. A ready plan is not a
 * lock; restore execution still repeats the relevant validation before writing.
 *
 * @param status global plan status, usually {@code ready} or {@code blocked}
 * @param mode requested restore mode
 * @param scope backup scope
 * @param backupVersion backup envelope version
 * @param appCount number of app entries in the backup
 * @param recordCount total record count across all entries
 * @param totalBytes total value bytes across all entries
 * @param apps per-app restore previews
 * @see AppDataRestoreResult
 */
public record AppDataRestorePlan(
    String status,
    AppDataRestoreMode mode,
    String scope,
    int backupVersion,
    int appCount,
    int recordCount,
    long totalBytes,
    List<AppPlan> apps) {
  /**
   * Plan status used when all app entries can be restored.
   *
   * <p>A ready plan has no blocking reason codes. It may still contain warnings, such as restoring
   * data for an app that is not currently installed.
   */
  public static final String STATUS_READY = "ready";

  /**
   * Plan status used when one or more app entries cannot be restored.
   *
   * <p>Blocked plans are metadata-only and stop restore execution before mutation. Blockers use
   * stable reason codes such as quota failures, invalid payloads, or unsupported compatibility.
   */
  public static final String STATUS_BLOCKED = "blocked";

  private static final String FIELD_STATUS = "status";

  /**
   * Creates a metadata-only restore plan.
   *
   * <p>The constructor takes defensive copies of the per-app plan list so callers cannot mutate a
   * response after it has been returned from the service. It validates only structural nullness and
   * leaves semantic status selection to the service preflight code that constructs the plan.
   *
   * @throws NullPointerException if required fields are {@code null}
   */
  public AppDataRestorePlan {
    Objects.requireNonNull(status, FIELD_STATUS);
    Objects.requireNonNull(mode, "mode");
    Objects.requireNonNull(scope, "scope");
    apps = List.copyOf(Objects.requireNonNull(apps, "apps"));
  }

  /**
   * Returns whether the plan has no blocking restore findings.
   *
   * <p>This is a convenience check for commit paths. Operator UI should still display warnings and
   * destructive-mode statuses even when this method returns {@code true}.
   *
   * @return {@code true} when the plan is ready to commit
   */
  public boolean ready() {
    return STATUS_READY.equals(status);
  }

  /**
   * Converts this plan to deterministic JSON-compatible metadata.
   *
   * <p>The returned map is the shape used by operator restore preview responses. Field order is
   * stable for tests and release evidence. Nested app plans are already sanitized and do not expose
   * backup payloads or record values.
   *
   * @return restore plan map without raw backup values
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(FIELD_STATUS, status);
    json.put("mode", mode.apiValue());
    json.put("scope", scope);
    json.put("backupVersion", backupVersion);
    json.put("appCount", appCount);
    json.put("recordCount", recordCount);
    json.put("totalBytes", totalBytes);
    json.put("apps", apps.stream().map(AppPlan::toJsonValue).toList());
    return json;
  }

  @Override
  public @NotNull String toString() {
    return "AppDataRestorePlan[status="
        + status
        + ", mode="
        + mode.apiValue()
        + ", scope="
        + scope
        + ", appCount="
        + appCount
        + ", recordCount="
        + recordCount
        + ", totalBytes="
        + totalBytes
        + "]";
  }

  /**
   * Metadata-only plan for one app entry in a backup bundle.
   *
   * <p>An app plan explains the effect of restoring one {@link AppDataBackupEntry}. It carries the
   * target app id, target-node installation metadata when available, stable status and reason
   * codes, counts from the backup entry, the number of existing records that would be overwritten,
   * and namespace summaries without values. The status lists are deliberately strings rather than
   * enum constants so route responses can preserve a stable vocabulary for Web Shell copy and
   * release certification fixtures.
   *
   * <p>{@code installed=false} is a warning condition rather than an automatic blocker. Cryptad can
   * restore preserved durable app-data before the app is reinstalled, but schema and manifest quota
   * compatibility may be less complete until an installed manifest is available.
   *
   * @param appId normalized app id being restored
   * @param installed whether the app is currently installed on the target node
   * @param appName installed app display name, or {@code null}
   * @param appVersion installed app version, or {@code null}
   * @param status app-level plan status
   * @param statuses stable reason/status codes
   * @param warnings non-blocking warning codes
   * @param blockers blocking reason codes
   * @param namespaceCount namespace count in the backup entry
   * @param recordCount record count in the backup entry
   * @param totalBytes total value bytes in the backup entry
   * @param conflictCount records that would overwrite an existing key
   * @param namespaces namespace summaries without values
   */
  public record AppPlan(
      String appId,
      boolean installed,
      String appName,
      String appVersion,
      String status,
      List<String> statuses,
      List<String> warnings,
      List<String> blockers,
      int namespaceCount,
      int recordCount,
      long totalBytes,
      int conflictCount,
      List<Map<String, Object>> namespaces) {
    /**
     * Creates a per-app restore plan.
     *
     * <p>The constructor normalizes the app id and defensively copies all status and namespace
     * collections. Namespace maps are copied into unmodifiable maps so later callers cannot add raw
     * values or paths to an object that has already been declared metadata-only.
     *
     * @throws NullPointerException if required metadata collections are {@code null}
     */
    public AppPlan {
      appId = AppDataRecord.normalizeAppId(appId);
      Objects.requireNonNull(status, FIELD_STATUS);
      statuses = List.copyOf(Objects.requireNonNull(statuses, "statuses"));
      warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
      blockers = List.copyOf(Objects.requireNonNull(blockers, "blockers"));
      namespaces =
          List.copyOf(
              Objects.requireNonNull(namespaces, "namespaces").stream()
                  .map(
                      namespace ->
                          java.util.Collections.unmodifiableMap(new LinkedHashMap<>(namespace)))
                  .toList());
    }

    /**
     * Converts this app plan to deterministic JSON-compatible metadata.
     *
     * <p>The map is suitable for operator route responses and Web Shell rendering. It includes
     * namespace summaries and reason codes, but excludes nested backup exports, record values,
     * payload digests other than scalar metadata already present in the plan, and any host path.
     *
     * @return app restore plan without raw record values
     */
    public Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(13);
      json.put("appId", appId);
      json.put("installed", installed);
      json.put("appName", appName);
      json.put("appVersion", appVersion);
      json.put(FIELD_STATUS, status);
      json.put("statuses", statuses);
      json.put("warnings", warnings);
      json.put("blockers", blockers);
      json.put("namespaceCount", namespaceCount);
      json.put("recordCount", recordCount);
      json.put("totalBytes", totalBytes);
      json.put("conflictCount", conflictCount);
      json.put("namespaces", namespaces);
      return json;
    }
  }
}
