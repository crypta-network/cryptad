package network.crypta.platform.api.appdata;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Metadata-only result for an operator app-data restore request.
 *
 * <p>A restore result is returned after the service either commits a ready restore plan or blocks
 * the request before mutation. It mirrors the plan's operator-safe shape but records the final
 * outcome: whether any writes were committed, which restore mode was requested, which backup scope
 * was considered, and how each app entry ended. Successful results summarize committed counts.
 * Blocked results preserve the blockers and warnings that explain why no write occurred.
 *
 * <p>The result intentionally excludes the raw backup JSON, payload base64, nested exports, record
 * values, request body, filesystem paths, private insert URIs, browser-session tokens, app tokens,
 * vault material, and app-process environment values. This keeps the object suitable for Web Shell
 * status panels, release-certification evidence, and support-adjacent diagnostics while still
 * making the operator-visible restore outcome auditable.
 *
 * @param restored whether any durable app-data writes were committed
 * @param status global restore status
 * @param mode requested restore mode
 * @param scope backup scope
 * @param appCount number of app entries considered
 * @param recordCount total record count considered
 * @param totalBytes total value bytes considered
 * @param apps per-app metadata-only results
 * @see AppDataRestorePlan
 */
public record AppDataRestoreResult(
    boolean restored,
    String status,
    AppDataRestoreMode mode,
    String scope,
    int appCount,
    int recordCount,
    long totalBytes,
    List<AppResult> apps) {
  /**
   * Restore result status used after all entries commit successfully.
   *
   * <p>A restored result means the preflight plan was ready and every selected app entry completed
   * under the requested restore mode. It does not imply that the target app is installed.
   */
  public static final String STATUS_RESTORED = "restored";

  /**
   * Restore result status used when a preflight plan blocks mutation.
   *
   * <p>A blocked result is a no-write outcome. Per-app blockers explain the failed preflight
   * condition without embedding backup payloads or record values.
   */
  public static final String STATUS_BLOCKED = "blocked";

  private static final String FIELD_STATUS = "status";

  /**
   * Creates a restore result.
   *
   * <p>The constructor defensively copies the app-result list and validates the required scalar
   * fields. It does not infer global status from child entries; service code constructs that status
   * after restore planning or commit has decided whether writes occurred.
   *
   * @throws NullPointerException if required fields are {@code null}
   */
  public AppDataRestoreResult {
    Objects.requireNonNull(status, FIELD_STATUS);
    Objects.requireNonNull(mode, "mode");
    Objects.requireNonNull(scope, "scope");
    apps = List.copyOf(Objects.requireNonNull(apps, "apps"));
  }

  /**
   * Converts this result to deterministic JSON-compatible metadata.
   *
   * <p>The returned map is the response shape for the operator restore commit route. Its field
   * order is stable for tests and offline evidence checks. Nested app results are metadata-only and
   * should be safe to render directly with normal Web Shell escaping.
   *
   * @return restore result map without raw backup values
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(STATUS_RESTORED, restored);
    json.put(FIELD_STATUS, status);
    json.put("mode", mode.apiValue());
    json.put("scope", scope);
    json.put("appCount", appCount);
    json.put("recordCount", recordCount);
    json.put("totalBytes", totalBytes);
    json.put("apps", apps.stream().map(AppResult::toJsonValue).toList());
    return json;
  }

  @Override
  public @NotNull String toString() {
    return "AppDataRestoreResult[restored="
        + restored
        + ", status="
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
   * Metadata-only result for one app entry.
   *
   * <p>An app result records the final outcome for one app id in the backup bundle. When {@code
   * restored} is {@code true}, the counts describe the durable app-data entry that was committed.
   * When {@code restored} is {@code false}, the counts describe the backup entry that was
   * considered and the blockers list explains why the service did not write it. Installation state
   * is carried through from preflight so the Web Shell can accurately report restores for preserved
   * data whose app is not currently installed.
   *
   * <p>Like {@link AppDataRestorePlan.AppPlan}, this record contains only reason codes and scalar
   * counts. It does not include namespace maps or nested export payloads because post-commit status
   * panels should not redisplay backup contents.
   *
   * @param appId normalized app id
   * @param installed whether the app was installed on the target node during preflight
   * @param restored whether this app entry was committed
   * @param status app-level restore status
   * @param statuses stable reason/status codes
   * @param warnings non-blocking warning codes copied from the preflight plan
   * @param blockers blocking reason codes copied from the preflight plan
   * @param namespaceCount namespace count restored or considered
   * @param recordCount record count restored or considered
   * @param totalBytes value bytes restored or considered
   */
  public record AppResult(
      String appId,
      boolean installed,
      boolean restored,
      String status,
      List<String> statuses,
      List<String> warnings,
      List<String> blockers,
      int namespaceCount,
      int recordCount,
      long totalBytes) {
    /**
     * Creates one app restore result.
     *
     * <p>The constructor normalizes the app id and makes defensive copies of reason-code
     * collections. The copied lists are safe to reuse in response maps without allowing later
     * mutation to add sensitive strings.
     *
     * @throws NullPointerException if required metadata is {@code null}
     */
    public AppResult {
      appId = AppDataRecord.normalizeAppId(appId);
      Objects.requireNonNull(status, FIELD_STATUS);
      statuses = List.copyOf(Objects.requireNonNull(statuses, "statuses"));
      warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
      blockers = List.copyOf(Objects.requireNonNull(blockers, "blockers"));
    }

    /**
     * Converts this app result to deterministic JSON-compatible metadata.
     *
     * <p>The map is intentionally smaller than an app restore plan. It reports installation state,
     * commit state, stable reason codes, and counts, but omits namespace details and all record
     * values. That keeps final restore status compact and safe for ordinary operator rendering.
     *
     * @return app restore result without raw backup values
     */
    public Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
      json.put("appId", appId);
      json.put("installed", installed);
      json.put(STATUS_RESTORED, restored);
      json.put(FIELD_STATUS, status);
      json.put("statuses", statuses);
      json.put("warnings", warnings);
      json.put("blockers", blockers);
      json.put("namespaceCount", namespaceCount);
      json.put("recordCount", recordCount);
      json.put("totalBytes", totalBytes);
      return json;
    }
  }
}
