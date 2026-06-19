package network.crypta.platform.api.appupdates;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.appdist.AppDataMigrationCommand;

/**
 * Describes the app-data migration work attached to one app update candidate or staged update.
 *
 * <p>The plan is deliberately split between a path-free public summary and internal execution
 * details. Platform API responses use the stable status strings, schema versions, namespace names,
 * step ids, and risk flags from {@link #toJsonValue()}. The update lifecycle also keeps the signed
 * {@link AppDataMigrationCommand} on each namespace step so dry-run and apply execution can resolve
 * the command inside the staged or installed bundle without exposing its filesystem path.
 *
 * <p>Instances are immutable and safe to cache in candidate, staged, and history summaries. They do
 * not contain app-data record values, tokens, private catalog URIs, staging directories, command
 * stdout/stderr, or other host-local diagnostics. Callers create new instances when dry-run,
 * snapshot, apply, or rollback state changes.
 *
 * @param required whether any durable app-data migration step must run for this update
 * @param status stable path-free migration status reported through Platform API summaries
 * @param currentSchemaVersion installed or stored app-data schema version, when known
 * @param targetSchemaVersion candidate bundle schema version, when declared by the manifest
 * @param namespaces ordered namespace migration steps that must run for this plan
 * @param operatorReviewRequired whether the plan contains migration risk requiring acknowledgement
 * @param blockReason stable public error code explaining why the plan cannot proceed
 * @param dryRunStatus path-free dry-run result such as {@code passed} or {@code failed}
 * @param snapshotStatus path-free snapshot result such as {@code passed} or {@code failed}
 * @param applyStatus path-free apply result such as {@code passed} or {@code failed}
 * @see AppUpdateService
 */
public record AppDataMigrationPlan(
    boolean required,
    String status,
    Integer currentSchemaVersion,
    Integer targetSchemaVersion,
    List<NamespaceStep> namespaces,
    boolean operatorReviewRequired,
    String blockReason,
    String dryRunStatus,
    String snapshotStatus,
    String applyStatus) {
  /** Migration status used before a candidate bundle has been staged and inspected. */
  public static final String STATUS_NOT_CHECKED = "not_checked";

  /** Migration status used when no durable data requires a schema-changing step. */
  public static final String STATUS_NOT_REQUIRED = "not_required";

  /** Migration status used after a valid path has passed the required dry-run checks. */
  public static final String STATUS_READY = "ready";

  /** Migration status used when durable data needs a step that the manifest does not declare. */
  public static final String STATUS_MISSING_MIGRATION = "missing_migration";

  /** Migration status used when the staged bundle migration dry-run rejects the update. */
  public static final String STATUS_DRY_RUN_FAILED = "dry_run_failed";

  /** Migration status used when a plan needs operator review for rollback risk. */
  public static final String STATUS_ROLLBACK_INCOMPATIBLE = "rollback_incompatible";

  /** Migration status used when a signed step requires the app to be stopped first. */
  public static final String STATUS_REQUIRES_STOPPED = "requires_stopped";

  /** Migration status used when required sandbox controls cannot run the migration command. */
  public static final String STATUS_SANDBOX_UNAVAILABLE = "sandbox_unavailable";

  /** Migration status used after all required apply steps and schema records commit. */
  public static final String STATUS_APPLIED = "applied";

  /** Migration status used for a failed migration or unrecoverable post-apply state. */
  public static final String STATUS_FAILED = "failed";

  /**
   * Creates a validated migration plan.
   *
   * <p>The constructor normalizes status strings, copies the namespace step list, and preserves
   * {@code null} for lifecycle fields that have not run yet. It rejects blank status and blocker
   * values so public summaries never contain ambiguous empty strings.
   *
   * @param required whether any migration step is required for durable data
   * @param status stable migration status for API and history summaries
   * @param currentSchemaVersion current durable schema version, or {@code null} when unknown
   * @param targetSchemaVersion target bundle schema version, or {@code null} when undeclared
   * @param namespaces ordered immutable namespace migration steps
   * @param operatorReviewRequired whether operator acknowledgement is required before apply
   * @param blockReason stable error code blocking staging or apply, or {@code null}
   * @param dryRunStatus dry-run status, or {@code null} before dry-run is relevant
   * @param snapshotStatus snapshot status, or {@code null} before snapshot creation
   * @param applyStatus apply status, or {@code null} before migration apply
   */
  public AppDataMigrationPlan {
    status = requireText(status, "status");
    namespaces = List.copyOf(Objects.requireNonNull(namespaces, "namespaces"));
    if (blockReason != null && blockReason.isBlank()) {
      throw new IllegalArgumentException("blockReason must not be blank");
    }
    blockReason = blockReason == null ? null : blockReason.trim();
    dryRunStatus = normalizeOptionalStatus(dryRunStatus);
    snapshotStatus = normalizeOptionalStatus(snapshotStatus);
    applyStatus = normalizeOptionalStatus(applyStatus);
  }

  /**
   * Returns a conservative placeholder for candidates whose bundle manifest has not been staged.
   *
   * <p>Catalog checks can report a candidate before a signed bundle has been prepared locally. This
   * placeholder tells operators that no migration decision has been made yet, while keeping the
   * candidate summary path-free and stable.
   *
   * @return unchecked migration plan with no namespace steps or blocker
   */
  public static AppDataMigrationPlan notChecked() {
    return new AppDataMigrationPlan(
        false, STATUS_NOT_CHECKED, null, null, List.of(), false, null, null, null, null);
  }

  /**
   * Returns a plan for an update that does not need durable app-data migration work.
   *
   * <p>The schema versions are retained when known so the public summary can explain why the update
   * is safe without exposing data values. This is used both for undeclared migration contracts and
   * for contracts whose target schema does not exceed the stored namespace metadata.
   *
   * @param currentSchemaVersion current durable schema version, or {@code null} when unknown
   * @param targetSchemaVersion target bundle schema version, or {@code null} when undeclared
   * @return migration plan marked as not required
   */
  static AppDataMigrationPlan notRequired(
      Integer currentSchemaVersion, Integer targetSchemaVersion) {
    return new AppDataMigrationPlan(
        false,
        STATUS_NOT_REQUIRED,
        currentSchemaVersion,
        targetSchemaVersion,
        List.of(),
        false,
        null,
        null,
        null,
        null);
  }

  /**
   * Returns a migration plan whose required steps have passed staging dry-run checks.
   *
   * <p>The returned plan is still not necessarily eligible for automatic apply. Any namespace step
   * marked rollback-incompatible sets {@code operatorReviewRequired}, and later lifecycle gates may
   * also reject apply if the app is running, the plan becomes stale, or snapshot creation fails.
   *
   * @param currentSchemaVersion current durable schema version used to construct the path
   * @param targetSchemaVersion target bundle schema version expected after migration
   * @param steps ordered namespace steps that form a complete path to the target schema
   * @return ready migration plan with dry-run status set to {@code passed}
   */
  static AppDataMigrationPlan ready(
      Integer currentSchemaVersion, Integer targetSchemaVersion, List<NamespaceStep> steps) {
    return new AppDataMigrationPlan(
        true,
        STATUS_READY,
        currentSchemaVersion,
        targetSchemaVersion,
        steps,
        steps.stream().anyMatch(step -> !step.rollbackCompatible()),
        null,
        "passed",
        null,
        null);
  }

  /**
   * Returns a copy that keeps the discovered migration path but clears lifecycle dry-run state.
   *
   * <p>Consent previews can inspect a prepared candidate manifest before the staging lifecycle has
   * executed dry-run commands. This copy lets the preview explain the required path and review risk
   * without reporting a dry-run result that has not actually occurred.
   *
   * @return migration plan with dry-run status cleared
   */
  AppDataMigrationPlan withoutDryRunResult() {
    if (dryRunStatus == null) {
      return this;
    }
    return new AppDataMigrationPlan(
        required,
        status,
        currentSchemaVersion,
        targetSchemaVersion,
        namespaces,
        operatorReviewRequired,
        blockReason,
        null,
        snapshotStatus,
        applyStatus);
  }

  /**
   * Returns a required migration plan that cannot proceed without operator or system action.
   *
   * <p>Blocked plans keep the discovered namespace steps when they are safe to reveal. The blocker
   * itself is a stable public reason string, not a command path, stack trace, or migration log.
   *
   * @param status public blocked status describing the migration failure class
   * @param currentSchemaVersion current durable schema version, or {@code null} when unknown
   * @param targetSchemaVersion target bundle schema version, or {@code null} when undeclared
   * @param steps namespace steps discovered before the blocker was found
   * @param operatorReviewRequired whether explicit acknowledgement can clear the blocker
   * @param blockReason stable public reason code for the blocked plan
   * @return blocked migration plan suitable for candidate and staged summaries
   */
  static AppDataMigrationPlan blocked(
      String status,
      Integer currentSchemaVersion,
      Integer targetSchemaVersion,
      List<NamespaceStep> steps,
      boolean operatorReviewRequired,
      String blockReason) {
    return new AppDataMigrationPlan(
        true,
        status,
        currentSchemaVersion,
        targetSchemaVersion,
        steps,
        operatorReviewRequired,
        blockReason,
        null,
        null,
        null);
  }

  /**
   * Returns whether this plan has a stable blocking reason.
   *
   * @return {@code true} when staging or apply should stop before bundle replacement
   */
  boolean hasBlocker() {
    return blockReason != null;
  }

  /**
   * Returns whether the plan is eligible to enter the apply sequence.
   *
   * @return {@code true} for not-required plans or required plans with a ready status and no
   *     blocker
   */
  boolean readyForApply() {
    return !required || (STATUS_READY.equals(status) && !hasBlocker());
  }

  /**
   * Returns whether any signed namespace step requires the app process to be stopped.
   *
   * @return {@code true} when dry-run or apply must not run while the app is live
   */
  boolean requiresStopped() {
    return namespaces.stream().anyMatch(NamespaceStep::requiresStopped);
  }

  /**
   * Returns a copy that records a failed dry-run.
   *
   * <p>The resulting plan is blocked before bundle replacement. It keeps the existing namespace
   * steps so operators can see which path failed without receiving raw command output.
   *
   * @return migration plan with dry-run failure status and blocker code
   */
  AppDataMigrationPlan withDryRunFailed() {
    return new AppDataMigrationPlan(
        required,
        STATUS_DRY_RUN_FAILED,
        currentSchemaVersion,
        targetSchemaVersion,
        namespaces,
        operatorReviewRequired,
        "app_data_migration_dry_run_failed",
        STATUS_FAILED,
        snapshotStatus,
        applyStatus);
  }

  /**
   * Returns a copy that records a created internal app-data rollback snapshot.
   *
   * <p>Snapshot failures are handled by the update lifecycle before this method is called, because
   * the update cannot safely replace the bundle without a rollback snapshot. A created snapshot
   * does not change the public migration status; it only records that the protected apply sequence
   * has a restore point available.
   *
   * @return migration plan with snapshot lifecycle status set to {@code created}
   */
  AppDataMigrationPlan withSnapshotCreated() {
    return new AppDataMigrationPlan(
        required,
        status,
        currentSchemaVersion,
        targetSchemaVersion,
        namespaces,
        operatorReviewRequired,
        blockReason,
        dryRunStatus,
        "created",
        applyStatus);
  }

  /**
   * Returns a copy that records successful migration apply.
   *
   * <p>Required plans move to {@link #STATUS_APPLIED}; not-required plans remain not required. The
   * operator-review flag and blocker are cleared because the durable schema state now matches the
   * installed bundle.
   *
   * @return migration plan with apply success reflected in public status fields
   */
  AppDataMigrationPlan applied() {
    return new AppDataMigrationPlan(
        required,
        required ? STATUS_APPLIED : STATUS_NOT_REQUIRED,
        currentSchemaVersion,
        targetSchemaVersion,
        namespaces,
        false,
        null,
        dryRunStatus,
        snapshotStatus,
        required ? "passed" : null);
  }

  /**
   * Returns a copy that records a failed migration apply or recovery state.
   *
   * <p>The caller supplies only the public blocker because apply failures all use the same stable
   * failed status in API summaries. The method never attaches raw command diagnostics.
   *
   * @param blockReason stable public reason code describing the failed state
   * @return migration plan with apply failure recorded
   */
  AppDataMigrationPlan failed(String blockReason) {
    return new AppDataMigrationPlan(
        required,
        STATUS_FAILED,
        currentSchemaVersion,
        targetSchemaVersion,
        namespaces,
        operatorReviewRequired,
        blockReason,
        dryRunStatus,
        snapshotStatus,
        STATUS_FAILED);
  }

  /**
   * Converts this plan to a path-free Platform API summary.
   *
   * <p>The returned map is safe for operator and release-certification surfaces. It includes
   * namespace names, schema versions, step ids, rollback flags, and stable status strings, but it
   * deliberately omits migration command paths, staging directories, tokens, raw app-data records,
   * and command output.
   *
   * @return JSON-compatible summary with no command paths or diagnostics
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("required", required);
    json.put("status", status);
    json.put("currentSchemaVersion", currentSchemaVersion);
    json.put("targetSchemaVersion", targetSchemaVersion);
    json.put("namespaces", namespaces.stream().map(NamespaceStep::toJsonValue).toList());
    json.put("operatorReviewRequired", operatorReviewRequired);
    json.put("blockReason", blockReason);
    json.put("dryRunStatus", dryRunStatus);
    json.put("snapshotStatus", snapshotStatus);
    json.put("applyStatus", applyStatus);
    return json;
  }

  /**
   * Normalizes a required status-like string.
   *
   * @param value supplied field value that must contain non-whitespace text
   * @param fieldName field name included in validation failures
   * @return trimmed text suitable for immutable plan storage
   */
  private static String requireText(String value, String fieldName) {
    Objects.requireNonNull(value, fieldName);
    String trimmed = value.trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return trimmed;
  }

  /**
   * Normalizes an optional lifecycle status string.
   *
   * @param status supplied optional status value, or {@code null}
   * @return trimmed status value, or {@code null} when no status was supplied
   */
  private static String normalizeOptionalStatus(String status) {
    if (status == null) {
      return null;
    }
    String trimmed = status.trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException("status must not be blank");
    }
    return trimmed;
  }

  /**
   * Describes one signed namespace migration step selected for execution.
   *
   * <p>A namespace step is the public-safe projection of an {@code AppDataMigrationStep} from the
   * signed bundle manifest plus the internal command reference needed by the migration runner. API
   * summaries expose the namespace, version bounds, step id, description, and risk flags. They do
   * not expose the command path because command resolution happens only inside the verified bundle
   * root.
   *
   * @param namespace normalized durable app-data namespace being migrated
   * @param fromSchemaVersion positive source schema version expected before this step
   * @param toSchemaVersion positive target schema version produced by this step
   * @param stepId stable signed migration step identifier from the bundle manifest
   * @param rollbackCompatible whether data written by this step remains readable after rollback
   * @param requiresStopped whether the signed step requires the app process to be stopped
   * @param description bounded operator-facing description from the signed bundle manifest
   * @param command relative bundle command reference retained only for internal execution
   */
  public record NamespaceStep(
      String namespace,
      int fromSchemaVersion,
      int toSchemaVersion,
      String stepId,
      boolean rollbackCompatible,
      boolean requiresStopped,
      String description,
      AppDataMigrationCommand command) {
    /**
     * Creates a namespace migration step.
     *
     * <p>The constructor enforces an increasing version range and non-blank public text fields. The
     * command must already have been validated by manifest parsing as a relative bundle path.
     *
     * @param namespace normalized durable app-data namespace being migrated
     * @param fromSchemaVersion source schema version, greater than zero
     * @param toSchemaVersion target schema version, greater than {@code fromSchemaVersion}
     * @param stepId stable migration step identifier
     * @param rollbackCompatible whether old bundles can read post-migration data
     * @param requiresStopped whether execution requires the app to be stopped
     * @param description single-line operator-facing migration description
     * @param command internal relative command reference for the migration runner
     */
    public NamespaceStep {
      namespace = requireText(namespace, "namespace");
      if (fromSchemaVersion <= 0 || toSchemaVersion <= 0 || toSchemaVersion <= fromSchemaVersion) {
        throw new IllegalArgumentException("namespace migration versions must increase");
      }
      stepId = requireText(stepId, "stepId");
      description = requireText(description, "description");
      Objects.requireNonNull(command, "command");
    }

    /**
     * Converts this step to the safe namespace entry embedded in migration summaries.
     *
     * @return JSON-compatible namespace migration entry without command path or host diagnostics
     */
    Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
      json.put("namespace", namespace);
      json.put("from", fromSchemaVersion);
      json.put("to", toSchemaVersion);
      json.put("stepId", stepId);
      json.put("rollbackCompatible", rollbackCompatible);
      json.put("requiresStopped", requiresStopped);
      json.put("description", description);
      return json;
    }
  }
}
