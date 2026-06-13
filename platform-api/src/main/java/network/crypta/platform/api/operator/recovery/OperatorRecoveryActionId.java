package network.crypta.platform.api.operator.recovery;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Enumerates every operator RC recovery action accepted by the plan and execute routes.
 *
 * <p>This enum is the server-side allowlist for recovery dispatch. Clients submit the dotted JSON
 * token, the route layer converts it through {@link #fromJsonValue(String)}, and {@code
 * OperatorRecoveryService} builds a typed plan before any mutation can run. The constants also
 * carry bounded metadata for Web Shell grouping, confirmation prompts, release-certification
 * evidence, and support-bundle summaries.
 *
 * <p>The descriptions intentionally name existing safe subsystems instead of route paths or
 * commands. Adding a new constant is not enough to create a recovery capability; the service must
 * still validate the target, build preconditions, preserve prior security gates, and implement an
 * explicit execution branch.
 */
public enum OperatorRecoveryActionId {
  /**
   * Refreshes one configured catalog source through the signed catalog fetch path.
   *
   * <p>The action is non-destructive but may change visible catalog health because it re-fetches
   * and verifies current source metadata. It does not switch channels or accept private insert URIs
   * from the operator request.
   */
  CATALOG_REFRESH(
      "catalog.refresh",
      "Refresh catalog",
      metadata(
          OperatorRecoveryActionCategory.CATALOG,
          OperatorRecoverySeverity.WARNING,
          Targets.CATALOG,
          false,
          "Fetch and verify the configured signed catalog source.",
          Fields.CATALOG_ID)),
  /**
   * Rechecks existing catalog sidecars and policy metadata without changing the source.
   *
   * <p>This is the safest catalog diagnostic action. It is intended for signature, security,
   * channel, or review-state drift where the operator needs fresh evidence rather than source
   * mutation.
   */
  CATALOG_REVERIFY(
      "catalog.reverify",
      "Re-verify catalog",
      metadata(
          OperatorRecoveryActionCategory.CATALOG,
          OperatorRecoverySeverity.INFO,
          Targets.CATALOG,
          false,
          "Re-read configured signed catalog sidecars through the existing verification path.",
          Fields.CATALOG_ID)),
  /**
   * Represents repair of the recommended first-party catalog source.
   *
   * <p>The action remains bounded to already-supported first-party catalog semantics. It must not
   * silently move stable operators to beta, nightly, deprecated, or operator-supplied catalog
   * channels.
   */
  CATALOG_REPAIR_FIRST_PARTY_SOURCE(
      "catalog.repair-first-party-source",
      "Repair first-party catalog source",
      metadata(
          OperatorRecoveryActionCategory.CATALOG,
          OperatorRecoverySeverity.WARNING,
          Targets.CATALOG,
          false,
          "Add a configured recommended first-party catalog without switching channels.",
          Fields.CATALOG_ID)),
  /**
   * Re-evaluates update availability for one installed app.
   *
   * <p>The action is metadata-oriented. It asks the existing update service to inspect verified
   * catalog candidates while preserving channel policy, trusted review receipt, and security
   * advisory gates.
   */
  APP_CHECK_UPDATE(
      "app.check-update",
      "Check app update",
      metadata(
          OperatorRecoveryActionCategory.APP,
          OperatorRecoverySeverity.INFO,
          Targets.APP,
          false,
          "Re-evaluate verified catalog update candidates.",
          Fields.APP_ID)),
  /**
   * Stages a verified update candidate for one installed app.
   *
   * <p>Staging is non-destructive to app data but may write update state. The execution path must
   * continue to enforce bundle signature, digest, migration, dependency, review, and security
   * checks.
   */
  APP_STAGE_UPDATE(
      "app.stage-update",
      "Stage app update",
      metadata(
          OperatorRecoveryActionCategory.APP,
          OperatorRecoverySeverity.WARNING,
          Targets.APP,
          false,
          "Stage a verified update candidate through the existing update gates.",
          Fields.APP_ID)),
  /**
   * Applies the already staged app update bundle.
   *
   * <p>This action is destructive because it replaces the active immutable app bundle. The recovery
   * plan must surface stopped-app requirements, migration compatibility, rollback warnings, and the
   * same gates used by the normal app-update flow.
   */
  APP_APPLY_UPDATE(
      "app.apply-update",
      "Apply staged app update",
      metadata(
          OperatorRecoveryActionCategory.APP,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.APP,
          true,
          "Apply the currently staged bundle while preserving update, review, and migration gates.",
          Fields.APP_ID)),
  /**
   * Rolls one installed app back to the previous immutable bundle.
   *
   * <p>Rollback is destructive and requires existing rollback metadata from AppHost. The plan must
   * block while the app is running or when rollback state is unavailable, rather than inventing a
   * replacement bundle.
   */
  APP_ROLLBACK(
      "app.rollback",
      "Rollback app bundle",
      metadata(
          OperatorRecoveryActionCategory.APP,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.APP,
          true,
          "Restore the previous immutable app bundle when AppHost has rollback metadata.",
          Fields.APP_ID)),
  /**
   * Represents reinstall repair from a verified catalog entry while preserving app data.
   *
   * <p>The action is destructive because it can replace the installed bundle. It is available only
   * when a safe catalog-backed reinstall path exists and all catalog, advisory, dependency, and
   * migration gates pass.
   */
  APP_REINSTALL_FROM_CATALOG(
      "app.reinstall-from-catalog",
      "Reinstall from catalog",
      metadata(
          OperatorRecoveryActionCategory.APP,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.APP,
          true,
          "Represent catalog reinstall repair when a dedicated safe replace API is available.",
          Fields.APP_AND_CATALOG)),
  /**
   * Creates a portable app-data backup before removing the installed app bundle.
   *
   * <p>This action is destructive because the app bundle is uninstalled after export. The sensitive
   * backup payload may appear only in the explicit execution result, never in ordinary dashboards,
   * support bundles, audits, or release evidence.
   */
  APP_EXPORT_BEFORE_UNINSTALL(
      "app.export-before-uninstall",
      "Export app data before uninstall",
      metadata(
          OperatorRecoveryActionCategory.APP,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.APP,
          true,
          "Create an app-data backup bundle before removing the installed app bundle.",
          Fields.APP_ID)),
  /**
   * Stops one running installed app through AppHost.
   *
   * <p>The action is non-destructive but operationally visible. It is primarily used to satisfy
   * recovery preconditions before rollback, apply-update, reinstall, restore, or export workflows.
   */
  APP_STOP(
      "app.stop",
      "Stop app",
      metadata(
          OperatorRecoveryActionCategory.APP,
          OperatorRecoverySeverity.WARNING,
          Targets.APP,
          false,
          "Stop a running installed app through AppHost.",
          Fields.APP_ID)),
  /**
   * Starts one stopped installed app through AppHost.
   *
   * <p>The action is non-destructive but can resume app-owned background work. Plans report the
   * stopped-app precondition explicitly so operators do not confuse it with update actions that
   * require an app to remain stopped.
   */
  APP_START(
      "app.start",
      "Start app",
      metadata(
          OperatorRecoveryActionCategory.APP,
          OperatorRecoverySeverity.WARNING,
          Targets.APP,
          false,
          "Start a stopped installed app through AppHost.",
          Fields.APP_ID)),
  /**
   * Runs one bounded fetch for a durable content subscription.
   *
   * <p>Unlike metadata-only subscription recovery actions, refresh can consume network fetch
   * budget. Results remain metadata-only and must not include raw fetched content, raw source URIs,
   * or queue HTML.
   */
  SUBSCRIPTION_REFRESH(
      "subscription.refresh",
      "Refresh subscription",
      metadata(
          OperatorRecoveryActionCategory.SUBSCRIPTION,
          OperatorRecoverySeverity.WARNING,
          Targets.SUBSCRIPTION,
          false,
          "Run one bounded subscription fetch subject to app-network budgets.",
          Fields.APP_AND_SUBSCRIPTION)),
  /**
   * Pauses scheduler polling for one durable content subscription.
   *
   * <p>The action changes subscription metadata only. It does not delete the record, fetch content,
   * clear failures, or consume network-scale fetch budget.
   */
  SUBSCRIPTION_PAUSE(
      "subscription.pause",
      "Pause subscription",
      metadata(
          OperatorRecoveryActionCategory.SUBSCRIPTION,
          OperatorRecoverySeverity.INFO,
          Targets.SUBSCRIPTION,
          false,
          "Pause scheduler polling for one subscription.",
          Fields.APP_AND_SUBSCRIPTION)),
  /**
   * Resumes scheduler polling for one durable content subscription.
   *
   * <p>Resume can make the subscription eligible for future scheduled work, but this action itself
   * does not fetch content. Operators can use refresh separately when they need an immediate fetch.
   */
  SUBSCRIPTION_RESUME(
      "subscription.resume",
      "Resume subscription",
      metadata(
          OperatorRecoveryActionCategory.SUBSCRIPTION,
          OperatorRecoverySeverity.INFO,
          Targets.SUBSCRIPTION,
          false,
          "Resume scheduler polling and make one subscription due.",
          Fields.APP_AND_SUBSCRIPTION)),
  /**
   * Clears failure and backoff metadata for one durable content subscription.
   *
   * <p>The action is intentionally metadata-only. It does not fetch content, does not spend network
   * budget, and does not expose the raw subscription source in the result.
   */
  SUBSCRIPTION_RESET_BACKOFF(
      "subscription.reset-backoff",
      "Reset subscription backoff",
      metadata(
          OperatorRecoveryActionCategory.SUBSCRIPTION,
          OperatorRecoverySeverity.INFO,
          Targets.SUBSCRIPTION,
          false,
          "Clear failure/backoff metadata without fetching content.",
          Fields.APP_AND_SUBSCRIPTION)),
  /**
   * Makes one enabled durable subscription due immediately.
   *
   * <p>The action repairs scheduler timing without fetching content. A later scheduler pass or
   * explicit refresh performs any network work and remains subject to PR-256 budget policy.
   */
  SUBSCRIPTION_RESCHEDULE_NOW(
      "subscription.reschedule-now",
      "Reschedule subscription now",
      metadata(
          OperatorRecoveryActionCategory.SUBSCRIPTION,
          OperatorRecoverySeverity.INFO,
          Targets.SUBSCRIPTION,
          false,
          "Make one enabled subscription due immediately without fetching content.",
          Fields.APP_AND_SUBSCRIPTION)),
  /**
   * Deletes one durable subscription metadata record.
   *
   * <p>The action is destructive because it removes scheduler state for the selected app and
   * subscription. It must not return raw content, request bodies, or unredacted source details.
   */
  SUBSCRIPTION_DELETE(
      "subscription.delete",
      "Delete subscription",
      metadata(
          OperatorRecoveryActionCategory.SUBSCRIPTION,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.SUBSCRIPTION,
          true,
          "Delete one durable subscription metadata record.",
          Fields.APP_AND_SUBSCRIPTION)),
  /**
   * Revokes one app-service grant.
   *
   * <p>Revocation is destructive for the dependent app capability. The result must keep future
   * service calls fail-closed and must not expose bearer tokens, invocation bodies, provider local
   * state, or Trust Graph raw data.
   */
  APP_SERVICE_GRANT_REVOKE(
      "app-service.grant-revoke",
      "Revoke app-service grant",
      metadata(
          OperatorRecoveryActionCategory.APP_SERVICE,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.APP_SERVICE_GRANT,
          true,
          "Revoke one app-service grant and keep future calls fail-closed.",
          Fields.GRANT_ID)),
  /**
   * Renews grants in one app-service dependency bundle.
   *
   * <p>Renewal is non-destructive but can restore authorizing state after descriptor and dependency
   * checks pass. Expired grants remain non-authorizing until this action succeeds.
   */
  APP_SERVICE_BUNDLE_RENEW(
      "app-service.bundle-renew",
      "Renew app-service grant bundle",
      metadata(
          OperatorRecoveryActionCategory.APP_SERVICE,
          OperatorRecoverySeverity.WARNING,
          Targets.APP_SERVICE_BUNDLE,
          false,
          "Renew approved or expired bundle grants after descriptor revalidation.",
          Fields.BUNDLE_ID)),
  /**
   * Revalidates one app-service dependency bundle.
   *
   * <p>The action uses the same fail-closed provider descriptor path as renewal. It is intended for
   * descriptor drift or dependency-state ambiguity where the operator needs fresh grant evidence.
   */
  APP_SERVICE_BUNDLE_REVALIDATE(
      "app-service.bundle-revalidate",
      "Revalidate app-service grant bundle",
      metadata(
          OperatorRecoveryActionCategory.APP_SERVICE,
          OperatorRecoverySeverity.WARNING,
          Targets.APP_SERVICE_BUNDLE,
          false,
          "Revalidate a bundle using the same fail-closed renewal path.",
          Fields.BUNDLE_ID)),
  /**
   * Rejects one pending app-service dependency bundle.
   *
   * <p>The action is destructive for the pending capability request because it prevents the bundle
   * from authorizing dependencies. It must not authorize optional or required grants as a side
   * effect.
   */
  APP_SERVICE_BUNDLE_REJECT(
      "app-service.bundle-reject",
      "Reject app-service grant bundle",
      metadata(
          OperatorRecoveryActionCategory.APP_SERVICE,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.APP_SERVICE_BUNDLE,
          true,
          "Reject a pending grant bundle without authorizing dependencies.",
          Fields.BUNDLE_ID)),
  /**
   * Exports a metadata-only summary of local Trust Graph RC state.
   *
   * <p>The export is bounded to local operator-curated trust data. It must omit raw statement JSON,
   * signatures, private identity material, local store paths, and any global moderation or routing
   * claims.
   */
  TRUST_GRAPH_EXPORT_SUMMARY(
      "trust-graph.export-summary",
      "Export Trust Graph summary",
      metadata(
          OperatorRecoveryActionCategory.TRUST_GRAPH,
          OperatorRecoverySeverity.INFO,
          Targets.TRUST_GRAPH,
          false,
          "Export metadata-only local Trust Graph RC state.",
          Fields.NONE)),
  /**
   * Represents destructive reset of local Trust Graph state.
   *
   * <p>The action is present so plans can report the limitation explicitly. It must remain blocked
   * or unavailable unless the backing store exposes a safe reset method for anchors, statements,
   * lifecycle state, and audit data.
   */
  TRUST_GRAPH_RESET_LOCAL_STATE(
      "trust-graph.reset-local-state",
      "Reset Trust Graph local state",
      metadata(
          OperatorRecoveryActionCategory.TRUST_GRAPH,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.TRUST_GRAPH,
          true,
          "Represent local reset only when a safe store reset API is available.",
          Fields.NONE)),
  /**
   * Represents destructive clearing of local Trust Graph audit state.
   *
   * <p>The action exists for workflow completeness but must not fake success. It remains blocked or
   * unavailable until a safe audit-clear operation is implemented and tested.
   */
  TRUST_GRAPH_CLEAR_AUDIT(
      "trust-graph.clear-audit",
      "Clear Trust Graph audit",
      metadata(
          OperatorRecoveryActionCategory.TRUST_GRAPH,
          OperatorRecoverySeverity.DESTRUCTIVE,
          Targets.TRUST_GRAPH,
          true,
          "Represent audit clearing only when a safe store audit-clear API is available.",
          Fields.NONE)),
  /**
   * Recomputes a metadata-only local Trust Graph summary.
   *
   * <p>The action re-reads bounded counts and summaries from the local handler. It does not expose
   * statement bodies, signatures, private identity material, or compatibility claims with legacy
   * Web of Trust systems.
   */
  TRUST_GRAPH_RECOMPUTE_SUMMARY(
      "trust-graph.recompute-summary",
      "Recompute Trust Graph summary",
      metadata(
          OperatorRecoveryActionCategory.TRUST_GRAPH,
          OperatorRecoverySeverity.INFO,
          Targets.TRUST_GRAPH,
          false,
          "Re-read Trust Graph status, anchors, subjects, statements, and audit counts.",
          Fields.NONE)),
  /**
   * Returns safe app-network budget snapshots.
   *
   * <p>The action is read-only. It reports counters, limits, active leases, operation names,
   * windows, and next availability without raw URIs, request bodies, response bodies, paths,
   * tokens, or queue internals.
   */
  NETWORK_BUDGET_VIEW(
      "network-budget.view",
      "View network budgets",
      metadata(
          OperatorRecoveryActionCategory.NETWORK_BUDGET,
          OperatorRecoverySeverity.INFO,
          Targets.NETWORK_BUDGET,
          false,
          "Read safe app-network budget snapshots.",
          Fields.NONE)),
  /**
   * Previews the redaction and section inventory for an operator support bundle.
   *
   * <p>The preview is read-only and lets the Web Shell show what will be included before export. It
   * must not contain app-data backup payloads, raw Trust Graph statements, tokens, passwords, or
   * local paths.
   */
  SUPPORT_BUNDLE_PREVIEW(
      "support-bundle.preview",
      "Preview support bundle",
      metadata(
          OperatorRecoveryActionCategory.SUPPORT,
          OperatorRecoverySeverity.INFO,
          Targets.SUPPORT,
          false,
          "Preview redaction and included sections before exporting a support bundle.",
          Fields.NONE)),
  /**
   * Generates the redacted operator support bundle.
   *
   * <p>The action returns the support artifact through typed recovery result details. It does not
   * perform remote upload, ticket creation, app-data backup download, or raw Trust Graph export.
   */
  SUPPORT_BUNDLE_EXPORT(
      "support-bundle.export",
      "Export support bundle",
      metadata(
          OperatorRecoveryActionCategory.SUPPORT,
          OperatorRecoverySeverity.INFO,
          Targets.SUPPORT,
          false,
          "Generate the redacted operator support bundle.",
          Fields.NONE));

  private final String jsonValue;
  private final String label;
  private final OperatorRecoveryActionCategory category;
  private final OperatorRecoverySeverity severity;
  private final String targetKind;
  private final boolean destructive;
  private final String description;
  private final String targetFields;

  private static ActionMetadata metadata(
      OperatorRecoveryActionCategory category,
      OperatorRecoverySeverity severity,
      String targetKind,
      boolean destructive,
      String description,
      String targetFields) {
    return new ActionMetadata(
        category, severity, targetKind, destructive, description, targetFields);
  }

  private record ActionMetadata(
      OperatorRecoveryActionCategory category,
      OperatorRecoverySeverity severity,
      String targetKind,
      boolean destructive,
      String description,
      String targetFields) {}

  private static final class Targets {
    private static final String APP = "app";
    private static final String APP_SERVICE_BUNDLE = "app-service-bundle";
    private static final String APP_SERVICE_GRANT = "app-service-grant";
    private static final String CATALOG = "catalog";
    private static final String NETWORK_BUDGET = "network-budget";
    private static final String SUBSCRIPTION = "subscription";
    private static final String SUPPORT = "support";
    private static final String TRUST_GRAPH = "trust-graph";

    private Targets() {}
  }

  private static final class Fields {
    private static final String APP_AND_CATALOG = "appId,catalogId";
    private static final String APP_AND_SUBSCRIPTION = "appId,subscriptionId";
    private static final String APP_ID = "appId";
    private static final String BUNDLE_ID = "bundleId";
    private static final String CATALOG_ID = "catalogId";
    private static final String GRANT_ID = "grantId";
    private static final String NONE = "";

    private Fields() {}
  }

  OperatorRecoveryActionId(String jsonValue, String label, ActionMetadata metadata) {
    this.jsonValue = jsonValue;
    this.label = label;
    this.category = metadata.category();
    this.severity = metadata.severity();
    this.targetKind = metadata.targetKind();
    this.destructive = metadata.destructive();
    this.description = metadata.description();
    this.targetFields = metadata.targetFields();
  }

  /**
   * Parses an action id using the public dotted token.
   *
   * <p>Parsing is case-insensitive after trimming so form submissions and Web Shell controls can
   * use stable JSON values without depending on enum names. Unknown, blank, or {@code null} values
   * return an empty result; callers decide whether to reject the request or display an unavailable
   * action.
   *
   * @param value submitted action token, usually a dotted value such as {@code app.rollback}
   * @return the matching allowlisted action, or an empty result when no constant matches
   */
  public static Optional<OperatorRecoveryActionId> fromJsonValue(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    return Arrays.stream(values())
        .filter(action -> action.jsonValue.equals(normalized))
        .findFirst();
  }

  /**
   * Returns the stable dotted JSON token accepted by the route dispatcher.
   *
   * <p>The token is the external identifier used by plan and execute requests. It is deliberately
   * not a path, command, or method name, which keeps recovery dispatch closed over this enum.
   *
   * @return the lowercase dotted token emitted in API JSON and accepted by form requests
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Returns the operator-facing action label.
   *
   * <p>The label is short enough for Web Shell buttons and release evidence. It is descriptive text
   * only; callers must use {@link #jsonValue()} when submitting a recovery action.
   *
   * @return the short human-readable label for this recovery action
   */
  public String label() {
    return label;
  }

  /**
   * Returns the grouping category.
   *
   * <p>Categories let dashboards group actions into catalog, app, subscription, app-service, Trust
   * Graph, network-budget, and support sections. They do not grant permission to execute an action.
   *
   * @return the presentation category associated with this action
   */
  public OperatorRecoveryActionCategory category() {
    return category;
  }

  /**
   * Returns the severity.
   *
   * <p>Severity is used for operator risk cues and plan summaries. Destructive severity generally
   * pairs with explicit confirmation, but callers should check {@link #requiresConfirmation()}
   * instead of deriving confirmation rules from presentation text.
   *
   * @return the operator-facing risk level for this action
   */
  public OperatorRecoverySeverity severity() {
    return severity;
  }

  /**
   * Returns the expected target kind.
   *
   * <p>The target kind is a compact JSON string used in plans, audit summaries, and support context
   * to describe what type of object the action operates on. It is not a class name or route path.
   *
   * @return the stable target-kind token used by recovery plans and results
   */
  public String targetKind() {
    return targetKind;
  }

  /**
   * Returns whether the action can remove or replace local state.
   *
   * <p>Destructive actions require explicit confirmation before execution. The flag is
   * intentionally conservative; operations that replace bundles, remove grants, delete
   * subscriptions, or reset local state are marked destructive even when app data is preserved.
   *
   * @return {@code true} when the action can remove or replace local operator-managed state
   */
  public boolean destructive() {
    return destructive;
  }

  /**
   * Returns whether execute requires a confirmation phrase.
   *
   * <p>The current RC workflow ties confirmation to the destructive flag. Keeping the method
   * separate makes call sites read in terms of execution policy rather than presentation severity.
   *
   * @return {@code true} when execute must include explicit confirmation for this action
   */
  public boolean requiresConfirmation() {
    return destructive;
  }

  /**
   * Returns a short safe description.
   *
   * <p>The description is suitable for ordinary dashboards, support-bundle metadata, and
   * release-certification evidence. It avoids local paths, raw URIs, backup payloads, request
   * bodies, and other sensitive operator state.
   *
   * @return the bounded operator-facing description for this recovery action
   */
  public String description() {
    return description;
  }

  /**
   * Returns required target fields for plan and execute requests.
   *
   * <p>The list is derived from a comma-separated constant string to keep enum construction compact
   * while still exposing a structured API. An action with no target fields returns an empty
   * immutable list.
   *
   * @return ordered request field names required to identify this action target
   */
  public List<String> targetFields() {
    if (targetFields.isBlank()) {
      return List.of();
    }
    return Arrays.stream(targetFields.split(",")).toList();
  }
}
