package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Redacted security decision derived from signed catalog security policy.
 *
 * <p>The decision is safe to expose through Platform API, Web Shell, CLI output, and release
 * certification. It contains only stable statuses, advisory ids, guidance, and boolean gate flags.
 * It never exposes raw catalog bytes, local scratch paths, signatures, private keys, request
 * bodies, or fetched content.
 *
 * <p>Callers should treat the boolean gates as authoritative, not as derived presentation details.
 * The display {@code action} records the strongest matching action, but combined decisions preserve
 * every lower-ranked gate that still applies. This matters when, for example, one advisory requires
 * acknowledgement and another blocks updates. Manual routes, staged-update validation, scheduler
 * policy, and Web Shell rendering can all consume the same object without needing access to the
 * original catalog policy.
 *
 * <p>Instances are immutable after construction. List components are copied defensively, and the
 * record equality semantics are used by update staging code to detect whether a previously
 * acknowledged candidate still matches the current security policy.
 *
 * @param status derived display and policy status for this decision
 * @param action strongest matching security action for display and errors
 * @param severity highest matching severity among all relevant advisories
 * @param advisoryIds bounded matching advisory ids in deterministic order
 * @param requiresAcknowledgement whether manual action needs security acknowledgement
 * @param blocksInstall whether install is blocked by current policy
 * @param blocksUpdate whether update, stage, or apply is blocked
 * @param blocksAutomaticApply whether unattended policy staging or apply is blocked
 * @param safeUninstallGuidance optional safe uninstall or export guidance
 * @param replacementAppId optional replacement guidance, never automatic migration
 * @param warnings bounded display-safe warnings in deterministic order
 */
public record AppCatalogSecurityDecision(
    AppCatalogSecurityDecisionStatus status,
    AppCatalogSecurityAction action,
    AppCatalogSecuritySeverity severity,
    List<String> advisoryIds,
    boolean requiresAcknowledgement,
    boolean blocksInstall,
    boolean blocksUpdate,
    boolean blocksAutomaticApply,
    String safeUninstallGuidance,
    String replacementAppId,
    List<String> warnings) {
  /**
   * No advisory or denylist entry applies.
   *
   * <p>This singleton is the neutral value used by older catalogs, missing policy fields, and
   * exact-version checks that find no denylist match. It carries no advisory ids and all gate flags
   * are false.
   */
  public static final AppCatalogSecurityDecision OK =
      new AppCatalogSecurityDecision(
          AppCatalogSecurityDecisionStatus.OK,
          AppCatalogSecurityAction.INFORM,
          AppCatalogSecuritySeverity.NONE,
          List.of(),
          false,
          false,
          false,
          false,
          null,
          null,
          List.of());

  /**
   * Creates a validated immutable decision.
   *
   * <p>The constructor requires the enum components and both list components to be present, then
   * copies the lists so callers cannot mutate advisory ids or warnings after publication. Optional
   * guidance is represented with nullable strings because JSON consumers receive the same shape.
   */
  public AppCatalogSecurityDecision {
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(action, "action");
    Objects.requireNonNull(severity, "severity");
    advisoryIds = List.copyOf(Objects.requireNonNull(advisoryIds, "advisoryIds"));
    warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
  }

  /**
   * Converts this decision to Platform API JSON-compatible values.
   *
   * <p>The map contains a stable field order and only scalar/list values that are safe for local
   * operator surfaces. The field names intentionally match the Platform API and Web Shell contract:
   * route handlers should pass the map through rather than re-deriving gate booleans from {@code
   * action}. Nullable guidance fields are preserved as {@code null} to avoid ambiguity with empty
   * operator guidance.
   *
   * @return stable redacted JSON value for API and UI summaries
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put("status", status.jsonValue());
    json.put("action", action.catalogValue());
    json.put("severity", severity.catalogValue());
    json.put("advisoryIds", advisoryIds);
    json.put("requiresAcknowledgement", requiresAcknowledgement);
    json.put("blocksInstall", blocksInstall);
    json.put("blocksUpdate", blocksUpdate);
    json.put("blocksAutomaticApply", blocksAutomaticApply);
    json.put("safeUninstallGuidance", safeUninstallGuidance);
    json.put("replacementAppId", replacementAppId);
    json.put("warnings", warnings);
    return json;
  }

  /**
   * Combines multiple catalog decisions, preserving the strongest action and highest severity.
   *
   * <p>This is used when an installed app version is checked against all verified configured
   * catalogs, and when a selected catalog entry must be combined with global exact-version
   * denylists from other configured catalogs. Advisory ids and warnings are deduplicated in
   * deterministic order. Gate booleans are accumulated with logical OR so a lower-ranked warning or
   * install block cannot disappear merely because a higher-ranked update block is also present.
   *
   * <p>If every supplied decision is neutral, the method returns {@link #OK}. A denylisted input
   * forces the combined status to {@code denylisted}; otherwise the strongest action determines the
   * status. The first non-null uninstall guidance and replacement app id are retained to keep
   * operator guidance deterministic.
   *
   * @param decisions non-null decisions from catalog-entry and exact-version checks
   * @return strongest combined decision with all gate booleans preserved
   */
  public static AppCatalogSecurityDecision combine(List<AppCatalogSecurityDecision> decisions) {
    Objects.requireNonNull(decisions, "decisions");
    if (decisions.isEmpty()) {
      return OK;
    }
    AppCatalogSecurityAction action = AppCatalogSecurityAction.INFORM;
    AppCatalogSecuritySeverity severity = AppCatalogSecuritySeverity.NONE;
    java.util.LinkedHashSet<String> advisoryIds = new java.util.LinkedHashSet<>();
    java.util.LinkedHashSet<String> warnings = new java.util.LinkedHashSet<>();
    boolean requiresAcknowledgement = false;
    boolean blocksInstall = false;
    boolean blocksUpdate = false;
    boolean blocksAutomaticApply = false;
    boolean denylisted = false;
    String safeUninstallGuidance = null;
    String replacementAppId = null;
    for (AppCatalogSecurityDecision decision : decisions) {
      AppCatalogSecurityDecision checked = Objects.requireNonNull(decision, "decision");
      action = AppCatalogSecurityAction.strongest(action, checked.action());
      severity = AppCatalogSecuritySeverity.max(severity, checked.severity());
      advisoryIds.addAll(checked.advisoryIds());
      warnings.addAll(checked.warnings());
      requiresAcknowledgement |= checked.requiresAcknowledgement();
      blocksInstall |= checked.blocksInstall();
      blocksUpdate |= checked.blocksUpdate();
      blocksAutomaticApply |= checked.blocksAutomaticApply();
      denylisted |= checked.status() == AppCatalogSecurityDecisionStatus.DENYLISTED;
      if (safeUninstallGuidance == null) {
        safeUninstallGuidance = checked.safeUninstallGuidance();
      }
      if (replacementAppId == null) {
        replacementAppId = checked.replacementAppId();
      }
    }
    if (advisoryIds.isEmpty()) {
      return OK;
    }
    AppCatalogSecurityDecisionStatus status =
        denylisted
            ? AppCatalogSecurityDecisionStatus.DENYLISTED
            : switch (action) {
              case INFORM -> AppCatalogSecurityDecisionStatus.INFORMATIONAL;
              case WARN -> AppCatalogSecurityDecisionStatus.WARNING;
              case BLOCK_INSTALL, BLOCK_UPDATE -> AppCatalogSecurityDecisionStatus.BLOCKED;
              case DENYLIST -> AppCatalogSecurityDecisionStatus.DENYLISTED;
            };
    return new AppCatalogSecurityDecision(
        status,
        action,
        severity,
        List.copyOf(advisoryIds),
        requiresAcknowledgement,
        blocksInstall,
        blocksUpdate,
        blocksAutomaticApply,
        safeUninstallGuidance,
        replacementAppId,
        List.copyOf(warnings));
  }
}
