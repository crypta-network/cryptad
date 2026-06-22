package network.crypta.platform.appcatalog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Catalog-level signed security advisory and exact version denylist policy.
 *
 * <p>The policy is authenticated by the catalog signature. Entry-level advisory references remain
 * advisory display metadata for v3 compatibility, but when an entry references a catalog-level
 * advisory record from this policy the advisory can now produce enforceable warning/blocking
 * decisions. Exact denylist entries are stronger: they match an app id and version even if the
 * catalog entry does not reference the advisory.
 *
 * <p>The policy is immutable and deterministic after construction. Duplicate advisory ids,
 * duplicate denylist ids, duplicate exact app-version denylist matches, and denylist references to
 * unknown advisories are rejected at construction time. That keeps signed catalog parsing
 * fail-closed before install or update policy sees the data. Version matching is deliberately exact
 * in this first enforcement layer; range handling would need a separate bounded version-range model
 * before it could be safe for automatic update decisions.
 *
 * <p>Callers normally use {@link #decisionFor(AppCatalogEntry)} for a candidate catalog entry and
 * {@link #decisionForInstalledVersion(String, String)} for installed-version visibility across
 * configured catalogs. Both paths return redacted decisions suitable for operator-facing surfaces.
 *
 * @param advisories catalog-level advisory records in deterministic signed order
 * @param denylist exact app-version denylist entries in deterministic signed order
 */
public record AppCatalogSecurityPolicy(
    List<AppCatalogSecurityAdvisoryRecord> advisories,
    List<AppCatalogVersionDenylistEntry> denylist) {
  /**
   * Empty policy used by v1-v3 catalogs and older callers.
   *
   * <p>The empty policy keeps older catalog versions compatible while making the absence of signed
   * security-policy fields explicit. Decisions produced from this policy are always neutral.
   */
  public static final AppCatalogSecurityPolicy EMPTY =
      new AppCatalogSecurityPolicy(List.of(), List.of());

  /**
   * Creates a validated immutable policy.
   *
   * <p>The constructor normalizes both collections into immutable deterministic order and verifies
   * referential integrity between denylist entries and advisory records. It rejects ambiguous exact
   * denylist matches so one signed catalog cannot provide competing reasons or guidance for the
   * same app id and version.
   *
   * @throws AppCatalogException if the policy contains duplicates or broken advisory references
   */
  public AppCatalogSecurityPolicy {
    advisories = normalizeAdvisories(advisories);
    denylist = normalizeDenylist(denylist, advisories);
  }

  /**
   * Returns whether the policy contains signed security data.
   *
   * <p>This is used by catalog writing and compatibility validation to decide whether v4
   * security-policy fields are present. Older catalogs with no policy data should behave exactly
   * like {@link #EMPTY}.
   *
   * @return true when at least one advisory or denylist entry exists
   */
  public boolean hasCatalogFields() {
    return !advisories.isEmpty() || !denylist.isEmpty();
  }

  /**
   * Looks up one advisory record by id.
   *
   * <p>The lookup applies the same advisory-id normalization used by the parser. Invalid ids fail
   * closed through the shared catalog validation path instead of returning an empty result for
   * malformed input.
   *
   * @param advisoryId advisory id from an entry reference or denylist entry
   * @return advisory record when the normalized id exists in this policy
   */
  public Optional<AppCatalogSecurityAdvisoryRecord> advisory(String advisoryId) {
    String normalized = AppCatalogSecurityAdvisory.normalizeId(advisoryId, "advisoryId");
    return advisories.stream().filter(advisory -> advisory.id().equals(normalized)).findFirst();
  }

  /**
   * Computes a security decision for a catalog entry.
   *
   * <p>Entry-level advisory references only contribute while the referenced catalog-level advisory
   * is in an enforcing lifecycle state such as {@code active} or {@code published}. Exact denylist
   * matches contribute regardless of the advisory lifecycle status while the denylist entry remains
   * present in the signed catalog.
   *
   * <p>The result is the correct decision for manual install/update checks and app-update candidate
   * creation for this entry. It includes entry advisory actions and exact denylist matches from the
   * same signed catalog. Callers that need configured-catalog-wide denylist coverage should combine
   * this decision with installed/exact-version decisions from other trusted catalogs.
   *
   * @param entry verified catalog entry being considered for distribution
   * @return redacted security decision for the candidate entry
   */
  public AppCatalogSecurityDecision decisionFor(AppCatalogEntry entry) {
    Objects.requireNonNull(entry, "entry");
    DecisionBuilder builder = new DecisionBuilder();
    applyEntryAdvisories(builder, entry);
    applyDenylist(builder, entry.appId(), entry.version());
    return builder.build();
  }

  /**
   * Computes a security decision for an exact installed app version.
   *
   * <p>This path is used when an installed vulnerable version must be visible even when no
   * immediately installable replacement entry exists in the current catalog.
   *
   * <p>Only exact denylist entries are considered here. Entry-level advisory references are tied to
   * catalog entries and cannot be inferred for an arbitrary installed version. The method therefore
   * provides the narrow, stable signal needed by update summaries, Web Shell installed-app cards,
   * and staged-update revalidation.
   *
   * @param appId installed app id to compare with exact denylist entries
   * @param version installed app version to compare with exact denylist entries
   * @return redacted security decision for the exact installed version
   */
  public AppCatalogSecurityDecision decisionForInstalledVersion(String appId, String version) {
    DecisionBuilder builder = new DecisionBuilder();
    applyDenylist(builder, appId, version);
    return builder.build();
  }

  /**
   * Converts the policy to JSON-compatible values for operator-facing summaries.
   *
   * <p>The returned map contains lists of already-redacted advisory and denylist metadata. It does
   * not include catalog signatures, local source paths, fetched catalog bodies, or bundle staging
   * paths. Field order is stable for deterministic release evidence and easier Web Shell rendering.
   *
   * @return redacted advisory and denylist metadata for operator surfaces
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put(
        "advisories",
        advisories.stream().map(AppCatalogSecurityAdvisoryRecord::toJsonValue).toList());
    json.put(
        "denylist", denylist.stream().map(AppCatalogVersionDenylistEntry::toJsonValue).toList());
    return json;
  }

  private void applyEntryAdvisories(DecisionBuilder builder, AppCatalogEntry entry) {
    for (AppCatalogSecurityAdvisory reference : entry.productionMetadata().securityAdvisories()) {
      advisory(reference.id())
          .filter(AppCatalogSecurityAdvisoryRecord::active)
          .ifPresent(advisory -> builder.addAdvisory(advisory, null));
    }
  }

  private void applyDenylist(DecisionBuilder builder, String appId, String version) {
    for (AppCatalogVersionDenylistEntry entry : denylist) {
      if (!entry.matches(appId, version)) {
        continue;
      }
      AppCatalogSecurityAdvisoryRecord advisory =
          advisory(entry.advisoryId())
              .orElseThrow(
                  () ->
                      AppCatalogSidecars.invalidEntry(
                          "denylist entry references unknown advisory: " + entry.advisoryId()));
      builder.addDenylist(advisory, entry);
    }
  }

  private static List<AppCatalogSecurityAdvisoryRecord> normalizeAdvisories(
      List<AppCatalogSecurityAdvisoryRecord> advisories) {
    Objects.requireNonNull(advisories, "advisories");
    LinkedHashMap<String, AppCatalogSecurityAdvisoryRecord> byId = new LinkedHashMap<>();
    for (AppCatalogSecurityAdvisoryRecord advisory : advisories) {
      AppCatalogSecurityAdvisoryRecord checked = Objects.requireNonNull(advisory, "advisory");
      AppCatalogSecurityAdvisoryRecord previous = byId.putIfAbsent(checked.id(), checked);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry(
            "duplicate catalog security advisory id: " + checked.id());
      }
    }
    return List.copyOf(byId.values());
  }

  private static List<AppCatalogVersionDenylistEntry> normalizeDenylist(
      List<AppCatalogVersionDenylistEntry> denylist,
      List<AppCatalogSecurityAdvisoryRecord> advisories) {
    Objects.requireNonNull(denylist, "denylist");
    Set<String> advisoryIds = new LinkedHashSet<>();
    for (AppCatalogSecurityAdvisoryRecord advisory : advisories) {
      advisoryIds.add(advisory.id());
    }
    LinkedHashMap<String, AppCatalogVersionDenylistEntry> byId = new LinkedHashMap<>();
    Set<String> exactMatches = new LinkedHashSet<>();
    for (AppCatalogVersionDenylistEntry entry : denylist) {
      AppCatalogVersionDenylistEntry checked = Objects.requireNonNull(entry, "denylist entry");
      if (!advisoryIds.contains(checked.advisoryId())) {
        throw AppCatalogSidecars.invalidEntry(
            "denylist entry references unknown advisory: " + checked.advisoryId());
      }
      AppCatalogVersionDenylistEntry previous = byId.putIfAbsent(checked.id(), checked);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry(
            "duplicate catalog security denylist id: " + checked.id());
      }
      String exactKey = checked.appId() + '\n' + checked.version();
      if (!exactMatches.add(exactKey)) {
        throw AppCatalogSidecars.invalidEntry(
            "duplicate catalog security denylist app version: "
                + checked.appId()
                + " "
                + checked.version());
      }
    }
    return List.copyOf(byId.values());
  }

  private static final class DecisionBuilder {
    private AppCatalogSecurityAction action = AppCatalogSecurityAction.INFORM;
    private AppCatalogSecuritySeverity severity = AppCatalogSecuritySeverity.NONE;
    private final LinkedHashSet<String> advisoryIds = new LinkedHashSet<>();
    private final ArrayList<String> warnings = new ArrayList<>();
    private String safeUninstallGuidance;
    private String replacementAppId;
    private boolean requiresAcknowledgement;
    private boolean blocksInstall;
    private boolean blocksUpdate;
    private boolean blocksAutomaticApply;
    private boolean denylisted;

    private void addAdvisory(
        AppCatalogSecurityAdvisoryRecord advisory, AppCatalogVersionDenylistEntry denylistEntry) {
      AppCatalogSecurityAction effectiveAction =
          denylistEntry == null ? advisory.action() : AppCatalogSecurityAction.DENYLIST;
      advisoryIds.add(advisory.id());
      action = AppCatalogSecurityAction.strongest(action, effectiveAction);
      severity = AppCatalogSecuritySeverity.max(severity, advisory.severity());
      requiresAcknowledgement |= effectiveAction.requiresAcknowledgement();
      blocksInstall |= effectiveAction.blocksInstall();
      blocksUpdate |= effectiveAction.blocksUpdate();
      blocksAutomaticApply |= effectiveAction.blocksAutomaticApply();
      if (denylistEntry != null) {
        denylistEntry.safeUninstallGuidance().ifPresent(value -> safeUninstallGuidance = value);
        denylistEntry.replacementAppId().ifPresent(value -> replacementAppId = value);
        warnings.add(denylistEntry.reason());
      }
      if (safeUninstallGuidance == null) {
        safeUninstallGuidance = advisory.safeUninstallGuidance().orElse(null);
      }
      if (replacementAppId == null) {
        replacementAppId = advisory.replacementAppId().orElse(null);
      }
      if (denylistEntry == null && advisory.action() == AppCatalogSecurityAction.WARN) {
        warnings.add("Security advisory requires operator acknowledgement.");
      }
    }

    private void addDenylist(
        AppCatalogSecurityAdvisoryRecord advisory, AppCatalogVersionDenylistEntry denylistEntry) {
      denylisted = true;
      addAdvisory(advisory, denylistEntry);
    }

    private AppCatalogSecurityDecision build() {
      if (advisoryIds.isEmpty()) {
        return AppCatalogSecurityDecision.OK;
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
}
