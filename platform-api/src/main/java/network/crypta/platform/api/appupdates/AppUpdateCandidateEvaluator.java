package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiAppAdmission;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogProductionMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogSecurityAdvisory;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecision;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Builds and revalidates catalog update candidates from authenticated catalog metadata.
 *
 * <p>This evaluator translates catalog entries into the bounded summaries consumed by the update
 * lifecycle. It compares versions, evaluates API and channel compatibility, attaches review and
 * security decisions, and computes permission changes against the installed manifest. Callers can
 * request candidates from every routine catalog or select one explicit catalog for a consented
 * source switch.
 *
 * <p>Catalog reads remain isolated when federation is active: a source that becomes unavailable
 * during a scan is omitted without changing the result for healthy catalogs. The evaluator does not
 * resolve cross-catalog conflicts or authorize a bundle mutation. Those decisions stay with the
 * federation and lifecycle authorities. Instances contain only references to host services; callers
 * provide the installed snapshot and update policy for each evaluation.
 */
final class AppUpdateCandidateEvaluator {
  /** Version relation used when the catalog version is greater than the installed version. */
  private static final String VERSION_NEWER = "newer";

  /** Version relation used when the catalog version is less than the installed version. */
  private static final String VERSION_LOWER = "lower";

  /** Version relation used when the catalog and installed versions are identical. */
  private static final String VERSION_EQUAL = "equal";

  /** Version relation used when the supported comparison cannot order the versions. */
  private static final String VERSION_AMBIGUOUS = "ambiguous";

  /** JSON field containing a summarized decision status. */
  private static final String JSON_STATUS = "status";

  /** JSON field containing a bounded operator-facing message. */
  private static final String JSON_MESSAGE = "message";

  /** Error code used when the local update policy rejects a catalog channel. */
  private static final String ERROR_CHANNEL_POLICY_BLOCKED = "channel_policy_blocked";

  /** Host service used to inspect installed manifests and process state. */
  private final AppHost appHost;

  /** Catalog service used for authenticated source, entry, and security-policy reads. */
  private final AppCatalogManager catalogManager;

  /** Review authority used to attach the current scoped receipt decision. */
  private final AppUpdateReviewAuthority reviewAuthority;

  /**
   * Creates an evaluator backed by the update lifecycle's host and catalog authorities.
   *
   * @param appHost host service used to inspect installed applications
   * @param catalogManager manager for authenticated catalog reads
   * @param reviewAuthority authority for locally scoped review decisions
   */
  AppUpdateCandidateEvaluator(
      AppHost appHost, AppCatalogManager catalogManager, AppUpdateReviewAuthority reviewAuthority) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.catalogManager = Objects.requireNonNull(catalogManager, "catalogManager");
    this.reviewAuthority = Objects.requireNonNull(reviewAuthority, "reviewAuthority");
  }

  /**
   * Builds the ordinary update candidate represented by one catalog entry.
   *
   * @param catalogId normalized identifier of the source catalog
   * @param entry authenticated catalog entry to summarize
   * @param installed current installed application snapshot
   * @param policy local policy controlling automatic channel eligibility
   * @return bounded update candidate derived from the supplied entry
   */
  AppUpdateCandidate candidate(
      String catalogId,
      AppCatalogEntry entry,
      InstalledAppSnapshot installed,
      AppUpdatePolicy policy) {
    String installedVersion = installed.manifest().appVersion();
    VersionDecision decision = versionDecision(entry.version(), installedVersion);
    Map<String, Object> apiCompatibility = apiCompatibility(entry);
    AppCatalogReviewMetadata review = entry.review();
    AppCatalogProductionMetadata productionMetadata = entry.productionMetadata();
    boolean channelPolicyAllowed = policyAllowsAutomaticCandidate(policy, productionMetadata);
    return new AppUpdateCandidate(
        installed.appId(),
        catalogId,
        catalogId,
        installedVersion,
        entry.version(),
        statusFor(decision, apiCompatibility),
        decision.label(),
        productionMetadata.channel().catalogValue(),
        productionMetadata.supportStatus().catalogValue(),
        deprecationSummary(productionMetadata),
        securityAdvisoriesSummary(productionMetadata),
        targetSecurityDecision(catalogId, entry),
        channelPolicyAllowed,
        channelPolicyAllowed ? null : ERROR_CHANNEL_POLICY_BLOCKED,
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        entry.bundleType(),
        AppUpdateCandidate.reviewSummary(
            review.status().catalogValue(), review.note().orElse(null)),
        reviewAuthority.reviewTrust(catalogId, entry),
        apiCompatibility,
        AppUpdateCandidate.permissionDelta(entry.permissions(), installed.manifest().permissions()),
        AppDataMigrationPlan.notChecked().toJsonValue(),
        appHost.status(installed.appId()).isPresent(),
        Instant.now());
  }

  /**
   * Builds a conflict-classification subject without applying normal version eligibility.
   *
   * @param catalogId normalized identifier of the source catalog
   * @param entry authenticated catalog entry to classify
   * @param installed current installation, or {@code null} when none exists
   * @return candidate containing the complete conflict-classification metadata
   */
  AppUpdateCandidate conflictCandidate(
      String catalogId, AppCatalogEntry entry, InstalledAppSnapshot installed) {
    AppCatalogProductionMetadata productionMetadata = entry.productionMetadata();
    String installedVersion =
        installed == null ? entry.version() : installed.manifest().appVersion();
    List<String> installedPermissions =
        installed == null ? List.of() : List.copyOf(installed.manifest().permissions());
    return new AppUpdateCandidate(
        entry.appId(),
        catalogId,
        catalogId,
        installedVersion,
        entry.version(),
        AppUpdateCandidateStatus.AVAILABLE,
        VERSION_EQUAL,
        productionMetadata.channel().catalogValue(),
        productionMetadata.supportStatus().catalogValue(),
        deprecationSummary(productionMetadata),
        securityAdvisoriesSummary(productionMetadata),
        targetSecurityDecision(catalogId, entry),
        true,
        null,
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        entry.bundleType(),
        AppUpdateCandidate.reviewSummary(
            entry.review().status().catalogValue(), entry.review().note().orElse(null)),
        reviewAuthority.reviewTrust(catalogId, entry),
        apiCompatibility(entry),
        AppUpdateCandidate.permissionDelta(entry.permissions(), installedPermissions),
        AppDataMigrationPlan.notChecked().toJsonValue(),
        installed != null && appHost.status(entry.appId()).isPresent(),
        Instant.now());
  }

  /**
   * Lists update candidates for an app across the currently usable catalog sources.
   *
   * @param appId exact application identifier to locate
   * @param installed current installed application snapshot
   * @param policy local policy controlling automatic channel eligibility
   * @param refresh whether each configured catalog should first be refreshed
   * @return immutable candidates from catalogs that remained usable during the scan
   */
  List<AppUpdateCandidate> catalogCandidates(
      String appId, InstalledAppSnapshot installed, AppUpdatePolicy policy, boolean refresh) {
    List<AppCatalogSourceSnapshot> catalogs = listCatalogs();
    if (refresh) {
      catalogs = refreshCatalogs(catalogs);
    }
    List<AppUpdateCandidate> matches = new ArrayList<>();
    for (AppCatalogSourceSnapshot catalog : catalogs) {
      for (AppCatalogEntry entry : listCatalogAppsForCandidateScan(catalog.catalogId())) {
        if (appId.equals(entry.appId())) {
          matches.add(candidate(catalog.catalogId(), entry, installed, policy));
        }
      }
    }
    return List.copyOf(matches);
  }

  /**
   * Lists every authenticated catalog subject needed for cross-catalog conflict evaluation.
   *
   * @param appId exact application identifier to locate
   * @param installed current installation, or {@code null} when none exists
   * @return immutable conflict subjects from all usable catalogs
   */
  List<AppUpdateCandidate> catalogConflictCandidates(String appId, InstalledAppSnapshot installed) {
    List<AppUpdateCandidate> matches = new ArrayList<>();
    for (AppCatalogSourceSnapshot catalog : listCatalogs()) {
      for (AppCatalogEntry entry : listCatalogAppsForCandidateScan(catalog.catalogId())) {
        if (appId.equals(entry.appId())) {
          matches.add(conflictCandidate(catalog.catalogId(), entry, installed));
        }
      }
    }
    return List.copyOf(matches);
  }

  /**
   * Returns the candidate from an exact operator-selected catalog, or {@code null} if absent.
   *
   * @param appId exact application identifier to locate
   * @param installed current installed application snapshot
   * @param policy local policy controlling automatic channel eligibility
   * @param targetCatalogId normalized catalog selected by the operator
   * @return matching candidate, or {@code null} when the catalog or app is absent
   */
  AppUpdateCandidate explicitCatalogCandidate(
      String appId,
      InstalledAppSnapshot installed,
      AppUpdatePolicy policy,
      String targetCatalogId) {
    for (AppCatalogSourceSnapshot catalog : listCatalogs()) {
      if (!targetCatalogId.equals(catalog.catalogId())) {
        continue;
      }
      for (AppCatalogEntry entry : listCatalogAppsForCandidateScan(catalog.catalogId())) {
        if (appId.equals(entry.appId())) {
          return candidate(catalog.catalogId(), entry, installed, policy);
        }
      }
      return null;
    }
    return null;
  }

  /**
   * Builds the no-update result for an installed app with no applicable catalog candidate.
   *
   * @param appId exact identifier of the installed application
   * @param installed current installed application snapshot
   * @return candidate that preserves installed compatibility and permission information
   */
  AppUpdateCandidate none(String appId, InstalledAppSnapshot installed) {
    return new AppUpdateCandidate(
        appId,
        "none",
        "none",
        installed.manifest().appVersion(),
        installed.manifest().appVersion(),
        AppUpdateCandidateStatus.NONE,
        VERSION_EQUAL,
        "stable",
        "supported",
        deprecationSummary(AppCatalogProductionMetadata.DEFAULT),
        List.of(),
        AppCatalogSecurityDecision.OK.toJsonValue(),
        true,
        null,
        "not_applicable",
        0L,
        "not_applicable",
        AppUpdateCandidate.reviewSummary(reviewAuthority.unreviewedStatus(), null),
        reviewAuthority.missingReviewTrust(),
        PlatformApiAppAdmission.summarizeAdmission(
            installed.manifest().apiCompatibility(), installed.manifest().permissions()),
        AppUpdateCandidate.permissionDelta(
            installed.manifest().permissions(), installed.manifest().permissions()),
        AppDataMigrationPlan.notRequired(
                installed.manifest().dataSchemaContract().currentSchemaVersion(),
                installed.manifest().dataSchemaContract().currentSchemaVersion())
            .toJsonValue(),
        appHost.status(appId).isPresent(),
        Instant.now());
  }

  /**
   * Reports whether a retained plan no longer matches the previously presented candidate.
   *
   * @param candidate candidate previously presented to the operator or scheduler
   * @param installed current installed application snapshot
   * @param plan retained catalog plan being revalidated
   * @return {@code true} when any material candidate subject changed
   */
  boolean planDiffers(
      AppUpdateCandidate candidate, InstalledAppSnapshot installed, AppCatalogInstallPlan plan) {
    AppCatalogEntry entry = plan.entry();
    if (!candidate.catalogId().equals(plan.catalogId())
        || !candidate.appId().equals(entry.appId())
        || !candidate.targetVersion().equals(entry.version())
        || !candidate.bundleSha256().equals(entry.bundleSha256())
        || candidate.bundleSizeBytes() != entry.bundleSizeBytes()
        || !candidate.bundleType().equals(entry.bundleType())) {
      return true;
    }
    AppCatalogReviewMetadata review = entry.review();
    AppCatalogProductionMetadata productionMetadata = entry.productionMetadata();
    Map<String, Object> reviewSummary =
        AppUpdateCandidate.reviewSummary(
            review.status().catalogValue(), review.note().orElse(null));
    Map<String, Object> permissionDelta =
        AppUpdateCandidate.permissionDelta(entry.permissions(), installed.manifest().permissions());
    return !candidate.review().equals(reviewSummary)
        || !candidate.channel().equals(productionMetadata.channel().catalogValue())
        || !candidate.supportStatus().equals(productionMetadata.supportStatus().catalogValue())
        || !candidate.deprecation().equals(deprecationSummary(productionMetadata))
        || !candidate.securityAdvisories().equals(securityAdvisoriesSummary(productionMetadata))
        || !candidate.securityDecision().equals(targetSecurityDecision(plan.catalogId(), entry))
        || !candidate.reviewTrust().equals(reviewAuthority.reviewTrust(plan.catalogId(), entry))
        || !candidate.apiCompatibility().equals(apiCompatibility(entry))
        || !candidate.permissionDelta().equals(permissionDelta);
  }

  /**
   * Returns the catalog-local security decision as a stable API summary.
   *
   * @param catalogId normalized catalog whose signed policy is evaluated
   * @param appId exact application identifier to evaluate
   * @return stable JSON-compatible security-decision map
   */
  Map<String, Object> catalogSecurityDecision(String catalogId, String appId) {
    return securityDecision(catalogId, appId).toJsonValue();
  }

  /**
   * Returns the aggregate installed-version security decision as a stable API summary.
   *
   * @param appId exact application identifier to evaluate
   * @param version exact installed version to evaluate
   * @return stable JSON-compatible aggregate security-decision map
   */
  Map<String, Object> installedSecurityDecision(String appId, String version) {
    return installedDecision(appId, version).toJsonValue();
  }

  /**
   * Combines catalog-local and installed-version security decisions for one target entry.
   *
   * @param catalogId normalized source catalog identifier
   * @param entry authenticated target entry to evaluate
   * @return stable JSON-compatible combined security decision
   */
  Map<String, Object> targetSecurityDecision(String catalogId, AppCatalogEntry entry) {
    return AppCatalogSecurityDecision.combine(
            List.of(
                securityDecision(catalogId, entry.appId()),
                installedDecision(entry.appId(), entry.version())))
        .toJsonValue();
  }

  /**
   * Lists routine catalogs and maps catalog-layer failures to Platform API failures.
   *
   * @return immutable snapshots for currently usable catalogs
   */
  private List<AppCatalogSourceSnapshot> listCatalogs() {
    try {
      return catalogManager.listCatalogs();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw catalogListFailure();
    }
  }

  /**
   * Refreshes each catalog independently and retains its previous snapshot on failure.
   *
   * @param catalogs current source snapshots to refresh
   * @return immutable refreshed-or-retained source snapshots
   */
  private List<AppCatalogSourceSnapshot> refreshCatalogs(List<AppCatalogSourceSnapshot> catalogs) {
    List<AppCatalogSourceSnapshot> refreshed = new ArrayList<>(catalogs.size());
    for (AppCatalogSourceSnapshot catalog : catalogs) {
      try {
        refreshed.add(catalogManager.refresh(catalog.catalogId()));
      } catch (AppCatalogException | IOException _) {
        refreshed.add(catalog);
      }
    }
    return List.copyOf(refreshed);
  }

  /**
   * Lists one catalog for a scan, isolating source-local failures in federation mode.
   *
   * @param catalogId normalized catalog identifier
   * @return authenticated entries, or an empty list for an isolated federated failure
   */
  private List<AppCatalogEntry> listCatalogAppsForCandidateScan(String catalogId) {
    try {
      return catalogManager.listRoutineApps(catalogId);
    } catch (AppCatalogException exception) {
      if (!catalogManager.federationEnabled()) {
        throw catalogFailure(exception);
      }
      return List.of();
    } catch (IOException _) {
      if (!catalogManager.federationEnabled()) {
        throw catalogListFailure();
      }
      return List.of();
    }
  }

  /**
   * Reads the catalog-local security decision, defaulting an absent decision to OK.
   *
   * @param catalogId normalized source catalog identifier
   * @param appId exact application identifier to evaluate
   * @return catalog-local security decision
   */
  private AppCatalogSecurityDecision securityDecision(String catalogId, String appId) {
    try {
      AppCatalogSecurityDecision decision = catalogManager.securityDecision(catalogId, appId);
      return Objects.requireNonNullElse(decision, AppCatalogSecurityDecision.OK);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw securityPolicyFailure();
    }
  }

  /**
   * Reads the aggregate installed-version decision, defaulting an absent decision to OK.
   *
   * @param appId exact application identifier to evaluate
   * @param version exact version to evaluate
   * @return aggregate installed-version security decision
   */
  private AppCatalogSecurityDecision installedDecision(String appId, String version) {
    try {
      AppCatalogSecurityDecision decision =
          catalogManager.installedSecurityDecision(appId, version);
      return Objects.requireNonNullElse(decision, AppCatalogSecurityDecision.OK);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw securityPolicyFailure();
    }
  }

  /**
   * Summarizes the entry's compatibility with the current Platform API contract.
   *
   * @param entry authenticated catalog entry to inspect
   * @return stable JSON-compatible compatibility summary
   */
  private static Map<String, Object> apiCompatibility(AppCatalogEntry entry) {
    return PlatformApiAppAdmission.summarizeAdmission(
        entry.compatibility().apiCompatibility(), entry.permissions());
  }

  /**
   * Reports whether local channel and deprecation policy permit automatic selection.
   *
   * @param policy local app-update policy
   * @param metadata authenticated production metadata from the catalog
   * @return {@code true} when the candidate may be selected automatically
   */
  private static boolean policyAllowsAutomaticCandidate(
      AppUpdatePolicy policy, AppCatalogProductionMetadata metadata) {
    return policy.allowsAutomaticChannel(metadata.channel())
        && !metadata.deprecatedForAutomaticUpdates();
  }

  /**
   * Creates the bounded deprecation summary exposed with a candidate.
   *
   * @param metadata authenticated catalog production metadata
   * @return stable JSON-compatible deprecation summary
   */
  private static Map<String, Object> deprecationSummary(AppCatalogProductionMetadata metadata) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(JSON_STATUS, metadata.deprecationStatus().catalogValue());
    json.put(JSON_MESSAGE, metadata.deprecationMessage().orElse(null));
    json.put("replacementAppId", metadata.replacementAppId().orElse(null));
    return json;
  }

  /**
   * Converts catalog security advisories to their bounded API representation.
   *
   * @param metadata authenticated catalog production metadata
   * @return immutable advisory summaries in catalog order
   */
  private static List<Map<String, Object>> securityAdvisoriesSummary(
      AppCatalogProductionMetadata metadata) {
    return metadata.securityAdvisories().stream()
        .map(AppUpdateCandidateEvaluator::securityAdvisorySummary)
        .toList();
  }

  /**
   * Converts one security advisory to its identifier-and-URI representation.
   *
   * @param advisory authenticated catalog advisory
   * @return stable JSON-compatible advisory summary
   */
  private static Map<String, Object> securityAdvisorySummary(AppCatalogSecurityAdvisory advisory) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("id", advisory.id());
    json.put("uri", advisory.uri().toString());
    return json;
  }

  /**
   * Maps version and API compatibility decisions to the public candidate status.
   *
   * @param decision closed version-relation decision
   * @param apiCompatibility summarized API compatibility result
   * @return candidate status presented by the lifecycle API
   */
  private static AppUpdateCandidateStatus statusFor(
      VersionDecision decision, Map<String, Object> apiCompatibility) {
    return switch (decision.label()) {
      case VERSION_NEWER ->
          apiCompatibilityBlocksUpdate(apiCompatibility)
              ? AppUpdateCandidateStatus.INCOMPATIBLE
              : AppUpdateCandidateStatus.AVAILABLE;
      case VERSION_AMBIGUOUS ->
          apiCompatibilityBlocksUpdate(apiCompatibility)
              ? AppUpdateCandidateStatus.INCOMPATIBLE
              : AppUpdateCandidateStatus.AMBIGUOUS;
      case VERSION_LOWER -> AppUpdateCandidateStatus.NOT_NEWER;
      case VERSION_EQUAL -> AppUpdateCandidateStatus.NONE;
      default -> AppUpdateCandidateStatus.AMBIGUOUS;
    };
  }

  /**
   * Reports whether the summarized API decision blocks the target update.
   *
   * @param apiCompatibility summarized API compatibility result
   * @return {@code true} when the compatibility status prevents updating
   */
  private static boolean apiCompatibilityBlocksUpdate(Map<String, Object> apiCompatibility) {
    String apiStatus = String.valueOf(apiCompatibility.get(JSON_STATUS));
    return "below_minimum".equals(apiStatus)
        || "incompatible".equals(apiStatus)
        || "unsupported-baseline".equals(apiStatus);
  }

  /**
   * Compares versions with the lifecycle's closed dotted-numeric version model.
   *
   * @param catalogVersion version declared by the catalog entry
   * @param installedVersion version declared by the installed manifest
   * @return closed relation label, including ambiguous when comparison is unsupported
   */
  private static VersionDecision versionDecision(String catalogVersion, String installedVersion) {
    if (catalogVersion == null || installedVersion == null) {
      return new VersionDecision(VERSION_AMBIGUOUS);
    }
    if (catalogVersion.equals(installedVersion)) {
      return new VersionDecision(VERSION_EQUAL);
    }
    Integer comparison =
        AppUpdateService.compareDottedNumericVersions(catalogVersion, installedVersion);
    if (comparison == null) {
      return new VersionDecision(VERSION_AMBIGUOUS);
    }
    return new VersionDecision(comparison > 0 ? VERSION_NEWER : VERSION_LOWER);
  }

  /**
   * Maps a catalog-domain failure to its stable Platform API status and code.
   *
   * @param exception catalog-domain failure to translate
   * @return Platform API exception preserving the bounded catalog error
   */
  private static PlatformApiException catalogFailure(AppCatalogException exception) {
    return switch (exception.errorCode()) {
      case "catalog_not_found", "app_not_found" ->
          new PlatformApiException(404, exception.errorCode(), exception.getMessage());
      case "catalog_conflict" ->
          new PlatformApiException(409, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_unavailable" ->
          new PlatformApiException(503, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_failed" ->
          new PlatformApiException(502, exception.errorCode(), exception.getMessage());
      default -> new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    };
  }

  /**
   * Creates the failure returned when catalog security policy cannot be read.
   *
   * @return stable internal-error response for security-policy reads
   */
  private static PlatformApiException securityPolicyFailure() {
    return new PlatformApiException(
        500, "catalog_security_policy_failed", "Failed to read catalog security policy.");
  }

  /**
   * Creates the failure returned when configured catalogs cannot be listed.
   *
   * @return stable internal-error response for catalog listing
   */
  private static PlatformApiException catalogListFailure() {
    return new PlatformApiException(500, "catalog_list_failed", "Failed to list app catalogs.");
  }

  /**
   * Holds the closed version-relation label used while building a candidate.
   *
   * @param label one of the evaluator's version relation constants
   */
  private record VersionDecision(String label) {}
}
