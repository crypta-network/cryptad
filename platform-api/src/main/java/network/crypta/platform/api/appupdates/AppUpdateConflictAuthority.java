package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.FederatedCatalogConflictEngine;
import network.crypta.platform.appcatalog.FileFederatedCatalogConflictResolutionStore;
import network.crypta.platform.apphost.AppHost;

/**
 * Classifies and retains exact cross-catalog conflict decisions for the update lifecycle.
 *
 * <p>The authority converts current catalog candidates into canonical conflict subjects, invokes
 * {@link FederatedCatalogConflictEngine}, and applies only an exact locally stored resolution. It
 * keeps automatic selection separate from explicit source-switch consent and preserves an installed
 * origin when another catalog provides an exact duplicate.
 *
 * <p>Final mutation authorization retains the applicable resolution-store lookup until AppHost
 * completes its commit. A changed or stale subject set therefore cannot authorize different catalog
 * bytes. Security-policy disagreements always block simple preference decisions. This class
 * publishes bounded local summaries only; it does not produce reputation, moderation, or remotely
 * shared conflict state. Instances share the synchronization behavior of the federation authority
 * and resolution store.
 */
final class AppUpdateConflictAuthority {
  /** Error code used when multiple catalogs do not produce a valid conflict set. */
  private static final String ERROR_INVALID_CATALOG_CONFLICT = "invalid_catalog_conflict";

  /** Internal message paired with an invalid conflict-set construction failure. */
  private static final String MESSAGE_MULTIPLE_CATALOGS_NO_CONFLICT =
      "multiple catalogs produced no conflict";

  /** Federation authority that converts candidates to locally trusted conflict subjects. */
  private final AppUpdateFederationAuthority federationAuthority;

  /** File-backed store containing exact local conflict resolutions. */
  private final FileFederatedCatalogConflictResolutionStore resolutionStore;

  /**
   * Creates a conflict authority over the supplied federation and resolution services.
   *
   * @param federationAuthority authority for trusted subject construction
   * @param resolutionStore store containing exact local conflict decisions
   */
  AppUpdateConflictAuthority(
      AppUpdateFederationAuthority federationAuthority,
      FileFederatedCatalogConflictResolutionStore resolutionStore) {
    this.federationAuthority = Objects.requireNonNull(federationAuthority, "federationAuthority");
    this.resolutionStore = Objects.requireNonNull(resolutionStore, "resolutionStore");
  }

  /**
   * Selects or blocks a candidate under the current complete conflict set.
   *
   * @param candidates authenticated candidates for one application
   * @param securityDigests provider of catalog-local security decision digests
   * @return authorized candidate, blocked candidate, or {@code null} for one catalog
   */
  AppUpdateCandidate decision(
      List<AppUpdateCandidate> candidates, SecurityDigestProvider securityDigests) {
    List<AppUpdateCandidate> sorted = sorted(candidates);
    if (hasFewerThanTwoCatalogs(sorted)) {
      return null;
    }
    try {
      CurrentConflict current = current(sorted, securityDigests);
      return applyPolicy(sorted, current.subjects(), current.conflictSet(), current.lookup());
    } catch (IOException | AppCatalogException _) {
      return blocked(sorted, "catalog_conflict_policy_could_not_be_authenticated");
    }
  }

  /**
   * Summarizes the current exact cross-catalog conflict and local resolution.
   *
   * @param candidates authenticated candidates for one application
   * @param securityDigests provider of catalog-local security decision digests
   * @return stable JSON-compatible local conflict summary
   */
  Map<String, Object> summary(
      List<AppUpdateCandidate> candidates, SecurityDigestProvider securityDigests) {
    List<AppUpdateCandidate> sorted = sorted(candidates);
    requireMultipleCatalogs(sorted);
    try {
      return summarize(current(sorted, securityDigests));
    } catch (IOException _) {
      throw policyUnavailable();
    }
  }

  /**
   * Stores a resolution bound to the caller's exact current conflict subjects.
   *
   * @param candidates authenticated candidates for one application
   * @param securityDigests provider of catalog-local security decision digests
   * @param request exact conflict identity and local resolution request
   * @return stable summary of the newly applicable local decision
   */
  Map<String, Object> resolve(
      List<AppUpdateCandidate> candidates,
      SecurityDigestProvider securityDigests,
      ResolutionRequest request) {
    List<AppUpdateCandidate> sorted = sorted(candidates);
    requireMultipleCatalogs(sorted);
    CurrentConflict current;
    try {
      current = current(sorted, securityDigests);
    } catch (IOException _) {
      throw policyUnavailable();
    }
    FederatedCatalogConflictEngine.ConflictSet conflictSet = current.conflictSet();
    if (!conflictSet.conflictId().equals(request.expectedConflictId())
        || !conflictSet.subjectSetDigest().equals(request.expectedSubjectSetDigest())) {
      throw new PlatformApiException(
          409,
          "catalog_conflict_changed",
          "The catalog conflict subjects changed; inspect the current conflict before resolving"
              + " it.");
    }
    FederatedCatalogConflictEngine.Resolution resolution =
        new FederatedCatalogConflictEngine.Resolution(
            conflictSet.conflictId(),
            conflictSet.subjectSetDigest(),
            resolutionKind(request.kind()),
            Optional.ofNullable(request.catalogId()),
            Optional.ofNullable(request.publisherFingerprint()),
            Instant.now(),
            request.reason(),
            null);
    try {
      resolutionStore.put(conflictSet, resolution);
    } catch (IOException _) {
      throw new PlatformApiException(
          500,
          "catalog_conflict_resolution_write_failed",
          "The local catalog conflict resolution could not be stored.");
    }
    return summarize(
        new CurrentConflict(
            sorted,
            current.subjects(),
            conflictSet,
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.APPLICABLE,
                Optional.of(resolution))));
  }

  /**
   * Reports whether the current resolution permits an exact explicit source switch.
   *
   * @param candidates authenticated candidates for one application
   * @param selected exact operator-selected target candidate
   * @param securityDigests provider of catalog-local security decision digests
   * @return {@code true} when the current exact resolution requires an explicit switch
   */
  boolean explicitSourceSwitchAllows(
      List<AppUpdateCandidate> candidates,
      AppUpdateCandidate selected,
      SecurityDigestProvider securityDigests) {
    List<AppUpdateCandidate> sorted = sorted(candidates);
    if (hasFewerThanTwoCatalogs(sorted)) {
      return false;
    }
    try {
      CurrentConflict current = current(sorted, securityDigests);
      return explicitSourceSwitchAllows(current, selected);
    } catch (IOException | AppCatalogException _) {
      return false;
    }
  }

  /**
   * Reports whether an exact duplicate may preserve the installed catalog origin.
   *
   * @param candidates authenticated candidates for one application
   * @param selected candidate from the installed origin
   * @param selectedIsInstalledOrigin whether the selected catalog matches provenance
   * @param securityDigests provider of catalog-local security decision digests
   * @return {@code true} when exact-duplicate policy preserves this origin
   */
  boolean exactDuplicatePreservesInstalledOrigin(
      List<AppUpdateCandidate> candidates,
      AppUpdateCandidate selected,
      boolean selectedIsInstalledOrigin,
      SecurityDigestProvider securityDigests) {
    if (!selectedIsInstalledOrigin) {
      return false;
    }
    try {
      return exactDuplicateAllowsInstalledOrigin(
          current(sorted(candidates), securityDigests), selected);
    } catch (IOException | AppCatalogException _) {
      return false;
    }
  }

  /**
   * Reports whether an exact-duplicate resolution permits the selected catalog.
   *
   * @param candidates authenticated candidates for one application
   * @param selected exact operator-selected catalog candidate
   * @param securityDigests provider of catalog-local security decision digests
   * @return {@code true} when the exact current decision permits this candidate
   */
  boolean exactDuplicateAllowsSelectedCatalog(
      List<AppUpdateCandidate> candidates,
      AppUpdateCandidate selected,
      SecurityDigestProvider securityDigests) {
    try {
      return exactDuplicateAllowsSelectedCatalog(
          current(sorted(candidates), securityDigests), selected);
    } catch (IOException | AppCatalogException _) {
      return false;
    }
  }

  /**
   * Retains the exact conflict decision through the AppHost mutation commit.
   *
   * @param candidates authenticated candidates in the complete current subject set
   * @param selected exact candidate that will be committed
   * @param selectedIsInstalledOrigin whether the candidate preserves installed provenance
   * @param explicitSourceSwitchAuthorized whether exact consent already authorized switching
   * @param securityDigests provider of catalog-local security decision digests
   * @return closeable lease retaining the applicable conflict resolution
   * @throws IOException if the resolution store cannot retain an authenticated lookup
   */
  AppHost.CatalogMutationAuthorizationLease retainAuthorization(
      List<AppUpdateCandidate> candidates,
      AppUpdateCandidate selected,
      boolean selectedIsInstalledOrigin,
      boolean explicitSourceSwitchAuthorized,
      SecurityDigestProvider securityDigests)
      throws IOException {
    List<AppUpdateCandidate> sorted = sorted(candidates);
    if (hasFewerThanTwoCatalogs(sorted)) {
      return () -> {};
    }
    List<ConflictCandidate> subjects = subjects(sorted, securityDigests);
    FederatedCatalogConflictEngine.ConflictSet conflictSet = classify(subjects);
    FileFederatedCatalogConflictResolutionStore.RetainedLookup retained =
        resolutionStore.retainLookup(conflictSet);
    boolean transferred = false;
    try {
      CurrentConflict current =
          new CurrentConflict(sorted, subjects, conflictSet, retained.lookup());
      AppUpdateCandidate policyDecision =
          applyPolicy(sorted, subjects, conflictSet, retained.lookup());
      boolean explicitlyAllowed =
          explicitSourceSwitchAuthorized && explicitSourceSwitchAllows(current, selected);
      boolean installedDuplicateAllowed =
          selectedIsInstalledOrigin && exactDuplicateAllowsInstalledOrigin(current, selected);
      boolean selectedDuplicateAllowed = exactDuplicateAllowsSelectedCatalog(current, selected);
      if (!authorizes(
          policyDecision,
          selected,
          explicitlyAllowed,
          installedDuplicateAllowed,
          selectedDuplicateAllowed)) {
        throw unresolvedExactSubject();
      }
      transferred = true;
      return retained::close;
    } finally {
      if (!transferred) {
        retained.close();
      }
    }
  }

  /**
   * Evaluates whether current conflict policy authorizes one exact candidate.
   *
   * @param candidates authenticated candidates in the complete current subject set
   * @param selected exact candidate proposed for mutation
   * @param selectedIsInstalledOrigin whether the candidate preserves installed provenance
   * @param explicitSourceSwitchAuthorized whether exact consent already authorized switching
   * @param securityDigests provider of catalog-local security decision digests
   * @return {@code true} when the current conflict authority permits the target
   */
  boolean authorizes(
      List<AppUpdateCandidate> candidates,
      AppUpdateCandidate selected,
      boolean selectedIsInstalledOrigin,
      boolean explicitSourceSwitchAuthorized,
      SecurityDigestProvider securityDigests) {
    AppUpdateCandidate policyDecision = decision(candidates, securityDigests);
    if (policyDecision == null) {
      return true;
    }
    boolean explicitlyAllowed =
        explicitSourceSwitchAuthorized
            && explicitSourceSwitchAllows(candidates, selected, securityDigests);
    boolean installedDuplicateAllowed =
        exactDuplicatePreservesInstalledOrigin(
            candidates, selected, selectedIsInstalledOrigin, securityDigests);
    boolean selectedDuplicateAllowed =
        exactDuplicateAllowsSelectedCatalog(candidates, selected, securityDigests);
    return authorizes(
        policyDecision,
        selected,
        explicitlyAllowed,
        installedDuplicateAllowed,
        selectedDuplicateAllowed);
  }

  /**
   * Classifies candidates and reads the matching current resolution lookup.
   *
   * @param sorted deterministically ordered candidates
   * @param securityDigests provider of catalog-local security decision digests
   * @return current conflict subjects, classification, and resolution lookup
   * @throws IOException if the resolution store cannot be read safely
   */
  private CurrentConflict current(
      List<AppUpdateCandidate> sorted, SecurityDigestProvider securityDigests) throws IOException {
    List<ConflictCandidate> subjects = subjects(sorted, securityDigests);
    FederatedCatalogConflictEngine.ConflictSet conflictSet = classify(subjects);
    return new CurrentConflict(sorted, subjects, conflictSet, resolutionStore.lookup(conflictSet));
  }

  /**
   * Converts update candidates to conflict subjects in candidate order.
   *
   * @param candidates authenticated update candidates
   * @param securityDigests provider of catalog-local security decision digests
   * @return immutable candidate and conflict-subject pairs
   */
  private List<ConflictCandidate> subjects(
      List<AppUpdateCandidate> candidates, SecurityDigestProvider securityDigests) {
    return candidates.stream().map(candidate -> subject(candidate, securityDigests)).toList();
  }

  /**
   * Converts one update candidate to its locally trusted conflict subject.
   *
   * @param candidate authenticated update candidate
   * @param securityDigests provider of its catalog-local security digest
   * @return candidate paired with its conflict subject and local priority
   */
  private ConflictCandidate subject(
      AppUpdateCandidate candidate, SecurityDigestProvider securityDigests) {
    AppUpdateFederationAuthority.SubjectSelection selection =
        federationAuthority.conflictSubject(
            candidate,
            AppUpdateDigestSupport.reviewPolicyDigest(candidate),
            securityDigests.digest(candidate),
            AppUpdateDigestSupport.candidateMetadataDigest(candidate));
    return new ConflictCandidate(candidate, selection.subject(), selection.localPriority());
  }

  /**
   * Classifies a complete list of cross-catalog subjects.
   *
   * @param subjects candidate and conflict-subject pairs
   * @return deterministic nonempty conflict set
   */
  private static FederatedCatalogConflictEngine.ConflictSet classify(
      List<ConflictCandidate> subjects) {
    return FederatedCatalogConflictEngine.classify(
            subjects.stream().map(ConflictCandidate::subject).toList())
        .orElseThrow(AppUpdateConflictAuthority::invalidConflict);
  }

  /**
   * Applies hard-conflict rules and the exact stored resolution.
   *
   * @param candidates authenticated update candidates
   * @param subjects corresponding locally trusted conflict subjects
   * @param conflictSet deterministic classification of the subjects
   * @param lookup current exact resolution-store lookup
   * @return selected or blocked lifecycle candidate
   */
  private static AppUpdateCandidate applyPolicy(
      List<AppUpdateCandidate> candidates,
      List<ConflictCandidate> subjects,
      FederatedCatalogConflictEngine.ConflictSet conflictSet,
      FileFederatedCatalogConflictResolutionStore.Lookup lookup) {
    if (conflictSet
        .types()
        .contains(FederatedCatalogConflictEngine.Type.SECURITY_POLICY_DISAGREEMENT)) {
      return blocked(candidates, "security_policy_disagreement_requires_operator_action");
    }
    if (lookup.applicable()) {
      return applyResolution(candidates, subjects, conflictSet, lookup.resolution().orElseThrow());
    }
    if (isExactDuplicate(conflictSet)) {
      return selectUniqueLocalPriority(subjects)
          .orElseGet(
              () ->
                  blocked(
                      candidates, "exact_duplicate_requires_unique_local_priority_or_resolution"));
    }
    String reason =
        lookup.status() == FileFederatedCatalogConflictResolutionStore.LookupStatus.STALE
            ? "stored_catalog_conflict_resolution_is_stale"
            : "multiple_catalog_origins_require_an_exact_local_resolution";
    return blocked(candidates, reason);
  }

  /**
   * Applies one exact applicable local resolution to the current subjects.
   *
   * @param candidates authenticated update candidates
   * @param subjects corresponding locally trusted conflict subjects
   * @param conflictSet deterministic classification of the subjects
   * @param resolution exact applicable local resolution
   * @return selected or blocked lifecycle candidate
   */
  private static AppUpdateCandidate applyResolution(
      List<AppUpdateCandidate> candidates,
      List<ConflictCandidate> subjects,
      FederatedCatalogConflictEngine.ConflictSet conflictSet,
      FederatedCatalogConflictEngine.Resolution resolution) {
    return switch (resolution.kind()) {
      case PIN_CATALOG ->
          selectCatalog(subjects, resolution.catalogId().orElseThrow())
              .orElseGet(() -> blocked(candidates, "pinned_catalog_is_not_available"));
      case PIN_PUBLISHER ->
          selectPublisher(subjects, resolution.publisherFingerprint().orElseThrow())
              .orElseGet(() -> blocked(candidates, "pinned_publisher_is_not_unique"));
      case PREFER_CATALOG ->
          conflictSet.hard()
              ? blocked(candidates, "catalog_preference_cannot_resolve_hard_conflict")
              : selectCatalog(subjects, resolution.catalogId().orElseThrow())
                  .orElseGet(() -> blocked(candidates, "preferred_catalog_is_not_available"));
      case ALLOW_EXACT_DUPLICATE ->
          isExactDuplicate(conflictSet)
              ? selectUniqueLocalPriority(subjects)
                  .orElseGet(
                      () ->
                          blocked(
                              candidates,
                              "exact_duplicate_requires_explicit_catalog_or_unique_local_priority"))
              : blocked(candidates, "exact_duplicate_resolution_does_not_match_conflict");
      case UNRESOLVED, BLOCKED, EXPLICIT_SOURCE_SWITCH_REQUIRED, QUARANTINED ->
          blocked(candidates, "local_catalog_conflict_resolution_blocks_selection");
    };
  }

  /**
   * Evaluates explicit-source-switch policy against one selected candidate.
   *
   * @param current current exact conflict state
   * @param selected exact operator-selected candidate
   * @return {@code true} when explicit switching is required and allowed
   */
  private static boolean explicitSourceSwitchAllows(
      CurrentConflict current, AppUpdateCandidate selected) {
    return !current
            .conflictSet()
            .types()
            .contains(FederatedCatalogConflictEngine.Type.SECURITY_POLICY_DISAGREEMENT)
        && current.lookup().applicable()
        && current.lookup().resolution().orElseThrow().kind()
            == FederatedCatalogConflictEngine.ResolutionKind.EXPLICIT_SOURCE_SWITCH_REQUIRED
        && current.subjects().stream().anyMatch(item -> sameCandidate(item.candidate(), selected));
  }

  /**
   * Evaluates whether an exact duplicate may retain installed provenance.
   *
   * @param current current exact conflict state
   * @param selected candidate associated with installed provenance
   * @return {@code true} when no conflicting exact resolution blocks it
   */
  private static boolean exactDuplicateAllowsInstalledOrigin(
      CurrentConflict current, AppUpdateCandidate selected) {
    if (current.subjects().stream().noneMatch(item -> sameCandidate(item.candidate(), selected))
        || !isExactDuplicate(current.conflictSet())
        || current
            .conflictSet()
            .types()
            .contains(FederatedCatalogConflictEngine.Type.SECURITY_POLICY_DISAGREEMENT)) {
      return false;
    }
    return !current.lookup().applicable()
        || current.lookup().resolution().orElseThrow().kind()
            == FederatedCatalogConflictEngine.ResolutionKind.ALLOW_EXACT_DUPLICATE;
  }

  /**
   * Evaluates an exact-duplicate resolution for an explicitly selected catalog.
   *
   * @param current current exact conflict state
   * @param selected exact selected catalog candidate
   * @return {@code true} when the resolution permits the selected subject
   */
  private static boolean exactDuplicateAllowsSelectedCatalog(
      CurrentConflict current, AppUpdateCandidate selected) {
    return isExactDuplicate(current.conflictSet())
        && current.lookup().applicable()
        && current.lookup().resolution().orElseThrow().kind()
            == FederatedCatalogConflictEngine.ResolutionKind.ALLOW_EXACT_DUPLICATE
        && current.subjects().stream().anyMatch(item -> sameCandidate(item.candidate(), selected));
  }

  /**
   * Combines ordinary selection and the three explicit exception paths.
   *
   * @param policyDecision candidate selected or blocked by current policy
   * @param selected exact candidate proposed for mutation
   * @param explicitlyAllowed whether source-switch policy permits the candidate
   * @param installedDuplicateAllowed whether installed provenance may be preserved
   * @param selectedDuplicateAllowed whether an exact duplicate permits this catalog
   * @return {@code true} when at least one exact authorization path applies
   */
  private static boolean authorizes(
      AppUpdateCandidate policyDecision,
      AppUpdateCandidate selected,
      boolean explicitlyAllowed,
      boolean installedDuplicateAllowed,
      boolean selectedDuplicateAllowed) {
    return policyDecision.status() == AppUpdateCandidateStatus.BLOCKED
        ? explicitlyAllowed || installedDuplicateAllowed || selectedDuplicateAllowed
        : sameCandidate(selected, policyDecision)
            || installedDuplicateAllowed
            || selectedDuplicateAllowed;
  }

  /**
   * Compares the exact catalog and bundle identity of two candidates.
   *
   * @param left first candidate to compare
   * @param right second candidate to compare
   * @return {@code true} when all mutation-relevant candidate fields match
   */
  static boolean sameCandidate(AppUpdateCandidate left, AppUpdateCandidate right) {
    return left.catalogId().equals(right.catalogId())
        && left.catalogSourceId().equals(right.catalogSourceId())
        && left.appId().equals(right.appId())
        && left.targetVersion().equals(right.targetVersion())
        && left.bundleSha256().equals(right.bundleSha256())
        && left.bundleSizeBytes() == right.bundleSizeBytes()
        && left.bundleType().equals(right.bundleType());
  }

  /**
   * Selects the candidate supplied by one exact catalog.
   *
   * @param subjects current candidate and conflict-subject pairs
   * @param catalogId normalized catalog identifier to select
   * @return matching candidate when the catalog is present
   */
  private static Optional<AppUpdateCandidate> selectCatalog(
      List<ConflictCandidate> subjects, String catalogId) {
    return subjects.stream()
        .filter(item -> item.subject().catalogId().equals(catalogId))
        .map(ConflictCandidate::candidate)
        .findFirst();
  }

  /**
   * Selects a uniquely preferred candidate under one publisher fingerprint.
   *
   * @param subjects current candidate and conflict-subject pairs
   * @param fingerprint exact publisher key fingerprint to select
   * @return uniquely highest-priority matching candidate when one exists
   */
  private static Optional<AppUpdateCandidate> selectPublisher(
      List<ConflictCandidate> subjects, String fingerprint) {
    return selectUniqueLocalPriority(
        subjects.stream()
            .filter(item -> item.subject().publisherFingerprint().equals(fingerprint))
            .toList());
  }

  /**
   * Selects a candidate only when one subject has the unique highest local priority.
   *
   * @param subjects candidate subjects eligible for local-priority selection
   * @return unique highest-priority candidate, or an empty value on a tie
   */
  private static Optional<AppUpdateCandidate> selectUniqueLocalPriority(
      List<ConflictCandidate> subjects) {
    int highest = subjects.stream().mapToInt(ConflictCandidate::localPriority).max().orElse(-1);
    List<AppUpdateCandidate> highestPriority =
        subjects.stream()
            .filter(item -> item.localPriority() == highest)
            .map(ConflictCandidate::candidate)
            .toList();
    return highestPriority.size() == 1 ? Optional.of(highestPriority.getFirst()) : Optional.empty();
  }

  /**
   * Reports whether a conflict set contains only the exact-duplicate classification.
   *
   * @param conflictSet deterministic conflict classification
   * @return {@code true} when exact duplicate is the sole conflict type
   */
  private static boolean isExactDuplicate(FederatedCatalogConflictEngine.ConflictSet conflictSet) {
    return conflictSet.types().equals(Set.of(FederatedCatalogConflictEngine.Type.EXACT_DUPLICATE));
  }

  /**
   * Converts current conflict state to its bounded operator-facing representation.
   *
   * @param current current exact conflict state
   * @return stable JSON-compatible conflict summary
   */
  private static Map<String, Object> summarize(CurrentConflict current) {
    FederatedCatalogConflictEngine.ConflictSet conflictSet = current.conflictSet();
    LinkedHashMap<String, Object> summary = new LinkedHashMap<>();
    summary.put("appId", conflictSet.appId());
    summary.put("conflictId", conflictSet.conflictId());
    summary.put("subjectSetDigestSha256", conflictSet.subjectSetDigest());
    summary.put(
        "types",
        conflictSet.types().stream()
            .map(type -> type.name().toLowerCase(Locale.ROOT))
            .sorted()
            .toList());
    summary.put("hard", conflictSet.hard());
    summary.put(
        "subjects",
        current.subjects().stream().map(AppUpdateConflictAuthority::subjectSummary).toList());
    summary.put("resolutionStatus", current.lookup().status().name().toLowerCase(Locale.ROOT));
    summary.put(
        "resolution",
        current
            .lookup()
            .resolution()
            .map(AppUpdateConflictAuthority::resolutionSummary)
            .orElse(null));
    summary.put("localDecisionOnly", true);
    summary.put("publishedAsModeration", false);
    return summary;
  }

  /**
   * Converts one conflict subject to its bounded digest-only representation.
   *
   * @param candidate candidate and locally trusted conflict subject
   * @return stable JSON-compatible subject summary
   */
  private static Map<String, Object> subjectSummary(ConflictCandidate candidate) {
    FederatedCatalogConflictEngine.Subject subject = candidate.subject();
    LinkedHashMap<String, Object> summary = new LinkedHashMap<>();
    summary.put("catalogId", subject.catalogId());
    summary.put("catalogTrustDigestSha256", subject.catalogTrustDigest());
    summary.put("version", subject.version());
    summary.put("bundleDigestSha256", subject.bundleDigest());
    summary.put("bundleType", subject.bundleType());
    summary.put("publisherFingerprintSha256", subject.publisherFingerprint());
    summary.put("publisherLineageDigestSha256", subject.publisherLineageDigest());
    summary.put("reviewPolicyDigestSha256", subject.reviewPolicyDigest());
    summary.put("securityDecisionDigestSha256", subject.securityDecision());
    summary.put("metadataDigestSha256", subject.metadataDigest());
    return summary;
  }

  /**
   * Converts one local resolution to its bounded operator-facing representation.
   *
   * @param resolution exact locally stored resolution
   * @return stable JSON-compatible resolution summary
   */
  private static Map<String, Object> resolutionSummary(
      FederatedCatalogConflictEngine.Resolution resolution) {
    LinkedHashMap<String, Object> summary = new LinkedHashMap<>();
    summary.put("kind", resolution.kind().name().toLowerCase(Locale.ROOT));
    summary.put("catalogId", resolution.catalogId().orElse(null));
    summary.put("publisherFingerprintSha256", resolution.publisherFingerprint().orElse(null));
    summary.put("decidedAt", resolution.decidedAt().toString());
    summary.put("reason", resolution.reason());
    summary.put("selfDigestSha256", resolution.selfDigest());
    return summary;
  }

  /**
   * Returns candidates in deterministic catalog, version, and bundle order.
   *
   * @param candidates authenticated candidates to order
   * @return immutable deterministic candidate list
   */
  private static List<AppUpdateCandidate> sorted(List<AppUpdateCandidate> candidates) {
    return candidates.stream()
        .sorted(
            Comparator.comparing(AppUpdateCandidate::catalogId)
                .thenComparing(AppUpdateCandidate::targetVersion)
                .thenComparing(AppUpdateCandidate::bundleSha256))
        .toList();
  }

  /**
   * Reports whether candidates contain fewer than two distinct catalogs.
   *
   * @param candidates candidates to inspect
   * @return {@code true} when cross-catalog classification is unnecessary
   */
  private static boolean hasFewerThanTwoCatalogs(List<AppUpdateCandidate> candidates) {
    return candidates.stream().map(AppUpdateCandidate::catalogId).distinct().count() < 2;
  }

  /**
   * Requires candidates from at least two distinct catalogs.
   *
   * @param candidates candidates supplied to an operator conflict operation
   */
  private static void requireMultipleCatalogs(List<AppUpdateCandidate> candidates) {
    if (hasFewerThanTwoCatalogs(candidates)) {
      throw new PlatformApiException(
          404,
          "catalog_conflict_not_found",
          "No current cross-catalog conflict exists for this app.");
    }
  }

  /**
   * Parses the closed resolution kind supplied by the operator API.
   *
   * @param kind exact enum spelling from the validated request
   * @return parsed local resolution kind
   */
  private static FederatedCatalogConflictEngine.ResolutionKind resolutionKind(String kind) {
    try {
      return FederatedCatalogConflictEngine.ResolutionKind.valueOf(
          Objects.requireNonNull(kind, "kind"));
    } catch (IllegalArgumentException _) {
      throw new PlatformApiException(
          400, "invalid_catalog_conflict_resolution", "Catalog conflict resolution is invalid.");
    }
  }

  /**
   * Converts the deterministic first candidate to a bounded blocked result.
   *
   * @param candidates nonempty deterministic candidate list
   * @param reason bounded local conflict reason
   * @return blocked lifecycle candidate
   */
  private static AppUpdateCandidate blocked(List<AppUpdateCandidate> candidates, String reason) {
    return candidates.getFirst().blockedByCatalogConflict(reason);
  }

  /**
   * Creates the internal failure for an invalid multi-catalog classification.
   *
   * @return stable invalid-conflict Platform API exception
   */
  private static PlatformApiException invalidConflict() {
    return new PlatformApiException(
        500, ERROR_INVALID_CATALOG_CONFLICT, MESSAGE_MULTIPLE_CATALOGS_NO_CONFLICT);
  }

  /**
   * Creates the failure used when current conflict policy cannot be authenticated.
   *
   * @return stable conflict-policy-unavailable Platform API exception
   */
  private static PlatformApiException policyUnavailable() {
    return new PlatformApiException(
        500,
        "catalog_conflict_policy_unavailable",
        "The current catalog conflict policy could not be authenticated.");
  }

  /**
   * Creates the failure used when a retained decision does not authorize the target.
   *
   * @return stable unresolved-conflict Platform API exception
   */
  private static PlatformApiException unresolvedExactSubject() {
    return new PlatformApiException(
        409,
        "catalog_conflict_unresolved",
        "The retained cross-catalog conflict decision does not authorize this exact subject.");
  }

  /** Supplies a catalog-local security-decision digest for one update candidate. */
  @FunctionalInterface
  interface SecurityDigestProvider {
    /**
     * Returns the digest used in the candidate's conflict subject.
     *
     * @param candidate authenticated candidate being classified
     * @return lowercase SHA-256 digest of catalog-local security policy
     */
    String digest(AppUpdateCandidate candidate);
  }

  /**
   * Carries an exact operator request to resolve the currently displayed conflict.
   *
   * @param expectedConflictId conflict identifier presented to the operator
   * @param expectedSubjectSetDigest exact digest of the displayed subject set
   * @param kind requested closed local resolution kind
   * @param catalogId optional normalized catalog selected by the resolution
   * @param publisherFingerprint optional publisher fingerprint selected by the resolution
   * @param reason bounded operator reason retained in local audit state
   */
  record ResolutionRequest(
      String expectedConflictId,
      String expectedSubjectSetDigest,
      String kind,
      String catalogId,
      String publisherFingerprint,
      String reason) {
    /** Validates required conflict identity and audit fields. */
    ResolutionRequest {
      Objects.requireNonNull(expectedConflictId, "expectedConflictId");
      Objects.requireNonNull(expectedSubjectSetDigest, "expectedSubjectSetDigest");
      Objects.requireNonNull(kind, "kind");
      Objects.requireNonNull(reason, "reason");
    }
  }

  /**
   * Associates an update candidate with its canonical conflict subject and local priority.
   *
   * @param candidate update candidate represented by the subject
   * @param subject canonical conflict-engine subject
   * @param localPriority operator-configured priority from catalog trust
   */
  private record ConflictCandidate(
      AppUpdateCandidate candidate,
      FederatedCatalogConflictEngine.Subject subject,
      int localPriority) {}

  /**
   * Holds one immutable classification and its exact resolution lookup.
   *
   * @param candidates deterministic authenticated candidate list
   * @param subjects candidate and canonical conflict-subject pairs
   * @param conflictSet deterministic classification over all subjects
   * @param lookup exact current resolution-store lookup
   */
  private record CurrentConflict(
      List<AppUpdateCandidate> candidates,
      List<ConflictCandidate> subjects,
      FederatedCatalogConflictEngine.ConflictSet conflictSet,
      FileFederatedCatalogConflictResolutionStore.Lookup lookup) {
    /** Copies mutable inputs and validates the retained classification state. */
    private CurrentConflict {
      candidates = List.copyOf(candidates);
      subjects = List.copyOf(subjects);
      Objects.requireNonNull(conflictSet, "conflictSet");
      Objects.requireNonNull(lookup, "lookup");
    }
  }
}
