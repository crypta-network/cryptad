package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Handles operator-facing catalog metadata operations for {@link AppCatalogManager}.
 *
 * <p>This collaborator keeps mirror administration, source-health projection, rollback candidate
 * evaluation, rollback execution, and signing-key rotation status out of the main catalog manager.
 * The manager still owns synchronization and high-level lifecycle entry points; this class performs
 * the smaller operational workflows while reusing the same source store and trusted-key provider.
 *
 * <p>All data returned from this class is derived from verified catalog sidecars, retained revision
 * metadata, or bounded source metadata. It does not expose raw catalog bytes, signature bytes,
 * private insert URIs, local scratch paths, staged bundle paths, or trusted-key material.
 */
final class AppCatalogOperations {
  private static final String APP_NOT_FOUND_MESSAGE = "Catalog app not found.";

  private final AppCatalogSourceStore sourceStore;
  private final AppCatalogManager.TrustedKeyProvider trustedKeyProvider;
  private final AppCatalogFetcher fetcher;
  private final FileFederatedCatalogTrustStore federatedTrustStore;

  AppCatalogOperations(
      AppCatalogSourceStore sourceStore,
      AppCatalogManager.TrustedKeyProvider trustedKeyProvider,
      AppCatalogFetcher fetcher,
      FileFederatedCatalogTrustStore federatedTrustStore) {
    this.sourceStore = Objects.requireNonNull(sourceStore, "sourceStore");
    this.trustedKeyProvider = Objects.requireNonNull(trustedKeyProvider, "trustedKeyProvider");
    this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
    this.federatedTrustStore = federatedTrustStore;
  }

  boolean hasTrustedCatalogKey(String keyId) throws IOException {
    if (keyId == null || keyId.isBlank()) {
      return false;
    }
    return trustedKeyProvider
        .trustedKeys()
        .findActiveForVerification(keyId.trim(), Instant.now())
        .isPresent();
  }

  AppCatalogSourceSnapshot addSource(String rawSource, String expectedCatalogId)
      throws IOException {
    AppCatalogSource source = AppCatalogSource.parse(rawSource);
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    FetchedCatalog fetched = fetcher.fetch(source);
    AppCatalog catalog =
        AppCatalogTrustVerification.verifyRoutine(
            fetched.catalogBytes(),
            fetched.signatureBytes(),
            trustedKeys,
            expectedCatalogId,
            federatedTrustStore);
    rejectUnexpectedCatalog(catalog, expectedCatalogId);
    rejectExistingCatalog(catalog);
    Instant now = Instant.now();
    Optional<FederatedCatalogTrustBinding> binding = trustBinding(catalog.catalogId());
    sourceStore.write(
        new AppCatalogSourceStore.VerifiedCatalogWrite(
            catalog,
            source,
            fetched,
            now,
            now,
            binding.map(FederatedCatalogTrustBinding::bindingId),
            binding.map(FederatedCatalogTrustBinding::selfDigest)),
        new AppCatalogSourceStore.EndpointWriteState(
            AppCatalogMirror.primary(source, now),
            List.of(AppCatalogMirror.primary(source, now)),
            Map.of()));
    return AppCatalogSourceSnapshot.of(
        catalog,
        source,
        now,
        now,
        AppCatalogSourceRefreshMetadata.success(now, resolvedCatalogUri(fetched, source)),
        fetched);
  }

  /** Re-verifies one stored source and projects its bounded operator-facing snapshot. */
  AppCatalogSourceSnapshot snapshot(StoredCatalogSource stored, TrustedAppKeys trustedKeys) {
    AppCatalog catalog = verifyStoredCatalog(stored, trustedKeys);
    return snapshot(stored, catalog);
  }

  /** Reads and re-verifies one configured source for bounded operator display. */
  AppCatalogSourceSnapshot catalogSnapshot(String catalogId, TrustedAppKeys trustedKeys)
      throws IOException {
    return snapshot(sourceStore.read(catalogId), trustedKeys);
  }

  /** Lists routine-authorized federated sources while isolating source-local failures. */
  List<AppCatalogSourceSnapshot> listFederatedRoutineCatalogs(TrustedAppKeys trustedKeys)
      throws IOException {
    List<AppCatalogSourceSnapshot> activeCatalogs = new ArrayList<>();
    for (String catalogId : sourceStore.configuredCatalogIds()) {
      try {
        StoredCatalogSource stored = sourceStore.read(catalogId);
        activeCatalogs.add(snapshot(stored, verifyRoutine(stored, trustedKeys)));
      } catch (AppCatalogException | IOException _) {
        // The affected catalog remains unavailable without changing unrelated trust decisions.
      }
    }
    return List.copyOf(activeCatalogs);
  }

  /** Reads one stored source and verifies that it remains authorized for routine work. */
  AppCatalog readRoutineCatalog(String catalogId, TrustedAppKeys trustedKeys) throws IOException {
    return verifyRoutine(sourceStore.read(catalogId), trustedKeys);
  }

  /** Selects one app from a source that remains authorized for routine work. */
  AppCatalogEntry getRoutineApp(
      StoredCatalogSource stored, String appId, TrustedAppKeys trustedKeys) throws IOException {
    AppCatalogEntry entry = requireApp(verifyRoutine(stored, trustedKeys), appId);
    requireRoutineChannel(stored.catalogId(), entry);
    return entry;
  }

  /** Reads one stored source and verifies it under bounded historical inspection policy. */
  AppCatalog readVerifiedCatalog(String catalogId, TrustedAppKeys trustedKeys) throws IOException {
    return verifyStoredCatalog(sourceStore.read(catalogId), trustedKeys);
  }

  /** Lists entries from one re-verified configured catalog. */
  List<AppCatalogEntry> listApps(String catalogId) throws IOException {
    return readVerifiedCatalog(catalogId, trustedKeyProvider.trustedKeys()).entries();
  }

  /** Lists entries that the current catalog binding authorizes for routine work. */
  List<AppCatalogEntry> listRoutineApps(String catalogId) throws IOException {
    AppCatalog catalog = readRoutineCatalog(catalogId, trustedKeyProvider.trustedKeys());
    Optional<FederatedCatalogTrustBinding> binding = trustBinding(catalogId);
    if (binding.isEmpty()) {
      return catalog.entries();
    }
    return catalog.entries().stream()
        .filter(
            entry -> binding.get().allowedChannels().contains(entry.productionMetadata().channel()))
        .toList();
  }

  /** Selects one app from a re-verified configured catalog. */
  AppCatalogEntry getApp(String catalogId, String appId) throws IOException {
    return requireApp(readVerifiedCatalog(catalogId, trustedKeyProvider.trustedKeys()), appId);
  }

  /** Computes one catalog-local signed security decision. */
  AppCatalogSecurityDecision securityDecision(String catalogId, String appId) throws IOException {
    AppCatalog catalog = readVerifiedCatalog(catalogId, trustedKeyProvider.trustedKeys());
    return catalog.securityPolicy().decisionFor(requireApp(catalog, appId));
  }

  /** Collects active federated security decisions without allowing one source to disable peers. */
  List<AppCatalogSecurityDecision> installedFederatedSecurityDecisions(
      String appId, String version, TrustedAppKeys trustedKeys) throws IOException {
    List<AppCatalogSecurityDecision> decisions = new ArrayList<>();
    for (String catalogId : sourceStore.configuredCatalogIds()) {
      try {
        AppCatalog catalog = readRoutineCatalog(catalogId, trustedKeys);
        decisions.add(catalog.securityPolicy().decisionForInstalledVersion(appId, version));
      } catch (AppCatalogException | IOException _) {
        // A locally unauthorized source contributes no security decision and cannot disable peers.
      }
    }
    return List.copyOf(decisions);
  }

  /** Verifies one stored source for active routine work under its exact local trust binding. */
  AppCatalog verifyRoutine(StoredCatalogSource stored, TrustedAppKeys trustedKeys)
      throws IOException {
    AppCatalogTrustVerification.requireStoredBinding(stored, federatedTrustStore);
    return AppCatalogTrustVerification.verifyRoutine(
        stored.fetchedCatalog().catalogBytes(),
        stored.fetchedCatalog().signatureBytes(),
        trustedKeys,
        stored.catalogId(),
        federatedTrustStore);
  }

  /** Verifies one stored source for bounded historical inspection. */
  AppCatalog verifyStoredCatalog(StoredCatalogSource stored, TrustedAppKeys trustedKeys) {
    try {
      AppCatalogTrustVerification.requireHistoricalStoredBinding(stored, federatedTrustStore);
      return AppCatalogTrustVerification.verifyHistorical(
          stored.fetchedCatalog().catalogBytes(),
          stored.fetchedCatalog().signatureBytes(),
          trustedKeys,
          stored.catalogId(),
          federatedTrustStore);
    } catch (IOException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "failed to verify stored catalog trust",
          exception);
    }
  }

  private AppCatalogSourceSnapshot historicalSnapshot(
      StoredCatalogSource stored, TrustedAppKeys trustedKeys) {
    try {
      AppCatalogTrustVerification.requireHistoricalStoredBinding(stored, federatedTrustStore);
      AppCatalog catalog =
          AppCatalogTrustVerification.verifyHistorical(
              stored.fetchedCatalog().catalogBytes(),
              stored.fetchedCatalog().signatureBytes(),
              trustedKeys,
              stored.catalogId(),
              federatedTrustStore);
      return snapshot(stored, catalog);
    } catch (IOException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "failed to verify stored historical catalog trust",
          exception);
    }
  }

  private static AppCatalogSourceSnapshot snapshot(StoredCatalogSource stored, AppCatalog catalog) {
    return AppCatalogSourceSnapshot.of(
        catalog,
        stored.source(),
        stored.addedAt(),
        stored.refreshedAt(),
        stored.refreshMetadata(),
        stored.fetchedCatalog());
  }

  private static AppCatalogEntry requireApp(AppCatalog catalog, String appId) {
    return catalog
        .entry(appId)
        .orElseThrow(
            () -> new AppCatalogException(AppCatalogSidecars.APP_NOT_FOUND, APP_NOT_FOUND_MESSAGE));
  }

  List<AppCatalogMirror> refreshEndpoints(StoredCatalogSource stored, boolean primaryOnly) {
    return stored.mirrors().stream()
        .filter(mirror -> !primaryOnly || mirror.role() == AppCatalogSourceRole.PRIMARY)
        .filter(AppCatalogMirror::enabled)
        .sorted(
            Comparator.comparing(AppCatalogMirror::role)
                .thenComparingInt(AppCatalogMirror::priority)
                .thenComparing(mirror -> mirror.id().value()))
        .toList();
  }

  List<AppCatalogMirror> listMirrors(String catalogId) throws IOException {
    return sourceStore.read(AppCatalogManager.normalizeCatalogIdForLookup(catalogId)).mirrors();
  }

  List<AppCatalogMirrorHealth> sourceHealth(String catalogId) throws IOException {
    String normalizedCatalogId = AppCatalogManager.normalizeCatalogIdForLookup(catalogId);
    StoredCatalogSource stored = sourceStore.read(normalizedCatalogId);
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    AppCatalog catalog = verifyStoredCatalog(stored, trustedKeys);
    AppCatalogVerifiedRevision currentRevision =
        currentRevision(
                normalizedCatalogId, AppCatalogRevisions.catalogDigest(stored.fetchedCatalog()))
            .orElse(null);
    Map<AppCatalogMirrorId, AppCatalogMirrorHealth> health =
        new LinkedHashMap<>(stored.mirrorHealth());
    if (currentRevision != null) {
      putCurrentRevisionHealth(health, currentRevision);
    }
    addPrimaryHealthWhenCurrent(stored, catalog, currentRevision, health);
    return sourceHealthEntries(stored, currentRevision, health);
  }

  AppCatalogMirror addMirror(
      String catalogId, String rawMirrorId, String rawSource, int priority, boolean enabled)
      throws IOException {
    StoredCatalogSource stored =
        sourceStore.read(AppCatalogManager.normalizeCatalogIdForLookup(catalogId));
    AppCatalogSource source = AppCatalogSource.parse(rawSource);
    AppCatalogMirrorId mirrorId = requestedMirrorId(rawMirrorId, stored.mirrors());
    rejectPrimaryMirror(mirrorId, "primary source cannot be added as mirror");
    rejectDuplicateMirror(stored.mirrors(), mirrorId, source);
    AppCatalogMirror mirror =
        new AppCatalogMirror(
            mirrorId,
            AppCatalogSourceRole.MIRROR,
            source,
            resolvedPriority(priority, stored.mirrors()),
            enabled,
            Instant.now());
    ArrayList<AppCatalogMirror> mirrors = new ArrayList<>(stored.mirrors());
    mirrors.add(mirror);
    sourceStore.writeMirrors(stored.catalogId(), mirrors);
    clearMirrorHealth(stored.catalogId(), stored.mirrorHealth(), mirrorId);
    return mirror;
  }

  AppCatalogMirror updateMirror(
      String catalogId, String mirrorId, String rawSource, Integer priority, Boolean enabled)
      throws IOException {
    StoredCatalogSource stored =
        sourceStore.read(AppCatalogManager.normalizeCatalogIdForLookup(catalogId));
    AppCatalogMirrorId id = AppCatalogMirrorId.parse(mirrorId);
    rejectPrimaryMirror(id, "primary source cannot be updated here");
    AppCatalogSource requestedSource = requestedSource(rawSource);
    if (requestedSource != null) {
      rejectDuplicateMirrorSource(stored.mirrors(), id, requestedSource);
    }
    MirrorUpdateResult result =
        updateMirrorList(stored.mirrors(), id, requestedSource, priority, enabled);
    sourceStore.writeMirrors(stored.catalogId(), result.mirrors());
    if (result.sourceChanged()) {
      clearMirrorHealth(stored.catalogId(), stored.mirrorHealth(), id);
    }
    return result.updated();
  }

  void removeMirror(String catalogId, String mirrorId) throws IOException {
    StoredCatalogSource stored =
        sourceStore.read(AppCatalogManager.normalizeCatalogIdForLookup(catalogId));
    AppCatalogMirrorId id = AppCatalogMirrorId.parse(mirrorId);
    rejectPrimaryMirror(id, "primary source cannot be removed");
    List<AppCatalogMirror> mirrors =
        stored.mirrors().stream().filter(mirror -> !mirror.id().equals(id)).toList();
    if (mirrors.size() == stored.mirrors().size()) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog mirror not found.");
    }
    sourceStore.writeMirrors(stored.catalogId(), mirrors);
    clearMirrorHealth(stored.catalogId(), stored.mirrorHealth(), id);
  }

  List<AppCatalogRollbackCandidate> rollbackCandidates(String catalogId) throws IOException {
    String normalizedCatalogId = AppCatalogManager.normalizeCatalogIdForLookup(catalogId);
    StoredCatalogSource stored = sourceStore.read(normalizedCatalogId);
    String currentDigest = AppCatalogRevisions.catalogDigest(stored.fetchedCatalog());
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    return sourceStore.listRevisions(normalizedCatalogId, currentDigest).stream()
        .map(revision -> rollbackCandidate(stored, revision, trustedKeys))
        .toList();
  }

  AppCatalogSourceSnapshot rollback(String catalogId, String revisionDigest, String reason)
      throws IOException {
    String rollbackReason = normalizedRollbackReason(reason);
    String normalizedCatalogId = AppCatalogManager.normalizeCatalogIdForLookup(catalogId);
    StoredCatalogSource stored = sourceStore.read(normalizedCatalogId);
    AppCatalogTrustVerification.requireHistoricalStoredBinding(stored, federatedTrustStore);
    FetchedCatalog fetched = sourceStore.readRevision(normalizedCatalogId, revisionDigest);
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    AppCatalog catalog =
        AppCatalogTrustVerification.verifyHistorical(
            fetched.catalogBytes(),
            fetched.signatureBytes(),
            trustedKeys,
            normalizedCatalogId,
            federatedTrustStore);
    if (!normalizedCatalogId.equals(catalog.catalogId())) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_ID_MISMATCH, "rollback catalog id does not match source");
    }
    AppCatalogVerifiedRevision revision = revisionForRollback(stored, revisionDigest);
    Instant now = Instant.now();
    AppCatalogMirror endpoint = endpointForRevision(stored, revision);
    String resolvedUri = resolvedUriForRevision(revision, endpoint);
    sourceStore.write(
        new AppCatalogSourceStore.VerifiedCatalogWrite(
            catalog,
            stored.source(),
            fetched,
            stored.addedAt(),
            now,
            stored.trustBindingId(),
            stored.trustBindingDigest()),
        new AppCatalogSourceStore.EndpointWriteState(
            endpoint,
            stored.mirrors(),
            rollbackHealth(stored, endpoint, fetched, catalog, now, resolvedUri, rollbackReason),
            resolvedUri,
            rollbackReason));
    return historicalSnapshot(sourceStore.read(normalizedCatalogId), trustedKeys);
  }

  private Optional<FederatedCatalogTrustBinding> trustBinding(String catalogId) throws IOException {
    if (federatedTrustStore == null) {
      return Optional.empty();
    }
    return Optional.of(
        federatedTrustStore
            .findByCatalogId(catalogId)
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "federated catalog admission requires a local trust binding")));
  }

  private void requireRoutineChannel(String catalogId, AppCatalogEntry entry) throws IOException {
    Optional<FederatedCatalogTrustBinding> binding = trustBinding(catalogId);
    if (binding.isPresent()
        && !binding.get().allowedChannels().contains(entry.productionMetadata().channel())) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "catalog app channel is not allowed by the local catalog binding");
    }
  }

  AppCatalogKeyRotationStatus keyRotationStatus(String catalogId) throws IOException {
    String normalizedCatalogId = AppCatalogManager.normalizeCatalogIdForLookup(catalogId);
    StoredCatalogSource stored = sourceStore.read(normalizedCatalogId);
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    String currentKeyId =
        AppCatalogVerifier.readSignature(stored.fetchedCatalog().signatureBytes()).keyId();
    boolean trusted =
        trustedKeys.findHistoricalForVerification(currentKeyId, Instant.now()).isPresent();
    if (trusted) {
      verifyStoredCatalog(stored, trustedKeys);
    }
    Optional<String> previousKeyId = previousKeyId(normalizedCatalogId, stored, currentKeyId);
    List<String> blockers = trusted ? List.of() : List.of("current_key_not_trusted");
    return new AppCatalogKeyRotationStatus(
        keyRotationStatusValue(trusted, previousKeyId.isPresent()),
        Optional.of(currentKeyId),
        previousKeyId,
        trusted,
        AppCatalogKeyRotationPlan.empty(),
        blockers);
  }

  Optional<Instant> currentGeneratedAt(StoredCatalogSource stored, TrustedAppKeys trustedKeys) {
    String currentDigest = AppCatalogRevisions.catalogDigest(stored.fetchedCatalog());
    try {
      Optional<Instant> retainedCurrent =
          sourceStore.listRevisions(stored.catalogId(), currentDigest).stream()
              .filter(AppCatalogVerifiedRevision::current)
              .map(AppCatalogVerifiedRevision::generatedAt)
              .findFirst();
      if (retainedCurrent.isPresent()) {
        return retainedCurrent;
      }
    } catch (AppCatalogException | IOException _) {
      // Damaged history must not block a verified fresh fetch from repairing the cache.
    }
    try {
      return Optional.of(verifyStoredCatalog(stored, trustedKeys).generatedAt());
    } catch (AppCatalogException _) {
      return Optional.empty();
    }
  }

  AppCatalogMirrorHealth previousHealth(
      Map<AppCatalogMirrorId, AppCatalogMirrorHealth> health,
      AppCatalogMirror endpoint,
      StoredCatalogSource stored,
      TrustedAppKeys trustedKeys) {
    AppCatalogMirrorHealth existing = health.get(endpoint.id());
    if (existing != null) {
      return existing;
    }
    if (endpoint.role() == AppCatalogSourceRole.PRIMARY) {
      try {
        AppCatalog catalog = verifyStoredCatalog(stored, trustedKeys);
        return AppCatalogMirrorHealth.primary(
            stored.refreshMetadata(), stored.fetchedCatalog(), catalog.generatedAt());
      } catch (AppCatalogException _) {
        // A damaged cached catalog must not prevent refresh from trying configured transports.
      }
    }
    return AppCatalogMirrorHealth.skipped(endpoint);
  }

  private static void addPrimaryHealthWhenCurrent(
      StoredCatalogSource stored,
      AppCatalog catalog,
      AppCatalogVerifiedRevision currentRevision,
      Map<AppCatalogMirrorId, AppCatalogMirrorHealth> health) {
    if (currentRevision == null || AppCatalogMirrorId.PRIMARY.equals(currentRevision.sourceId())) {
      health.putIfAbsent(
          AppCatalogMirrorId.PRIMARY,
          AppCatalogMirrorHealth.primary(
              stored.refreshMetadata(), stored.fetchedCatalog(), catalog.generatedAt()));
    }
  }

  private static List<AppCatalogMirrorHealth> sourceHealthEntries(
      StoredCatalogSource stored,
      AppCatalogVerifiedRevision currentRevision,
      Map<AppCatalogMirrorId, AppCatalogMirrorHealth> health) {
    ArrayList<AppCatalogMirrorHealth> entries = new ArrayList<>();
    for (AppCatalogMirror mirror : stored.mirrors()) {
      entries.add(health.getOrDefault(mirror.id(), AppCatalogMirrorHealth.skipped(mirror)));
    }
    if (currentRevision != null) {
      addRetainedCurrentRevisionHealth(entries, currentRevision, health);
    }
    return List.copyOf(entries);
  }

  private static void addRetainedCurrentRevisionHealth(
      List<AppCatalogMirrorHealth> entries,
      AppCatalogVerifiedRevision revision,
      Map<AppCatalogMirrorId, AppCatalogMirrorHealth> health) {
    if (entries.stream().noneMatch(entry -> entry.id().equals(revision.sourceId()))) {
      entries.add(health.getOrDefault(revision.sourceId(), healthFromRevision(revision)));
    }
  }

  private static void putCurrentRevisionHealth(
      Map<AppCatalogMirrorId, AppCatalogMirrorHealth> health,
      AppCatalogVerifiedRevision currentRevision) {
    AppCatalogMirrorHealth currentHealth = healthFromRevision(currentRevision);
    health.compute(
        currentRevision.sourceId(),
        (_, existing) -> shouldUseCurrentRevisionHealth(existing) ? currentHealth : existing);
  }

  private static boolean shouldUseCurrentRevisionHealth(AppCatalogMirrorHealth existing) {
    return existing == null
        || (existing.lastFetchStatus() == AppCatalogFetchStatus.SKIPPED
            && existing.lastSuccessfulRefreshAt().isEmpty()
            && existing.lastCatalogDigest().isEmpty()
            && existing.lastSignatureKeyId().isEmpty());
  }

  private static AppCatalogMirrorHealth healthFromRevision(AppCatalogVerifiedRevision revision) {
    return new AppCatalogMirrorHealth(
        revision.sourceId(),
        revision.sourceRole(),
        AppCatalogFetchStatus.SUCCESS,
        Optional.of(revision.verifiedAt()),
        Optional.of(revision.verifiedAt()),
        Optional.empty(),
        Optional.empty(),
        revision.resolvedUri(),
        Optional.of(revision.revisionDigest()),
        Optional.of(revision.signatureKeyId()),
        Optional.of(revision.generatedAt()),
        revision.rollbackReason());
  }

  private Optional<AppCatalogVerifiedRevision> currentRevision(
      String catalogId, String currentDigest) {
    try {
      return sourceStore.listRevisions(catalogId, currentDigest).stream()
          .filter(AppCatalogVerifiedRevision::current)
          .findFirst();
    } catch (AppCatalogException | IOException _) {
      return Optional.empty();
    }
  }

  private static AppCatalogMirrorId requestedMirrorId(
      String rawMirrorId, List<AppCatalogMirror> mirrors) {
    if (rawMirrorId == null || rawMirrorId.isBlank()) {
      return nextMirrorId(mirrors);
    }
    return AppCatalogMirrorId.parse(rawMirrorId);
  }

  private static AppCatalogSource requestedSource(String rawSource) {
    if (rawSource == null || rawSource.isBlank()) {
      return null;
    }
    return AppCatalogSource.parse(rawSource);
  }

  private static void rejectPrimaryMirror(AppCatalogMirrorId mirrorId, String message) {
    if (AppCatalogMirrorId.PRIMARY.equals(mirrorId)) {
      throw new AppCatalogException(AppCatalogSidecars.INVALID_CATALOG_SOURCE, message);
    }
  }

  private static void rejectUnexpectedCatalog(AppCatalog catalog, String expectedCatalogId) {
    if (expectedCatalogId == null || expectedCatalogId.isBlank()) {
      return;
    }
    String normalizedExpectedCatalogId = AppCatalog.normalizeCatalogId(expectedCatalogId);
    if (!normalizedExpectedCatalogId.equals(catalog.catalogId())) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_ID_MISMATCH,
          "Catalog id does not match the requested catalog.");
    }
  }

  private void rejectExistingCatalog(AppCatalog catalog) {
    if (sourceStore.exists(catalog.catalogId())) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_CONFLICT,
          "Catalog already configured: " + catalog.catalogId());
    }
  }

  private static void rejectDuplicateMirror(
      List<AppCatalogMirror> mirrors, AppCatalogMirrorId mirrorId, AppCatalogSource source) {
    if (mirrors.stream()
        .anyMatch(
            mirror ->
                mirror.id().equals(mirrorId)
                    || mirror.source().displayUri().equals(source.displayUri()))) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_CONFLICT, "Catalog mirror already configured.");
    }
  }

  private static void rejectDuplicateMirrorSource(
      List<AppCatalogMirror> mirrors, AppCatalogMirrorId mirrorId, AppCatalogSource source) {
    if (mirrors.stream()
        .anyMatch(
            mirror ->
                !mirror.id().equals(mirrorId)
                    && mirror.source().displayUri().equals(source.displayUri()))) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_CONFLICT, "Catalog mirror already configured.");
    }
  }

  private static int resolvedPriority(int priority, List<AppCatalogMirror> mirrors) {
    if (priority <= 0) {
      return nextMirrorPriority(mirrors);
    }
    return priority;
  }

  private static int resolvedPriority(Integer priority, AppCatalogMirror mirror) {
    if (priority == null || priority <= 0) {
      return mirror.priority();
    }
    return priority;
  }

  private static boolean resolvedEnabled(Boolean enabled, AppCatalogMirror mirror) {
    if (enabled == null) {
      return mirror.enabled();
    }
    return enabled;
  }

  private static MirrorUpdateResult updateMirrorList(
      List<AppCatalogMirror> mirrors,
      AppCatalogMirrorId id,
      AppCatalogSource requestedSource,
      Integer priority,
      Boolean enabled) {
    AppCatalogMirror existing = findMirror(mirrors, id);
    AppCatalogMirror updated = updatedMirror(existing, requestedSource, priority, enabled);
    List<AppCatalogMirror> updatedMirrors =
        mirrors.stream().map(mirror -> replacementMirror(mirror, id, updated)).toList();
    return new MirrorUpdateResult(
        updatedMirrors,
        updated,
        !updated.source().displayUri().equals(existing.source().displayUri()));
  }

  private static AppCatalogMirror findMirror(
      List<AppCatalogMirror> mirrors, AppCatalogMirrorId id) {
    return mirrors.stream()
        .filter(mirror -> mirror.id().equals(id))
        .findFirst()
        .orElseThrow(
            () ->
                new AppCatalogException(
                    AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog mirror not found."));
  }

  private static AppCatalogMirror updatedMirror(
      AppCatalogMirror mirror,
      AppCatalogSource requestedSource,
      Integer priority,
      Boolean enabled) {
    return new AppCatalogMirror(
        mirror.id(),
        AppCatalogSourceRole.MIRROR,
        requestedSource == null ? mirror.source() : requestedSource,
        resolvedPriority(priority, mirror),
        resolvedEnabled(enabled, mirror),
        mirror.addedAt());
  }

  private static AppCatalogMirror replacementMirror(
      AppCatalogMirror mirror, AppCatalogMirrorId id, AppCatalogMirror replacement) {
    if (mirror.id().equals(id)) {
      return replacement;
    }
    return mirror;
  }

  private void clearMirrorHealth(
      String catalogId,
      Map<AppCatalogMirrorId, AppCatalogMirrorHealth> mirrorHealth,
      AppCatalogMirrorId mirrorId)
      throws IOException {
    LinkedHashMap<AppCatalogMirrorId, AppCatalogMirrorHealth> retainedHealth =
        new LinkedHashMap<>(mirrorHealth);
    retainedHealth.remove(mirrorId);
    sourceStore.writeMirrorHealth(catalogId, retainedHealth);
  }

  private static AppCatalogMirrorId nextMirrorId(List<AppCatalogMirror> mirrors) {
    int index = 1;
    while (true) {
      AppCatalogMirrorId candidate = AppCatalogMirrorId.parse("mirror-" + index);
      if (mirrors.stream().noneMatch(mirror -> mirror.id().equals(candidate))) {
        return candidate;
      }
      index++;
    }
  }

  private static int nextMirrorPriority(List<AppCatalogMirror> mirrors) {
    return mirrors.stream()
            .filter(mirror -> mirror.role() == AppCatalogSourceRole.MIRROR)
            .mapToInt(AppCatalogMirror::priority)
            .max()
            .orElse(0)
        + 1;
  }

  private AppCatalogRollbackCandidate rollbackCandidate(
      StoredCatalogSource stored, AppCatalogVerifiedRevision revision, TrustedAppKeys trustedKeys) {
    try {
      String catalogId = stored.catalogId();
      AppCatalogTrustVerification.requireHistoricalStoredBinding(stored, federatedTrustStore);
      FetchedCatalog fetched = sourceStore.readRevision(catalogId, revision.revisionDigest());
      AppCatalog catalog =
          AppCatalogTrustVerification.verifyHistorical(
              fetched.catalogBytes(),
              fetched.signatureBytes(),
              trustedKeys,
              catalogId,
              federatedTrustStore);
      if (!catalogId.equals(catalog.catalogId())) {
        return new AppCatalogRollbackCandidate(revision, false, Optional.of("catalog_id_mismatch"));
      }
      if (revision.current()) {
        return new AppCatalogRollbackCandidate(revision, false, Optional.of("current_revision"));
      }
      return new AppCatalogRollbackCandidate(revision, true, Optional.empty());
    } catch (AppCatalogException exception) {
      return new AppCatalogRollbackCandidate(revision, false, Optional.of(exception.errorCode()));
    } catch (IOException _) {
      return new AppCatalogRollbackCandidate(
          revision, false, Optional.of(AppCatalogSidecars.CATALOG_FETCH_FAILED));
    }
  }

  private AppCatalogVerifiedRevision revisionForRollback(
      StoredCatalogSource stored, String revisionDigest) throws IOException {
    String currentDigest = AppCatalogRevisions.catalogDigest(stored.fetchedCatalog());
    return sourceStore.listRevisions(stored.catalogId(), currentDigest).stream()
        .filter(revision -> revision.revisionDigest().equals(revisionDigest))
        .findFirst()
        .orElseThrow(
            () ->
                new AppCatalogException(
                    AppCatalogSidecars.CATALOG_NOT_FOUND, "Catalog revision metadata not found."));
  }

  private static AppCatalogMirror endpointForRevision(
      StoredCatalogSource stored, AppCatalogVerifiedRevision revision) {
    return stored.mirrors().stream()
        .filter(mirror -> mirror.id().equals(revision.sourceId()))
        .findFirst()
        .orElseGet(() -> retainedRevisionEndpoint(stored, revision));
  }

  private static AppCatalogMirror retainedRevisionEndpoint(
      StoredCatalogSource stored, AppCatalogVerifiedRevision revision) {
    return new AppCatalogMirror(
        revision.sourceId(),
        revision.sourceRole(),
        stored.source(),
        retainedRevisionPriority(revision.sourceRole()),
        revision.sourceRole() == AppCatalogSourceRole.PRIMARY,
        revision.verifiedAt());
  }

  private static int retainedRevisionPriority(AppCatalogSourceRole role) {
    return role == AppCatalogSourceRole.PRIMARY ? AppCatalogMirror.PRIMARY_PRIORITY : 1;
  }

  private static String resolvedUriForRevision(
      AppCatalogVerifiedRevision revision, AppCatalogMirror endpoint) {
    return revision.resolvedUri().orElseGet(() -> endpoint.source().resolvedCatalogFetchUri());
  }

  private static Map<AppCatalogMirrorId, AppCatalogMirrorHealth> rollbackHealth(
      StoredCatalogSource stored,
      AppCatalogMirror endpoint,
      FetchedCatalog fetched,
      AppCatalog catalog,
      Instant now,
      String resolvedUri,
      String rollbackReason) {
    String digest = AppCatalogRevisions.catalogDigest(fetched);
    String signatureKeyId = AppCatalogVerifier.readSignature(fetched.signatureBytes()).keyId();
    LinkedHashMap<AppCatalogMirrorId, AppCatalogMirrorHealth> health =
        new LinkedHashMap<>(stored.mirrorHealth());
    AppCatalogMirrorHealth previous =
        health.getOrDefault(endpoint.id(), AppCatalogMirrorHealth.skipped(endpoint));
    health.put(
        endpoint.id(),
        previous.successfulRollback(
            now, resolvedUri, digest, signatureKeyId, catalog.generatedAt(), rollbackReason));
    return health;
  }

  private Optional<String> previousKeyId(
      String normalizedCatalogId, StoredCatalogSource stored, String currentKeyId)
      throws IOException {
    String currentDigest = AppCatalogRevisions.catalogDigest(stored.fetchedCatalog());
    return sourceStore.listRevisions(normalizedCatalogId, currentDigest).stream()
        .filter(revision -> !revision.current())
        .map(AppCatalogVerifiedRevision::signatureKeyId)
        .filter(keyId -> !keyId.equals(currentKeyId))
        .findFirst();
  }

  private static String keyRotationStatusValue(boolean trusted, boolean hasPreviousKeyId) {
    if (!trusted) {
      return "blocked";
    }
    if (hasPreviousKeyId) {
      return "active";
    }
    return "configured";
  }

  private static String normalizedRollbackReason(String reason) {
    if (reason == null || reason.isBlank()) {
      return null;
    }
    return AppCatalogSidecars.requireBoundedSingleLine(
        reason,
        "rollback reason",
        AppCatalogSidecars.INVALID_CATALOG_SOURCE,
        AppCatalogSidecars.MAX_OPERATOR_REASON_CHARS);
  }

  private static String resolvedCatalogUri(FetchedCatalog fetched, AppCatalogSource source) {
    return fetched.resolvedCatalogUri().orElseGet(source::resolvedCatalogFetchUri);
  }

  private record MirrorUpdateResult(
      List<AppCatalogMirror> mirrors, AppCatalogMirror updated, boolean sourceChanged) {}
}
