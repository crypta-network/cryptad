package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Coordinates primary and mirror refresh attempts for {@link AppCatalogManager}.
 *
 * <p>Catalog refresh has a larger transport workflow than the rest of manager: source ordering,
 * fetch failure capture, signature verification, stale-revision handling, source-health updates,
 * and final sidecar persistence. Keeping that workflow here lets the public manager stay focused on
 * lifecycle entry points while this class owns the retry and health bookkeeping for refreshes.
 *
 * <p>A mirror remains only a transport fallback. Every accepted refresh still goes through the same
 * trusted-key signature verification and catalog-id checks before it can replace the active
 * catalog.
 */
final class AppCatalogRefreshCoordinator {
  private final AppCatalogSourceStore sourceStore;
  private final AppCatalogManager.TrustedKeyProvider trustedKeyProvider;
  private final AppCatalogFetcher fetcher;
  private final AppCatalogOperations operations;

  AppCatalogRefreshCoordinator(
      AppCatalogSourceStore sourceStore,
      AppCatalogManager.TrustedKeyProvider trustedKeyProvider,
      AppCatalogFetcher fetcher,
      AppCatalogOperations operations) {
    this.sourceStore = sourceStore;
    this.trustedKeyProvider = trustedKeyProvider;
    this.fetcher = fetcher;
    this.operations = operations;
  }

  AppCatalogSourceSnapshot refresh(String catalogId, boolean primaryOnly) throws IOException {
    String normalizedCatalogId = AppCatalogManager.normalizeCatalogIdForLookup(catalogId);
    StoredCatalogSource stored = sourceStore.read(normalizedCatalogId);
    TrustedAppKeys trustedKeys = trustedKeyProvider.trustedKeys();
    RefreshContext context = refreshContext(normalizedCatalogId, stored, trustedKeys);
    AppCatalogException lastFailure = null;
    String lastFailureResolvedUri = stored.source().resolvedCatalogFetchUri();
    for (AppCatalogMirror endpoint : operations.refreshEndpoints(stored, primaryOnly)) {
      RefreshEndpointResult result = refreshEndpoint(context, endpoint);
      if (result.snapshot().isPresent()) {
        return result.snapshot().orElseThrow();
      }
      lastFailure = result.failure().orElse(lastFailure);
      lastFailureResolvedUri = result.resolvedUri().orElse(lastFailureResolvedUri);
    }
    AppCatalogException failure = selectedFailure(lastFailure);
    recordRefreshFailure(stored, context.attemptedAt(), failure, lastFailureResolvedUri);
    try {
      sourceStore.writeMirrorHealth(normalizedCatalogId, context.health());
    } catch (IOException metadataException) {
      failure.addSuppressed(metadataException);
    }
    throw failure;
  }

  private RefreshContext refreshContext(
      String normalizedCatalogId, StoredCatalogSource stored, TrustedAppKeys trustedKeys) {
    return new RefreshContext(
        normalizedCatalogId,
        stored,
        trustedKeys,
        Instant.now(),
        operations.currentGeneratedAt(stored, trustedKeys).orElse(null),
        AppCatalogRevisions.catalogContentDigest(stored.fetchedCatalog()),
        new LinkedHashMap<>(stored.mirrorHealth()));
  }

  private RefreshEndpointResult refreshEndpoint(RefreshContext context, AppCatalogMirror endpoint)
      throws IOException {
    FetchAttempt attempt =
        fetchAndVerifyEndpoint(context.normalizedCatalogId(), endpoint, context.trustedKeys());
    if (attempt.exception().isPresent()) {
      return recordFailedEndpoint(context, endpoint, attempt);
    }
    Optional<AppCatalogSourceSnapshot> refreshed =
        acceptVerifiedRefreshAttempt(context, endpoint, attempt);
    if (refreshed.isPresent()) {
      return RefreshEndpointResult.success(refreshed.orElseThrow());
    }
    return recordStaleEndpoint(context, endpoint, attempt);
  }

  private RefreshEndpointResult recordFailedEndpoint(
      RefreshContext context, AppCatalogMirror endpoint, FetchAttempt attempt) {
    AppCatalogException exception = attempt.exception().orElseThrow();
    String resolvedUri = attempt.resolvedUri(endpoint);
    AppCatalogMirrorHealth previous =
        operations.previousHealth(
            context.health(), endpoint, context.stored(), context.trustedKeys());
    context
        .health()
        .put(endpoint.id(), previous.failedAttempt(context.attemptedAt(), exception, resolvedUri));
    return RefreshEndpointResult.failure(exception, resolvedUri);
  }

  private Optional<AppCatalogSourceSnapshot> acceptVerifiedRefreshAttempt(
      RefreshContext context, AppCatalogMirror endpoint, FetchAttempt attempt) throws IOException {
    AppCatalog candidate = attempt.catalog().orElseThrow();
    FetchedCatalog fetched = attempt.fetchedCatalog().orElseThrow();
    String contentDigest = AppCatalogRevisions.catalogContentDigest(fetched);
    if (isStaleOrAmbiguousRevision(
        candidate, contentDigest, context.currentGeneratedAt(), context.currentContentDigest())) {
      return Optional.empty();
    }
    String digest = AppCatalogRevisions.catalogDigest(fetched);
    String signatureKeyId = AppCatalogVerifier.readSignature(fetched.signatureBytes()).keyId();
    String resolvedUri = attempt.resolvedUri(endpoint);
    AppCatalogMirrorHealth previous =
        operations.previousHealth(
            context.health(), endpoint, context.stored(), context.trustedKeys());
    context
        .health()
        .put(
            endpoint.id(),
            previous.successfulAttempt(
                context.attemptedAt(),
                resolvedUri,
                digest,
                signatureKeyId,
                candidate.generatedAt()));
    StoredCatalogSource stored = context.stored();
    sourceStore.write(
        new AppCatalogSourceStore.VerifiedCatalogWrite(
            candidate, stored.source(), fetched, stored.addedAt(), context.attemptedAt()),
        new AppCatalogSourceStore.EndpointWriteState(endpoint, stored.mirrors(), context.health()));
    return Optional.of(
        AppCatalogManager.snapshot(
            sourceStore.read(context.normalizedCatalogId()), context.trustedKeys()));
  }

  private RefreshEndpointResult recordStaleEndpoint(
      RefreshContext context, AppCatalogMirror endpoint, FetchAttempt attempt) {
    AppCatalog candidate = attempt.catalog().orElseThrow();
    FetchedCatalog fetched = attempt.fetchedCatalog().orElseThrow();
    String resolvedUri = attempt.resolvedUri(endpoint);
    AppCatalogException failure =
        new AppCatalogException(
            AppCatalogSidecars.CATALOG_FETCH_FAILED,
            "catalog source returned an older or ambiguous verified revision");
    AppCatalogMirrorHealth previous =
        operations.previousHealth(
            context.health(), endpoint, context.stored(), context.trustedKeys());
    context
        .health()
        .put(
            endpoint.id(),
            previous.staleAttempt(
                context.attemptedAt(),
                resolvedUri,
                AppCatalogRevisions.catalogDigest(fetched),
                AppCatalogVerifier.readSignature(fetched.signatureBytes()).keyId(),
                candidate.generatedAt()));
    return RefreshEndpointResult.failure(failure, resolvedUri);
  }

  private FetchAttempt fetchAndVerifyEndpoint(
      String normalizedCatalogId, AppCatalogMirror endpoint, TrustedAppKeys trustedKeys) {
    FetchedCatalog fetched;
    try {
      fetched = fetcher.fetch(endpoint.source());
    } catch (AppCatalogException exception) {
      return FetchAttempt.failed(exception, null);
    } catch (IOException exception) {
      return FetchAttempt.failed(
          new AppCatalogException(
              AppCatalogSidecars.CATALOG_FETCH_FAILED,
              "failed to refresh catalog source: " + normalizedCatalogId,
              exception),
          null);
    }
    try {
      AppCatalog catalog =
          AppCatalogVerifier.verify(fetched.catalogBytes(), fetched.signatureBytes(), trustedKeys);
      if (!normalizedCatalogId.equals(catalog.catalogId())) {
        throw new AppCatalogException(
            AppCatalogSidecars.CATALOG_ID_MISMATCH,
            "refreshed catalog id does not match configured source");
      }
      return FetchAttempt.success(fetched, catalog);
    } catch (AppCatalogException exception) {
      return FetchAttempt.failed(exception, fetched);
    }
  }

  private static AppCatalogException selectedFailure(AppCatalogException lastFailure) {
    if (lastFailure != null) {
      return lastFailure;
    }
    return new AppCatalogException(
        AppCatalogSidecars.CATALOG_FETCH_FAILED, "no enabled catalog sources are available");
  }

  private void recordRefreshFailure(
      StoredCatalogSource stored,
      Instant attemptedAt,
      AppCatalogException exception,
      String resolvedUri) {
    try {
      sourceStore.recordRefreshFailure(stored, attemptedAt, exception, resolvedUri);
    } catch (IOException metadataException) {
      exception.addSuppressed(metadataException);
    }
  }

  private static boolean isStaleOrAmbiguousRevision(
      AppCatalog candidate,
      String candidateContentDigest,
      Instant currentGeneratedAt,
      String currentContentDigest) {
    if (currentGeneratedAt == null) {
      return false;
    }
    int generatedAtComparison = candidate.generatedAt().compareTo(currentGeneratedAt);
    if (generatedAtComparison != 0) {
      return generatedAtComparison < 0;
    }
    return !candidateContentDigest.equals(currentContentDigest);
  }

  private record RefreshContext(
      String normalizedCatalogId,
      StoredCatalogSource stored,
      TrustedAppKeys trustedKeys,
      Instant attemptedAt,
      Instant currentGeneratedAt,
      String currentContentDigest,
      Map<AppCatalogMirrorId, AppCatalogMirrorHealth> health) {}

  private record RefreshEndpointResult(
      Optional<AppCatalogSourceSnapshot> snapshot,
      Optional<AppCatalogException> failure,
      Optional<String> resolvedUri) {
    static RefreshEndpointResult success(AppCatalogSourceSnapshot snapshot) {
      return new RefreshEndpointResult(Optional.of(snapshot), Optional.empty(), Optional.empty());
    }

    static RefreshEndpointResult failure(AppCatalogException failure, String resolvedUri) {
      return new RefreshEndpointResult(
          Optional.empty(), Optional.of(failure), Optional.of(resolvedUri));
    }
  }

  private record FetchAttempt(
      Optional<FetchedCatalog> fetchedCatalog,
      Optional<AppCatalog> catalog,
      Optional<AppCatalogException> exception) {
    static FetchAttempt success(FetchedCatalog fetchedCatalog, AppCatalog catalog) {
      return new FetchAttempt(Optional.of(fetchedCatalog), Optional.of(catalog), Optional.empty());
    }

    static FetchAttempt failed(AppCatalogException exception, FetchedCatalog fetchedCatalog) {
      return new FetchAttempt(
          Optional.ofNullable(fetchedCatalog), Optional.empty(), Optional.of(exception));
    }

    String resolvedUri(AppCatalogMirror endpoint) {
      return fetchedCatalog
          .flatMap(FetchedCatalog::resolvedCatalogUri)
          .orElseGet(() -> endpoint.source().resolvedCatalogFetchUri());
    }
  }
}
