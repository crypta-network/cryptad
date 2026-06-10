package network.crypta.platform.api.appservices;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Process-local app-service grant store for focused tests and reduced embeddings.
 *
 * <p>The store keeps grants and audit events in ordinary collections and applies the same
 * deterministic ordering and limit behavior expected from the file-backed store. It is useful for
 * router tests, small embedded Platform API configurations, and development-only coordinators that
 * should not write host data directories.
 *
 * <p>Records disappear when the JVM exits. Runtime wiring that needs durable app-service grants
 * should use {@link FileAppServiceGrantStore} instead.
 *
 * <p>This implementation does not try to emulate filesystem failures, owner-only permissions, or
 * cross-restart retention. Tests that cover those behaviors should exercise {@link
 * FileAppServiceGrantStore} directly.
 */
public final class InMemoryAppServiceGrantStore implements AppServiceGrantStore {
  private final Map<String, AppServiceGrant> grants = new LinkedHashMap<>();
  private final Map<String, AppServiceGrantBundle> bundles = new LinkedHashMap<>();
  private final List<AppServiceAuditEvent> auditEvents = new ArrayList<>();

  /**
   * Creates an empty process-local store.
   *
   * <p>No state is loaded from disk and no owner-only filesystem permissions are involved. Tests
   * can create a new instance per scenario to isolate grant and audit history.
   */
  public InMemoryAppServiceGrantStore() {
    // Field initializers create the empty in-memory grant and audit collections.
  }

  /**
   * Lists grants in the same deterministic order as the file-backed store.
   *
   * @return immutable grant list ordered by creation time and grant id
   */
  @Override
  public synchronized List<AppServiceGrant> listGrants() {
    return grants.values().stream()
        .sorted(
            Comparator.comparing(AppServiceGrant::createdAt)
                .thenComparing(AppServiceGrant::grantId))
        .toList();
  }

  /**
   * Reads one grant by normalized id from memory.
   *
   * @param grantId stable local grant id to read
   * @return grant when present, or empty when the id is unknown
   */
  @Override
  public synchronized Optional<AppServiceGrant> readGrant(String grantId) {
    return Optional.ofNullable(grants.get(AppServiceManifestParser.normalizeGrantId(grantId)));
  }

  /**
   * Creates or replaces one in-memory grant record.
   *
   * @param grant validated grant record to store
   */
  @Override
  public synchronized void writeGrant(AppServiceGrant grant) {
    grants.put(grant.grantId(), grant);
  }

  @Override
  public synchronized List<AppServiceGrantBundle> listBundles() {
    return bundles.values().stream()
        .sorted(
            Comparator.comparing(AppServiceGrantBundle::createdAt)
                .thenComparing(AppServiceGrantBundle::bundleId))
        .toList();
  }

  @Override
  public synchronized Optional<AppServiceGrantBundle> readBundle(String bundleId) {
    return Optional.ofNullable(bundles.get(AppServiceManifestParser.normalizeBundleId(bundleId)));
  }

  @Override
  public synchronized void writeBundle(AppServiceGrantBundle bundle) {
    bundles.put(bundle.bundleId(), bundle);
  }

  /**
   * Appends one redacted audit event to the in-memory history.
   *
   * @param event redacted audit event to append
   */
  @Override
  public synchronized void appendAuditEvent(AppServiceAuditEvent event) {
    auditEvents.add(event);
  }

  /**
   * Lists recent in-memory audit events, newest first.
   *
   * @param limit maximum number of events requested by the caller
   * @return immutable audit list ordered newest first
   */
  @Override
  public synchronized List<AppServiceAuditEvent> listAuditEvents(int limit) {
    int boundedLimit = Math.clamp(limit, 0, 200);
    return auditEvents.stream()
        .sorted(Comparator.comparing(AppServiceAuditEvent::timestamp).reversed())
        .limit(boundedLimit)
        .toList();
  }
}
