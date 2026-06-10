package network.crypta.platform.api.appservices;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Storage boundary for app-service grant and audit records.
 *
 * <p>The coordinator uses this interface for both test-local memory storage and runtime durable
 * storage. Implementations must keep records bounded, deterministic, and safe to serialize. They
 * store grant ids and redacted audit metadata only; raw service bearer tokens, request bodies,
 * private insert URIs, provider app data, and absolute local paths do not belong in this store.
 *
 * <p>The interface is synchronous and process-local. Callers synchronize at the coordinator level
 * when they need read-modify-write behavior, such as updating use counts after successful
 * invocation.
 *
 * <p>Implementations should fail closed. An {@link IOException} from this boundary makes the
 * coordinator return the stable app-services-unavailable error rather than falling back to an
 * in-memory authorization cache.
 */
public interface AppServiceGrantStore {
  /**
   * Lists all stored grants in deterministic order.
   *
   * <p>Implementations should return a stable order, normally creation time followed by grant id,
   * so operator views and tests do not depend on filesystem enumeration order.
   *
   * @return immutable grant list in deterministic store order
   * @throws IOException when grant records cannot be read or decoded
   */
  List<AppServiceGrant> listGrants() throws IOException;

  /**
   * Reads one grant by id.
   *
   * <p>Malformed ids should fail through the same validation used for persisted grant records. A
   * missing, well-formed id returns an empty result instead of raising a route-level not-found
   * exception.
   *
   * @param grantId stable local grant id to look up
   * @return grant when present, or empty when the id is unknown
   * @throws IOException when grant records cannot be read or decoded
   */
  Optional<AppServiceGrant> readGrant(String grantId) throws IOException;

  /**
   * Creates or replaces one grant.
   *
   * <p>Replacement is used for lifecycle transitions and use-count updates. Implementations should
   * write atomically where the backing storage supports it so partially written grant records do
   * not become authorization decisions after a restart.
   *
   * @param grant validated grant record to persist
   * @throws IOException when the grant cannot be written safely
   */
  void writeGrant(AppServiceGrant grant) throws IOException;

  /**
   * Lists all stored grant bundles in deterministic order.
   *
   * @return immutable bundle list ordered by creation time and bundle id
   * @throws IOException when bundle records cannot be read or decoded
   */
  List<AppServiceGrantBundle> listBundles() throws IOException;

  /**
   * Reads one grant bundle by id.
   *
   * @param bundleId stable local bundle id to look up
   * @return bundle when present, or empty when the id is unknown
   * @throws IOException when bundle records cannot be read or decoded
   */
  Optional<AppServiceGrantBundle> readBundle(String bundleId) throws IOException;

  /**
   * Creates or replaces one grant-bundle review record.
   *
   * @param bundle validated bundle record to persist
   * @throws IOException when the bundle cannot be written safely
   */
  void writeBundle(AppServiceGrantBundle bundle) throws IOException;

  /**
   * Appends a redacted audit event.
   *
   * <p>The event is already redacted by the coordinator or adapter boundary. Implementations may
   * enforce retention limits during append so long-running nodes do not accumulate unbounded local
   * audit files.
   *
   * @param event redacted audit event to persist
   * @throws IOException when the audit event cannot be written safely
   */
  void appendAuditEvent(AppServiceAuditEvent event) throws IOException;

  /**
   * Lists recent audit events, newest first.
   *
   * <p>The coordinator caps caller-supplied limits before invoking the store. Implementations
   * should still handle zero or negative limits defensively and return immutable lists.
   *
   * @param limit maximum number of entries requested by the caller
   * @return immutable audit list ordered with the newest records first
   * @throws IOException when audit records cannot be read or decoded
   */
  List<AppServiceAuditEvent> listAuditEvents(int limit) throws IOException;
}
