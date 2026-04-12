package network.crypta.clients.http;

/**
 * Shared-shell view of the legacy HTTP push-data manager.
 *
 * <p>This handle represents the server-side coordination point for the legacy push/update flow used
 * by the HTTP shell. Shared-shell code registers rendered elements, reports later changes by
 * updater id, and polls for queued notifications without depending directly on the concrete
 * browse-owned push implementation. That keeps the current behavior intact while giving the shared
 * shell a stable, browse-neutral contract for the later physical split.
 *
 * <p>The interface models the full request lifecycle for pushed pages: render-time registration,
 * change propagation, leader failover, poll keepalives, and explicit teardown when a page leaves
 * the system. Implementations are stateful and are expected to manage any synchronization,
 * deduplication, and cleanup policy internally.
 */
public interface PushDataManagerHandle {

  /**
   * Notifies the manager that an element was rendered for the given request.
   *
   * <p>Implementations use this callback to associate a rendered element with a request or page
   * identifier so later update notifications can be routed back to the correct server-side state.
   * The shared shell calls this after an element has produced its initial markup and is ready to
   * participate in the push lifecycle.
   *
   * @param requestUniqueId request or page identifier that rendered the element and will later poll
   *     for updates
   * @param element rendered element to track for future update lookups and cleanup
   */
  void elementRendered(String requestUniqueId, PushUpdatableElement element);

  /**
   * Marks an element as changed and schedules any waiting notifications.
   *
   * <p>This method is the write-side signal used by interval refreshers and other producers. The
   * caller supplies the stable updater id for the changed element; the implementation is
   * responsible for finding interesting requests, deduplicating queued events where appropriate,
   * and waking any blocked pollers.
   *
   * @param id updater id of the element whose rendered state changed
   */
  void updateElement(String id);

  /**
   * Returns a previously rendered element for the supplied request and element id.
   *
   * <p>This is the read-side lookup used when a poll response tells the client to refresh a single
   * element. Implementations may refresh the element state before returning it, so callers can
   * immediately serialize the current markup without a second coordination step.
   *
   * @param requestId request or page identifier that originally rendered the element
   * @param id stable updater id for the element within that request
   * @return tracked updatable element for the supplied request and id, or {@code null} when the
   *     element is no longer available
   */
  PushUpdatableElement getRenderedElement(String requestId, String id);

  /**
   * Moves queued notifications from one request id to another.
   *
   * <p>This operation supports the legacy notion of a polling leader. When leadership changes, the
   * implementation can move any queued notifications from the original request id to the new one so
   * pending updates are not lost.
   *
   * @param originalRequestId request id whose queued notifications should be transferred away
   * @param newRequestId request id that should receive the transferred notification queue
   * @return {@code true} when a queued notification list was migrated, or {@code false} when the
   *     original request id was not tracked
   */
  boolean failover(String originalRequestId, String newRequestId);

  /**
   * Retrieves the next notification for the supplied request.
   *
   * <p>Implementations may block until a queued notification becomes available, the request stops
   * being tracked, or the underlying wait is interrupted. Callers should therefore treat a {@code
   * null} return as "no event is available right now" rather than assuming a specific cause.
   *
   * @param requestId polling request identifier currently waiting for the next push event
   * @return next queued update event for the request, or {@code null} when no event can be
   *     delivered
   */
  PushUpdateEvent getNextNotification(String requestId);

  /**
   * Notes that a polling request is still alive.
   *
   * <p>This method refreshes the liveness signal for a tracked polling request so the
   * implementation's cleanup policy does not discard it as stale. Implementations may also use the
   * first successful keepalive as a gate before releasing pending notifications.
   *
   * @param requestUniqueId request identifier to mark as still alive
   * @return {@code true} when the request remains tracked, or {@code false} when it has already
   *     been removed
   */
  boolean keepAliveReceived(String requestUniqueId);

  /**
   * Marks a request as leaving the push system.
   *
   * <p>This gives the HTTP shell an explicit teardown hook for request completion and client
   * navigation. Implementations should release tracked elements, discard queued notifications as
   * needed, and stop treating the request as active.
   *
   * @param requestId request identifier leaving the push system
   * @return {@code true} when tracked state was removed, or {@code false} when the request was
   *     already absent
   */
  boolean leaving(String requestId);
}
