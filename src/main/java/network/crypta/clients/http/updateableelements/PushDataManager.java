package network.crypta.clients.http.updateableelements;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates server-side state for "push" updates in the HTTP UI.
 *
 * <p>This manager tracks which {@link BaseUpdatableElement} instances are rendered on which active
 * HTTP request (page), and it converts element changes into queued {@link UpdateEvent}s for clients
 * that poll for notifications. It is designed for UIs that render elements during normal page
 * handling and then rely on a separate long-polling (or repeated polling) request to ask, "what
 * should I refresh next?".
 *
 * <ul>
 *   <li>{@link #elementRendered(String, BaseUpdatableElement)} registers a rendered element for a
 *       request/page.
 *   <li>{@link #updateElement(String)} marks an element as changed and queues notifications for all
 *       pages currently rendering it.
 *   <li>{@link #getNextNotification(String)} blocks until a queued update is available for a
 *       polling request.
 *   <li>{@link #keepAliveReceived(String)} marks that a polling request is still alive.
 * </ul>
 *
 * <p>All public methods are {@code synchronized} and use {@link Object#wait()} / {@link
 * Object#notifyAll()} to coordinate between poller threads and update producers. This object is
 * stateful and mutable: callers are expected to reuse one instance and to treat it as the
 * authoritative in-memory index for what is currently rendered and what updates are pending. The
 * internal maps are not thread-safe on their own and must not be accessed without the instance
 * monitor.
 *
 * <p>To avoid unbounded growth when clients disconnect or stop polling, a {@link Ticker}-scheduled
 * cleaner periodically removes requests that do not send keepalives across successive cleaner runs.
 * Cleanup also disposes elements and removes queued notifications that originated from the removed
 * request.
 */
public class PushDataManager {
  private static final Logger LOG = LoggerFactory.getLogger(PushDataManager.class);

  /** What notifications are waiting for the leader */
  private final Map<String, List<UpdateEvent>> awaitingNotifications = new HashMap<>();

  /** What elements are on the page */
  private final Map<String, List<BaseUpdatableElement>> pages = new HashMap<>();

  /** What pages are on the element. It is redundant with the pages map. */
  private final Map<String, List<String>> elements = new HashMap<>();

  /** Stores whether a keepalive was received for a request since the Cleaner last run */
  private final Map<String, Boolean> isKeepaliveReceived = new HashMap<>();

  private final Map<String, Boolean> isFirstKeepaliveReceived = new HashMap<>();

  /** The Cleaner that runs periodically and cleans the failing requests */
  private final Ticker cleaner;

  /** A task for the Cleaner that the Cleaner invokes */
  private final CleanerTimerTask cleanerTask = new CleanerTimerTask();

  /**
   * The Cleaner only runs when needed. If this field is true, then the Cleaner is scheduled to run
   */
  private boolean isScheduled = false;

  /**
   * Creates a new manager backed by the provided {@link Ticker}.
   *
   * <p>The ticker is used only for scheduling the internal cleaner task; it does not execute any
   * work on the caller thread. The cleaner is scheduled lazily on the first call to {@link
   * #elementRendered(String, BaseUpdatableElement)} and is re-scheduled while at least one active
   * request is tracked.
   *
   * @param ticker scheduler used to queue periodic cleanup work; must not be {@code null}.
   */
  public PushDataManager(Ticker ticker) {
    cleaner = ticker;
  }

  /**
   * Records that an element has changed and should be refreshed.
   *
   * <p>This queues an {@link UpdateEvent} for every request/page that is currently known to render
   * the element, and wakes any blocked {@link #getNextNotification(String)} callers via {@link
   * Object#notifyAll()}. If the element id is not currently registered, this method performs no
   * state changes.
   *
   * <p>Notifications are de-duplicated per polling request: if an identical {@link UpdateEvent} is
   * already present in a request's queue, it is not added again. This provides a simple form of
   * coalescing when the same element changes multiple times before clients have a chance to poll.
   *
   * @param id updater element id returned by {@link BaseUpdatableElement#getUpdaterId(String)}.
   */
  public synchronized void updateElement(String id) {
    LOG.debug("Element updated id:{}", id);
    List<String> requestIds = elements.get(id);
    if (requestIds == null) {
      LOG.debug(
          "Element is updating, but not present on elements! elements:{} pages:{}"
              + " awaitingNotifications:{}",
          elements,
          pages,
          awaitingNotifications);
      return;
    }

    boolean needsUpdate = false;
    for (String requestId : requestIds) {
      addUpdateEventForPage(id, requestId);
      needsUpdate = true;
    }

    if (needsUpdate) {
      LOG.debug("Waking up notification polls");
      notifyAll();
    }
  }

  private void addUpdateEventForPage(String elementId, String requestId) {
    LOG.debug(
        "Element is present on page:{}. Adding an UpdateEvent for all notification list.",
        requestId);
    UpdateEvent updateEvent = new UpdateEvent(requestId, elementId);
    for (Map.Entry<String, List<UpdateEvent>> entry : awaitingNotifications.entrySet()) {
      List<UpdateEvent> notificationList = entry.getValue();
      if (notificationList.contains(updateEvent)) {
        LOG.debug("Not notifying {} because already on list", entry.getKey());
        continue;
      }
      notificationList.add(updateEvent);
      LOG.debug(
          "Notification({}) added to a notification list for {}", updateEvent, entry.getKey());
    }
  }

  /**
   * Registers a rendered element so it can receive future updates.
   *
   * <p>This registers the element under the request/page id, updates the reverse index from element
   * id to request ids, and marks the request as alive for the cleaner. The caller is expected to
   * pass an element instance whose updater id is stable for the lifetime of the request.
   *
   * <p>If the internal cleaner is not currently scheduled, this call schedules it to run after the
   * keepalive timeout window.
   *
   * <p>This method also ensures the request has an initialized notification queue. Once a request
   * is tracked, it will remain tracked until it is explicitly removed via {@link #leaving(String)}
   * or the periodic cleaner detects missing keepalives. When a request is removed, its rendered
   * elements are disposed via {@link BaseUpdatableElement#dispose()} and any update events that
   * originated from that request are removed from all queues.
   *
   * @param requestUniqueId request/page identifier used for polling notifications; should be
   *     stable.
   * @param element rendered element to track and later dispose on cleanup.
   */
  public synchronized void elementRendered(String requestUniqueId, BaseUpdatableElement element) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Element is rendered in page:{} element:{}", requestUniqueId, element);
    }
    // Add to the pages
    pages.computeIfAbsent(requestUniqueId, ignored -> new ArrayList<>()).add(element);
    // Add to the elements
    String id = element.getUpdaterId(requestUniqueId);
    elements.computeIfAbsent(id, ignored -> new ArrayList<>()).add(requestUniqueId);
    // The request needs to be tracked
    isKeepaliveReceived.put(requestUniqueId, true);

    awaitingNotifications.computeIfAbsent(requestUniqueId, ignored -> new ArrayList<>());
    // If the Cleaner isn't running, then we schedule it to clear this request if failing
    if (!isScheduled) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Cleaner is queued(1) time:{}", System.currentTimeMillis());
      }
      cleaner.queueTimedJob(cleanerTask, "cleanerTask", getDelayInMs(), false, true);
      isScheduled = true;
    }
  }

  /**
   * Returns the element's current state.
   *
   * <p>This looks up the element within the set previously registered via {@link
   * #elementRendered(String, BaseUpdatableElement)} for the given request. When found, the element
   * state is refreshed via {@link BaseUpdatableElement#updateState(boolean)} and the element is
   * returned to the caller.
   *
   * <p>This method does not register new elements and does not create placeholder state. It is
   * intended to be called by the HTTP layer when it needs to re-render a previously rendered
   * element after receiving an {@link UpdateEvent}. A missing element indicates that the request is
   * no longer tracked (for example, because it timed out and was cleaned) or that the element was
   * never registered for that request.
   *
   * <p>If the element is not found, this method logs an error and returns {@code null}. Callers
   * should treat a {@code null} return as "not rendered" or "no longer tracked" and avoid assuming
   * that the element still exists for the request.
   *
   * @param requestId request/page identifier that previously rendered the element; used for lookup.
   * @param id element updater id previously returned for this request; used for lookup.
   * @return the tracked element with refreshed state, or {@code null} if missing.
   */
  public synchronized BaseUpdatableElement getRenderedElement(String requestId, String id) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Getting element data for element:{} in page:{}", id, requestId);
    }
    if (pages.get(requestId) != null)
      for (BaseUpdatableElement element : pages.get(requestId)) {
        if (element.getUpdaterId(requestId).compareTo(id) == 0) {
          element.updateState(false);
          return element;
        }
      }
    LOG.error(
        "Could not find data for the element requested. requestId:{} id:{} pages:{}"
            + " keepaliveReceived:{}",
        requestId,
        id,
        pages,
        isKeepaliveReceived);
    return null;
  }

  /**
   * Fails a request and copies all notifications directed to it to another request. It is invoked
   * when a leadership change occurs.
   *
   * <p>This method is used to migrate queued notifications from the old leader request to the new
   * leader request. If notifications exist for {@code originalRequestId}, they are moved to {@code
   * newRequestId} and any blocked pollers are woken via {@link Object#notifyAll()}.
   *
   * <p>The migration is a move, not a merge: any existing queue currently associated with {@code
   * newRequestId} is replaced by the moved queue. This mirrors the leader semantics used by the
   * HTTP UI, where a single active "leader" poll is expected to own the queue at a time.
   *
   * <p>If the original request id is not present, this method performs no changes.
   *
   * @param originalRequestId previous leader request id whose queue should be moved.
   * @param newRequestId new leader request id that should receive the moved queue.
   * @return {@code true} if a notification queue was migrated; {@code false} otherwise.
   */
  public synchronized boolean failover(String originalRequestId, String newRequestId) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Failover, original:{} new:{}", originalRequestId, newRequestId);
    }
    if (awaitingNotifications.containsKey(originalRequestId)) {
      awaitingNotifications.put(newRequestId, awaitingNotifications.remove(originalRequestId));
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "copied {} notification:{}",
            awaitingNotifications.get(newRequestId).size(),
            awaitingNotifications.get(newRequestId));
      }
      notifyAll();
      return true;
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Does not contains key");
      }
      return false;
    }
  }

  /**
   * Removes all state tracked for a request/page that is leaving.
   *
   * <p>This is equivalent to deleting the request due to failure: it removes the request from the
   * keepalive tracking, disposes rendered elements registered for that request, and removes any
   * queued notifications originating from that request.
   *
   * <p>This method is intended to be called when the HTTP layer knows a page/request is finished,
   * such as when a client navigates away. It is safe to call multiple times for the same request
   * id; subsequent calls will return {@code false} once the request has already been removed.
   *
   * @param requestId request/page identifier to remove from internal state maps.
   * @return {@code true} if the request was present and removed; {@code false} if it was already
   *     absent.
   */
  public synchronized boolean leaving(String requestId) {
    return deleteRequest(requestId);
  }

  /**
   * Records a keepalive for a tracked request.
   *
   * <p>This marks the request as alive for the next cleaner cycle and records that the request has
   * completed its first keepalive. The latter is used by {@link #getNextNotification(String)} to
   * avoid returning updates for a request that has not yet started polling.
   *
   * <p>This method does not create request state: the request must already have been registered via
   * {@link #elementRendered(String, BaseUpdatableElement)}. If the request is unknown, the return
   * value is {@code false} and no state is created.
   *
   * <p>This call wakes blocked pollers via {@link Object#notifyAll()} so they can re-check their
   * conditions.
   *
   * @param requestId request/page identifier that is still active and polling.
   * @return {@code true} if the request is still tracked; {@code false} if it was already removed.
   */
  public synchronized boolean keepAliveReceived(String requestId) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Keepalive is received for page:{}", requestId);
    }
    // If the request is already deleted, then fail
    if (!isKeepaliveReceived.containsKey(requestId)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Keepalive failed");
      }
      return false;
    }
    isKeepaliveReceived.put(requestId, true);
    isFirstKeepaliveReceived.put(requestId, true);
    notifyAll();
    return true;
  }

  /**
   * Waits and returns the next notification.
   *
   * <p>This method is the blocking poll endpoint: it waits until a queued {@link UpdateEvent} is
   * available for the given request and the request has sent its first keepalive. The latter avoids
   * returning updates for requests that have not yet started polling.
   *
   * <p>Update events are created when a rendered element changes via {@link
   * #updateElement(String)}. Each {@link UpdateEvent} identifies the request/page that should
   * refresh and the element id to re-render. Callers typically loop by calling this method,
   * applying the update on the client, sending periodic keepalives, and then polling again.
   *
   * <p>If the thread is interrupted while waiting, the interrupt flag is restored and this method
   * returns {@code null}.
   *
   * @param requestId request/page identifier to poll; must already be registered.
   * @return the next queued update event, or {@code null} when interrupted or not tracked.
   */
  public synchronized UpdateEvent getNextNotification(String requestId) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Polling for notification:{}", requestId);
    }
    while ((awaitingNotifications.get(requestId) != null
            && awaitingNotifications.get(requestId).isEmpty())
        || // No notifications
        (awaitingNotifications.get(requestId) != null
            && !awaitingNotifications.get(requestId).isEmpty()
            && !isFirstKeepaliveReceived.containsKey(
                awaitingNotifications.get(requestId).getFirst().requestId))) { // Not asked us yet
      try {
        wait();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        return null;
      }
    }
    if (awaitingNotifications.get(requestId) == null) {
      return null;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Getting notification, notification:{},remaining:{}",
          awaitingNotifications.get(requestId).getFirst(),
          awaitingNotifications.get(requestId).size() - 1);
    }
    return awaitingNotifications.get(requestId).removeFirst();
  }

  /** Returns the cleaner's delay in ms */
  private int getDelayInMs() {
    return (int) (UpdaterConstants.KEEPALIVE_INTERVAL_SECONDS * 1000 * 2.1);
  }

  /**
   * Deletes a request either because of failing or leaving
   *
   * @param requestId - The id of the request
   * @return Was a request deleted?
   */
  private synchronized boolean deleteRequest(String requestId) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("DeleteRequest with requestId:{}", requestId);
    }
    if (!isKeepaliveReceived.containsKey(requestId)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Request already cleaned, doing nothing");
      }
      return false;
    }
    isKeepaliveReceived.remove(requestId);
    isFirstKeepaliveReceived.remove(requestId);
    removeRenderedElements(requestId);
    removeNotificationsOriginatedFromRequest(requestId);
    awaitingNotifications.remove(requestId);
    return true;
  }

  private void removeRenderedElements(String requestId) {
    // Iterate over all the pushed elements present on the page
    List<BaseUpdatableElement> renderedElements = pages.get(requestId);
    for (BaseUpdatableElement element : new ArrayList<>(renderedElements)) {
      renderedElements.remove(element);
      String elementId = element.getUpdaterId(requestId);
      removeRequestFromElementsIndex(requestId, elementId);
      element.dispose();
    }
    pages.remove(requestId);
  }

  private void removeRequestFromElementsIndex(String requestId, String elementId) {
    List<String> requestIds = elements.get(elementId);
    requestIds.remove(requestId);
    if (requestIds.isEmpty()) {
      elements.remove(elementId);
    }
  }

  private void removeNotificationsOriginatedFromRequest(String requestId) {
    for (Entry<String, List<UpdateEvent>> entry : awaitingNotifications.entrySet()) {
      entry.getValue().removeIf(event -> event.requestId.equals(requestId));
    }
  }

  /**
   * Value object describing which request/page should refresh which element.
   *
   * <p>Instances are created internally when an element changes and are delivered to clients via
   * {@link PushDataManager#getNextNotification(String)}. Equality and hashing are based on the
   * request id and element id, which allows {@link PushDataManager} to avoid enqueuing duplicates
   * for the same polling request.
   */
  public static class UpdateEvent {
    private final String requestId;
    private final String elementId;

    private UpdateEvent(String requestId, String elementId) {
      this.requestId = requestId;
      this.elementId = elementId;
    }

    /**
     * Returns the identifier of the request/page that should apply the update.
     *
     * <p>The request id corresponds to the value used when registering rendered elements via {@link
     * PushDataManager#elementRendered(String, BaseUpdatableElement)} and when polling for
     * notifications via {@link PushDataManager#getNextNotification(String)}.
     *
     * <p>This is the target request/page identifier to refresh, not the identifier of the polling
     * request that received the notification. In practice the HTTP UI leader poll can receive
     * update events for multiple pages and uses this value to route each update to the correct page
     * state on the server side.
     *
     * @return the request/page identifier for this update event; never {@code null}.
     */
    public String getRequestId() {
      return requestId;
    }

    /**
     * Returns the updater element id that changed and should be re-rendered.
     *
     * <p>The element id corresponds to the value returned from {@link
     * BaseUpdatableElement#getUpdaterId(String)} for the request that rendered the element.
     *
     * <p>Consumers use this id with {@link PushDataManager#getRenderedElement(String, String)} to
     * resolve the corresponding {@link BaseUpdatableElement} for a particular request/page and then
     * render the refreshed state back to the client.
     *
     * @return the updater element identifier for this update event; never {@code null}.
     */
    public String getElementId() {
      return elementId;
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) return true;
      if (obj instanceof UpdateEvent o) {
        return o.getRequestId().compareTo(requestId) == 0
            && o.getElementId().compareTo(elementId) == 0;
      }
      return false;
    }

    @Override
    public int hashCode() {
      return requestId.hashCode() + elementId.hashCode();
    }

    @Override
    public String toString() {
      return "UpdateEvent[requestId=" + requestId + ",elementId=" + elementId + "]";
    }
  }

  /** A task for the Cleaner, that periodically checks for failed requests. */
  private class CleanerTimerTask implements Runnable {
    @Override
    public void run() {
      synchronized (PushDataManager.this) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Cleaner running:{}", isKeepaliveReceived);
        }
        isScheduled = false;
        for (Entry<String, Boolean> entry : new HashMap<>(isKeepaliveReceived).entrySet()) {
          if (Boolean.FALSE.equals(entry.getValue())) {
            if (LOG.isDebugEnabled()) {
              LOG.debug("Cleaner cleaned request:{}", entry.getKey());
            }
            deleteRequest(entry.getKey());
          } else {
            if (LOG.isDebugEnabled()) {
              LOG.debug("Cleaner reset request:{}", entry.getKey());
            }
            isKeepaliveReceived.put(entry.getKey(), false);
          }
        }
        if (!isKeepaliveReceived.isEmpty()) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("Cleaner is queued(2) time:{}", System.currentTimeMillis());
          }
          cleaner.queueTimedJob(cleanerTask, "cleanerTask", getDelayInMs(), false, true);
          isScheduled = true;
        }
      }
    }
  }
}
