package network.crypta.clients.http;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import network.crypta.clients.http.updateableelements.BaseUpdatableElement;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.support.Ticker;

/**
 * Coordinates periodic push updates for registered HTTP updatable elements.
 *
 * <p>This manager acts as a lightweight scheduler that relies on a shared {@link Ticker} to run a
 * refresher job every fixed interval (10 seconds). Clients create a single instance per HTTP
 * context, register elements as they become visible to the UI, and allow the manager to keep those
 * elements fresh without bespoke timers. The internal {@link CopyOnWriteArrayList} permits safe
 * iteration from the refresher while callers add or remove elements concurrently. When the list is
 * empty no further jobs are queued, so idle nodes avoid unnecessary wakeups. The manager is
 * intentionally minimal: it delegates all data retrieval to {@link PushDataManager} and uses each
 * element's updater identifier to trigger the appropriate push logic.
 *
 * <ul>
 *   <li>Registers UI elements that expect recurring server pushes.
 *   <li>Queues a timed job on first registration and requeues while elements exist.
 *   <li>Stops rescheduling automatically once all elements are deregistered.
 * </ul>
 *
 * @see Ticker
 * @see PushDataManager
 * @see BaseUpdatableElement
 */
public class IntervalPusherManager {

  /** The interval when the elements will be pushed */
  private static final int REFRESH_PERIOD = 10000;

  /** The PushDataManager object */
  private final PushDataManager pushDataManager;

  /** The Ticker to schedule the interval */
  private final Ticker ticker;

  /** The job, that will refresh the elements */
  private final Runnable refresherJob =
      new Runnable() {

        @Override
        public void run() {
          // Updating
          for (BaseUpdatableElement element : elements) {
            pushDataManager.updateElement(element.getUpdaterId(null));
          }

          // If there are more elements, it reschedules
          if (!elements.isEmpty()) {
            ticker.queueTimedJob(this, "Stats refresher", REFRESH_PERIOD, false, true);
          }
        }
      };

  /** The elements that are pushed at a fixed interval */
  private final List<BaseUpdatableElement> elements = new CopyOnWriteArrayList<>();

  /**
   * Creates a manager that schedules update pushes with the supplied ticker.
   *
   * <p>The manager remains idle until the first element is registered. Afterward it maintains a
   * single recurring job that requeues itself as long as at least one element stays registered.
   * Callers should provide the shared {@link Ticker} instance used for other HTTP client timing
   * tasks so updates align with the application's scheduling model. Neither parameter may be null;
   * this class does not perform null checks beyond normal {@link NullPointerException} semantics.
   *
   * @param ticker non-null ticker that handles delayed job scheduling
   * @param pushDataManager manager that performs element updates when jobs run
   */
  public IntervalPusherManager(Ticker ticker, PushDataManager pushDataManager) {
    this.ticker = ticker;
    this.pushDataManager = pushDataManager;
  }

  /**
   * Registers an element to be pushed at a fixed interval.
   *
   * <p>The element is appended to the internal {@link CopyOnWriteArrayList}, allowing concurrent
   * registration even while a refresh cycle is iterating. If this call adds the first element, the
   * manager immediately schedules the refresher job, which subsequently requeues itself every
   * {@value #REFRESH_PERIOD} milliseconds while the list remains non-empty. Duplicate registrations
   * are not deduplicated and result in multiple update calls. The element must expose a stable
   * updater identifier because the manager forwards that value to {@link PushDataManager} without
   * further validation.
   *
   * @param element element to track; must not be null
   */
  @SuppressWarnings("unused")
  public void registerUpdateableElement(BaseUpdatableElement element) {
    boolean needsStart = elements.isEmpty();
    elements.add(element);
    // If this is the first element, then it starts the ticker
    if (needsStart) {
      ticker.queueTimedJob(refresherJob, "Stats refresher", REFRESH_PERIOD, false, true);
    }
  }

  /**
   * Removes the element from interval pushing.
   *
   * <p>The element is removed from the internal copy-on-write list, which makes the operation safe
   * to perform while a refresh iteration is in progress. If removal empties the list, the currently
   * executing refresher (if any) completes its cycle but does not schedule a follow-up job, thereby
   * stopping periodic updates until a new element is registered. The method tolerates removal of
   * elements that were not previously registered; in that case it performs no work.
   *
   * @param element element to remove from recurring update schedule
   */
  @SuppressWarnings("unused")
  public void deregisterUpdateableElement(BaseUpdatableElement element) {
    elements.remove(element);
  }
}
