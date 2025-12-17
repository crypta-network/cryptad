package network.crypta.clients.http.updateableelements;

import java.util.Timer;
import java.util.TimerTask;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;

/**
 * A pushed HTTP UI element that increments its state once per second for testing.
 *
 * <p>This element is intentionally small and side-effectful: it schedules a background {@link
 * TimerTask} that repeatedly calls {@link #update()} to advance an integer counter. Each tick
 * notifies the HTTP push subsystem that the element has changed, which causes the server to ask the
 * element to re-render its current state.
 *
 * <p>The rendered state is an {@code <img>} tag whose {@code src} points at the ImageCreator
 * endpoint, with the current counter value embedded in the query string. The image dimensions grow
 * with the counter and are bounded to keep the UI stable.
 *
 * <p><b>Threading:</b> The counter is advanced from a {@link Timer} thread. There is no explicit
 * synchronization; this is acceptable for its intended role as a debugging/testing aid but should
 * not be treated as a general-purpose, thread-safe component.
 *
 * <p><b>Lifecycle:</b> Constructing an instance starts the timer immediately. {@link #dispose()}
 * stops the timer; the timer also stops itself once the counter reaches {@code maxStatus}.
 *
 * <p><b>Responsibilities:</b>
 *
 * <ul>
 *   <li>Generate a unique per-request updater identifier via {@link #getUpdaterId(String)}.
 *   <li>Advance {@code status} on a fixed schedule and publish updates to the push data manager.
 *   <li>Render a simple, changing HTML payload suitable for manual testing.
 * </ul>
 */
public class TesterElement extends BaseUpdatableElement {

  private int status = 0;

  private final int maxStatus;

  Timer t;

  final String id;

  /**
   * Creates a new tester element and starts its background update timer immediately.
   *
   * <p>The timer is created as a daemon timer and scheduled at a fixed rate of once per second. On
   * every tick, the element advances an internal counter and notifies the push subsystem that this
   * element's state has changed. The element stops updating automatically once the counter reaches
   * {@code max}.
   *
   * <p>Callers typically create this element as part of an HTTP test page and rely on the push
   * framework to call {@link #updateState(boolean)} when a client needs an updated render.
   *
   * @param ctx the request-scoped context used to locate the push data manager and unique request
   *     id; must not be {@code null}.
   * @param id an element identifier that is incorporated into the updater id; typically stable for
   *     the page, and not {@code null}.
   * @param max the maximum counter value at which the periodic timer cancels itself; values {@code
   *     <= 0} stop almost immediately after the first tick.
   */
  public TesterElement(ToadletContext ctx, String id, int max) {
    super("div", "style", "float:left;", ctx);
    this.id = id;
    this.maxStatus = max;
    init(true);
    t = new Timer(true);
    t.scheduleAtFixedRate(
        new TimerTask() {

          @Override
          public void run() {
            update();
          }
        },
        0,
        1000);
  }

  /**
   * Advances the internal counter and notifies the HTTP push subsystem that this element has
   * changed.
   *
   * <p>This method increments {@code status} by one and cancels the timer once {@code status >=
   * maxStatus}. After updating the counter, it calls into the {@link
   * network.crypta.clients.http.SimpleToadletServer} push manager to publish an update for this
   * element's updater id.
   *
   * <p>This method is normally invoked by the element's {@link TimerTask}. It is safe to call
   * multiple times, but it is not designed to be invoked concurrently with rendering; it performs
   * no locking.
   */
  public void update() {
    status++;
    if (status >= maxStatus) {
      t.cancel();
    }
    ((SimpleToadletServer) ctx.getContainer())
        .getPushDataManager()
        .updateElement(getUpdaterId(ctx.getUniqueId()));
  }

  /**
   * Stops the periodic update timer for this element.
   *
   * <p>This cancels the underlying {@link Timer}. It is safe to call more than once; canceling an
   * already-canceled timer is a no-op for this use case.
   */
  @Override
  public void dispose() {
    t.cancel();
  }

  /**
   * Returns the updater identifier for this element in the current request context.
   *
   * <p>The returned identifier is derived from the request id and the element-local {@code id}
   * supplied at construction time. It is used by the push framework to map incoming update
   * notifications to the correct updatable element instance.
   *
   * @param requestId the unique request identifier used to scope updater ids; must not be {@code
   *     null}.
   * @return a deterministic updater id string for this request and element id.
   */
  @Override
  public String getUpdaterId(String requestId) {
    return getId(requestId, id);
  }

  /**
   * Builds a deterministic updater identifier for testing by Base64-encoding a composite string.
   *
   * <p>This helper exists primarily to exercise long updater id handling in the push layer. It
   * concatenates a fixed prefix, the provided request id, a marker containing the provided element
   * id, and a long constant suffix, then encodes the result with {@link
   * Base64#encodeStandardUTF8(String)}.
   *
   * <pre>{@code
   * String updaterId = TesterElement.getId(ctx.getUniqueId(), "example");
   * }</pre>
   *
   * @param requestId the unique request identifier whose value should be included in the id; must
   *     not be {@code null}.
   * @param id the element identifier to include in the id; typically stable for the page, and not
   *     {@code null}.
   * @return a Base64-encoded updater identifier suitable for the push data manager.
   */
  public static String getId(String requestId, String id) {
    return Base64.encodeStandardUTF8(
        ("test:"
            + requestId
            + "id:"
            + id
            + "gndfjkghghdfukggherugbdfkutg54ibngjkdfgyisdhiterbyjhuyfghdightw7i4tfgsdgo;dfnghsdbfuiyfgfoinfsdbufvwte4785tu4kgjdfnzukfbyfhe48e54gjfdjgbdruserigbfdnvbxdio;fherigtuseofjuodsvbyfhsd8ofghfio;"));
  }

  /**
   * Returns the updater type constant used by this element.
   *
   * <p>This element uses a replacer-style updater, meaning the server replaces the element's
   * rendered HTML when the push framework indicates that the element has updated.
   *
   * @return the updater type identifier used for replacer-style HTML updates.
   */
  @Override
  public String getUpdaterType() {
    return UpdaterConstants.REPLACER_UPDATER;
  }

  /**
   * Rebuilds the element's child nodes to reflect the current counter value.
   *
   * <p>The previous children are cleared and replaced with a single {@code <img>} node. The {@code
   * src} points at the ImageCreator endpoint and includes query parameters for the displayed text
   * and image dimensions. The width and height grow as {@code status + 30} and are capped at {@code
   * 300} to avoid unbounded growth during tests.
   *
   * @param initial whether this is the initial render pass for the element; ignored by this
   *     implementation.
   */
  @Override
  public void updateState(boolean initial) {
    children.clear();
    addChild(
        new HTMLNode(
            "img",
            "src",
            "/imagecreator/?text="
                + status
                + "&width="
                + Math.min(status + 30, 300)
                + "&height="
                + Math.min(status + 30, 300)));
  }
}
