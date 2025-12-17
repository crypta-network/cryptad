package network.crypta.clients.http.updateableelements;

/**
 * Constants for the FProxy “AJAX push” / updateable-elements subsystem.
 *
 * <p>This class centralizes the small set of string and numeric tokens shared between the server
 * side (toadlets and {@link BaseUpdatableElement} renderers) and the browser-side updater logic. It
 * contains:
 *
 * <ul>
 *   <li>Updater type identifiers returned by {@link BaseUpdatableElement#getUpdaterType()} so the
 *       client can choose the appropriate DOM update strategy for a given element.
 *   <li>Wire-format tokens such as {@link #SUCCESS} and {@link #FAILURE} used as compact response
 *       bodies for update endpoints.
 *   <li>HTTP path constants for routing toadlets like {@link #DATA_PATH} and {@link
 *       #NOTIFICATION_PATH}.
 * </ul>
 *
 * <p>Invariants: the values are treated as stable protocol/UI identifiers; changing them is a
 * breaking change for any deployed web UI JavaScript that expects specific updater names, payload
 * prefixes, or endpoint paths.
 *
 * <p>Thread-safety: this type is immutable and has no runtime state; all fields are constants.
 *
 * @see network.crypta.clients.http.ajaxpush.PushDataToadlet
 * @see network.crypta.clients.http.ajaxpush.PushNotificationToadlet
 * @see network.crypta.clients.http.ajaxpush.PushKeepaliveToadlet
 * @see network.crypta.clients.http.updateableelements.PushDataManager
 * @see network.crypta.clients.http.updateableelements.BaseUpdatableElement
 */
public final class UpdaterConstants {
  /**
   * Creates an instance of the constants holder.
   *
   * <p>This class is designed for static access; instantiation has no effect and provides no
   * additional behavior. The public constructor is retained for compatibility with historical
   * callers and frameworks that may reflectively instantiate types.
   */
  private UpdaterConstants() {
    // Utility class; not instantiable.
  }

  /**
   * Sentinel content value indicating that an updatable element has reached a terminal state.
   *
   * <p>Some {@link BaseUpdatableElement} implementations (for example, a fetch progress element)
   * replace their rendered HTML with this value when they consider the underlying operation
   * finished. Browser-side updater logic can treat the appearance of this literal as a cue to stop
   * incremental updates and trigger a full page reload.
   *
   * @see network.crypta.clients.http.updateableelements.ProgressBarElement
   */
  public static final String FINISHED = "Finished";

  // Updaters
  /**
   * Updater type identifier for a progress bar element that may eventually request a page reload.
   *
   * <p>This string is returned by {@link BaseUpdatableElement#getUpdaterType()} for progress bar
   * renderers. When the browser receives an update payload of this type, it replaces the element's
   * contents and, if the new content equals {@link #FINISHED}, typically stops polling and reloads
   * the page to show the final state.
   */
  public static final String PROGRESSBAR_UPDATER = "progressBar";

  /**
   * Updater type identifier for image elements that refresh both the DOM and fetch progress text.
   *
   * <p>This string is returned by {@link BaseUpdatableElement#getUpdaterType()} for image element
   * renderers. The corresponding client-side updater replaces the element and can refresh any
   * associated “total image fetching” message so that pages with many images update smoothly while
   * loading.
   *
   * @see network.crypta.clients.http.updateableelements.ImageElement
   */
  public static final String IMAGE_ELEMENT_UPDATER = "ImageElementUpdater";

  /**
   * Updater type identifier for elements that can be updated by simple replacement.
   *
   * <p>This updater is used when the server can re-render an element and the browser only needs to
   * replace the target node's children (or entire node) without any additional logic such as
   * conditional reloads or progress aggregation.
   *
   * @see network.crypta.clients.http.updateableelements.TesterElement
   * @see network.crypta.clients.http.updateableelements.ProgressInfoElement
   */
  public static final String REPLACER_UPDATER = "ReplacerUpdater";

  // End of Updaters

  /**
   * Keepalive interval, in seconds, for browser pages using the AJAX push mechanism.
   *
   * <p>The client-side code periodically calls the keepalive endpoint to indicate that the page is
   * still active. A relatively generous interval is intentional: page closure is typically reported
   * separately, and pages with many CSS fetches or manual downloads can tie up multiple
   * connections, so the server should not time out too aggressively.
   *
   * @see #KEEPALIVE_PATH
   * @see network.crypta.clients.http.ajaxpush.PushKeepaliveToadlet
   */
  public static final int KEEPALIVE_INTERVAL_SECONDS = 600;

  /**
   * Response-body token indicating a successful outcome for AJAX push endpoints.
   *
   * <p>Several push-related toadlets return HTTP {@code 200 OK} for both success and failure and
   * encode the result in the body. When present as the payload prefix, {@code SUCCESS} is commonly
   * followed by additional colon-separated fields.
   *
   * @see #FAILURE
   * @see #SEPARATOR
   */
  public static final String SUCCESS = "SUCCESS";

  /**
   * Response-body token indicating a failed outcome for AJAX push endpoints.
   *
   * <p>This value is used as a compact sentinel response body when an endpoint cannot satisfy the
   * request (for example, a request id is no longer tracked). It is intentionally short and
   * machine-readable; callers should treat it as an opaque protocol token.
   *
   * @see #SUCCESS
   */
  public static final String FAILURE = "FAILURE";

  /**
   * Field separator used in the compact response bodies produced by the AJAX push subsystem.
   *
   * <p>Some endpoints build payloads by concatenating values separated by a literal colon. Keeping
   * the separator centralized reduces the chance of subtle parsing mismatches between endpoints and
   * browser-side code.
   */
  public static final String SEPARATOR = ":";

  // Paths
  /**
   * HTTP path prefix for the endpoint that serves the current rendered state of an updatable
   * element.
   *
   * <p>The value includes leading and trailing slashes (for example {@code "/pushdata/"}). It is
   * used by the toadlet container for routing and by the browser-side updater logic to fetch the
   * latest HTML for a specific element.
   *
   * @see network.crypta.clients.http.ajaxpush.PushDataToadlet
   */
  public static final String DATA_PATH = '/' + "pushdata" + '/';

  /**
   * HTTP path prefix for the long-poll notification endpoint used by the AJAX push subsystem.
   *
   * <p>The browser calls this endpoint (typically in a loop) to wait for the next update event for
   * a given {@code requestId}. The response is a compact tokenized payload prefixed with {@link
   * #SUCCESS} or a {@link #FAILURE} sentinel, depending on whether an update is available.
   *
   * @see network.crypta.clients.http.ajaxpush.PushNotificationToadlet
   */
  public static final String NOTIFICATION_PATH = '/' + "pushnotifications" + '/';

  /**
   * HTTP path prefix for the keepalive endpoint used to maintain a push request's liveness.
   *
   * <p>Clients periodically issue a request to this path with their current {@code requestId}. The
   * server uses it as a liveness signal for cleanup heuristics and returns either {@link #SUCCESS}
   * or {@link #FAILURE} as the response body.
   *
   * @see network.crypta.clients.http.ajaxpush.PushKeepaliveToadlet
   */
  public static final String KEEPALIVE_PATH = '/' + "keepalive" + '/';

  /**
   * HTTP path prefix for the failover endpoint used when leadership for a push stream changes.
   *
   * <p>This endpoint exists to reassign queued notifications from one request id to another in the
   * push manager so that clients can continue polling after a leader request is replaced. The
   * outcome is reported via {@link #SUCCESS}/{@link #FAILURE} rather than via HTTP status codes.
   *
   * @see network.crypta.clients.http.ajaxpush.PushFailoverToadlet
   */
  public static final String FAILOVER_PATH = '/' + "failover" + '/';

  /**
   * HTTP path prefix for the “page leaving” endpoint used to proactively release push state.
   *
   * <p>Browser pages call this endpoint just before unloading to tell the server it can discard
   * per-page push registrations and queued notifications. This reduces memory retention when a
   * client navigates away without waiting for the server-side cleanup delay.
   *
   * @see network.crypta.clients.http.ajaxpush.PushLeavingToadlet
   */
  public static final String LEAVING_PATH = '/' + "leaving" + '/';

  /**
   * HTTP path prefix for the endpoint that dismisses a UI alert associated with a request/page.
   *
   * <p>The web UI calls this endpoint to notify the server that an alert has been acknowledged so
   * it can be removed from any tracked state. The response typically uses the {@link #SUCCESS} or
   * {@link #FAILURE} tokens and is intended for machine parsing.
   *
   * @see network.crypta.clients.http.ajaxpush.DismissAlertToadlet
   */
  public static final String DISMISS_ALERT_PATH = '/' + "dismissalert" + '/';

  /**
   * HTTP path prefix for the endpoint used to write client log text back to the server.
   *
   * <p>This route is used by the web UI to post client-generated log fragments so that they can be
   * captured by the node for debugging purposes. The exact payload format is defined by the
   * corresponding toadlet; this constant exists to keep routing stable.
   *
   * @see network.crypta.clients.http.ajaxpush.LogWritebackToadlet
   */
  public static final String LOG_WRITEBACK_PATH = '/' + "logwriteback" + '/';
  // End of Paths
}
