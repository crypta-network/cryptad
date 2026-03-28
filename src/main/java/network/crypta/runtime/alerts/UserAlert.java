package network.crypta.runtime.alerts;

import network.crypta.client.async.alerts.ClientAlert;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.support.HTMLNode;

/**
 * Describes a user-facing alert emitted by the node and consumed by UI surfaces and external
 * clients. Implementations provide human-readable text (plain and optional HTML), priority,
 * lifecycle hooks, and metadata used for deduplication and feeds. Alerts may be dismissible by the
 * end user or persist until programmatically unregistered by the producer.
 *
 * <p>Typical usage in consumers follows this pattern: check {@link #isValid()} under appropriate
 * synchronization, then read the title, short text, and full text to render. Producers update
 * validity or unregister when the underlying condition changes. The {@link #getPriorityClass()}
 * allows callers to rank and style alerts, and {@link #isEventNotification()} distinguishes
 * transient notifications from persistent operational warnings.
 *
 * <p>Implementations should document any thread-safety guarantees they provide; most alerts are
 * read-mostly and updated on state changes. Timestamps returned by {@link #getUpdatedTime()} are in
 * milliseconds since the Unix epoch and let feeds and clients order alerts deterministically.
 *
 * <ul>
 *   <li>Plain and HTML bodies: {@link #getText()} and {@link #getHTMLText()}.
 *   <li>Dismissal behavior: {@link #userCanDismiss()}, {@link #onDismiss()}, and {@link
 *       #shouldUnregisterOnDismiss()}.
 *   <li>External propagation: {@link #getFCPMessage()} for FCP subscribers.
 * </ul>
 *
 * @see network.crypta.runtime.alerts.UserAlertManager
 * @see network.crypta.clients.fcp.FeedMessage
 */
public interface UserAlert extends ClientAlert {

  /**
   * Indicates whether the alert is user-dismissible. Non-dismissible alerts remain visible until
   * their producer unregisters them or marks them invalid. User interfaces may hide the dismissed
   * affordance when this returns {@code false} and show a specific button label otherwise.
   *
   * @return {@code true} when a user action can dismiss the alert; {@code false} when the alert
   *     persists until programmatic removal.
   */
  boolean userCanDismiss();

  /**
   * Returns a short, human-readable title suitable for list or headline presentation. The title
   * should be concise and localized, ideally fitting on a single line in common UI contexts.
   * Implementations should avoid including trailing punctuation or markup here.
   *
   * @return a succinct, localized title string describing the alert purpose for display headers.
   */
  String getTitle();

  /**
   * Returns the full content of the alert as plain text. This text must be safe to render without
   * HTML interpretation and should contain all details necessary for a user who cannot render HTML.
   * Newlines may separate lines; callers are free to wrap as needed for display.
   *
   * @return plain-text body of the alert; non-null, suitable for text-only renderers and feeds.
   */
  String getText();

  /**
   * Returns the full content of the alert as a structured HTML fragment. When provided, this allows
   * richer presentation such as links or emphasis. Implementations should return markup that is
   * safe for embedding and does not rely on external scripts or styles. If HTML is not available,
   * callers should fall back to {@link #getText()}.
   *
   * @return an {@link HTMLNode} containing an HTML fragment, or {@code null} when not provided.
   */
  HTMLNode getHTMLText();

  /**
   * Returns a very short summary for compact contexts such as notifications and feeds. The summary
   * should remain understandable after translation into more verbose languages and be comfortably
   * under one display line. User interfaces typically make this summary clickable to show full
   * details.
   *
   * @return a compact, single-line summary of the alert for constrained UI placements.
   */
  String getShortText();

  /**
   * Returns the priority class of the alert, allowing callers to rank, style, or filter alerts.
   * Values map to the constants defined on this interface: {@link #CRITICAL_ERROR}, {@link #ERROR},
   * {@link #WARNING}, and {@link #MINOR}. Higher-severity classes should receive more prominent
   * placement and attention in user interfaces.
   *
   * @return one of the defined priority constants indicating severity and display importance.
   */
  short getPriorityClass();

  /**
   * Reports whether the alert is currently valid and should be shown. Callers that consume multiple
   * fields from an alert are encouraged to synchronize on the alert instance, check this flag, and
   * then read the remaining fields to get a consistent snapshot for rendering.
   *
   * @return {@code true} if the alert remains relevant and should be displayed; {@code false}
   *     otherwise.
   */
  boolean isValid();

  /**
   * Updates the alert validity flag. Implementations may ignore changes when the alert is not
   * user-dismissible. When set to {@code false}, consumers should stop rendering the alert and may
   * drop it from future feeds or lists.
   *
   * @param validity {@code true} to mark the alert as currently valid and visible; {@code false} to
   *     hide it until it is revalidated or replaced by the producer.
   */
  void isValid(boolean validity);

  /**
   * Provides the localized text to place on a dismiss action (e.g., a button). The value is
   * relevant only when {@link #userCanDismiss()} is {@code true}; callers may ignore it otherwise.
   * Examples include “Dismiss”, “Hide”, or domain-specific verbs like “Acknowledge”.
   *
   * @return the label to use for the dismissal control, suitable for direct display to users.
   */
  String dismissButtonText();

  /**
   * Indicates whether the alert should be unregistered entirely when a user dismisses it. If {@code
   * true}, the producer will typically remove the alert from the registry upon dismissal rather
   * than just marking it invalid.
   *
   * @return {@code true} when dismissal should unregister the alert from its manager; otherwise
   *     {@code false}.
   */
  boolean shouldUnregisterOnDismiss();

  /**
   * Callback invoked when a user dismisses the alert. Implementations may perform cleanup, persist
   * acknowledgement, or trigger follow-up actions. This method must not throw and should return
   * quickly, avoiding blocking operations on UI threads.
   */
  void onDismiss();

  /**
   * Returns a unique, stable, and short anchor string for the alert used as an identifier in feeds
   * and fragment links. It is not shown to end users. Implementations must avoid spaces and commas
   * to keep URLs stable and parsable.
   *
   * @return short unique identifier for the alert; contains no spaces or commas.
   */
  String anchor();

  /**
   * Signals that this alert represents a transient event notification. Event notifications can be
   * bulk-deleted and are expected to be displayed differently from persistent operational alerts
   * (for example, in an activity stream rather than a sticky banner).
   *
   * @return {@code true} when the alert is a transient event; {@code false} for persistent alerts.
   */
  boolean isEventNotification();

  /**
   * Produces the message that will be sent to subscribers of the FCP feed that mirrors user alerts
   * for remote clients. Implementations should populate the message with the same values exposed by
   * this interface so consumers observe consistent data across protocols.
   *
   * @return an FCP message describing this alert for subscribing FCP clients; never {@code null}.
   */
  FCPMessage getFCPMessage();

  /**
   * Returns the moment the alert was last updated, expressed as milliseconds since the Unix epoch
   * (January 1st, 1970 UTC). Consumers use this timestamp for ordering and freshness indicators.
   * Implementations should advance this value whenever the alert’s visible content or status
   * changes.
   *
   * @return epoch time in milliseconds of the most recent update to this alert.
   */
  long getUpdatedTime();

  /**
   * An error that prevents normal operation and likely requires immediate user attention. User
   * interfaces should present critical alerts prominently and may block unrelated actions until the
   * condition is acknowledged or resolved.
   */
  short CRITICAL_ERROR = 0;

  /**
   * A serious error that may prevent normal operation but could be transient or recoverable without
   * user intervention. Surfaces should highlight the condition and encourage the user to review
   * details, while allowing continued use where safe.
   */
  short ERROR = 1;

  /**
   * A warning about degraded operation or reduced anonymity, such as insufficient connections or
   * similar conditions. Users should be informed and offered guidance to improve the situation, but
   * normal operation can often continue.
   */
  short WARNING = 2;

  /**
   * A minor notification or informational message that does not indicate an error condition. UIs
   * may display these less prominently and allow users to dismiss them quickly.
   */
  short MINOR = 3;
}
