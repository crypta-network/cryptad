package network.crypta.runtime.alerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.NativeThread;

/**
 * User alert shown when the operating system does not provide enough distinct thread nice levels
 * for the node's scheduling strategy.
 *
 * <p>This alert is emitted when the runtime detects that the available native priority range is
 * smaller than what the node expects for its background and foreground worker pools. The message
 * explains both the number of priority levels detected at startup and the amount typically required
 * for optimal separation. It is informational and non-fatal: the node continues to run, but some
 * work categories may share the same effective priority and therefore compete more directly for CPU
 * time on certain platforms or configurations.
 *
 * <p>Typical usage is internal to the node: the alert is constructed during initialization and
 * delivered to the user alert system. UI components render the title and text, and may also present
 * the HTML variant for rich views. The instance is immutable after construction and can be safely
 * accessed from the UI thread; it does not hold external resources.
 *
 * <ul>
 *   <li>Explains detected vs. required priority levels.
 *   <li>Advises that behavior remains functional but less differentiated.
 *   <li>Provides plain-text and HTML representations for display.
 * </ul>
 *
 * @see network.crypta.support.io.NativeThread
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class NotEnoughNiceLevelsUserAlert extends AbstractUserAlert {
  /**
   * Creates the alert with a warning severity and a default dismiss option.
   *
   * <p>The constructed instance carries a localized title and message that explain the mismatch
   * between available and required native thread priority levels. Dismissal hides the alert from
   * subsequent views until re-created by the node. Construction performs no I/O and allocates no
   * external resources.
   */
  public NotEnoughNiceLevelsUserAlert() {
    super(
        true,
        null,
        null,
        UserAlert.WARNING,
        true,
        new DismissOptions(NodeL10n.getBase().getString("UserAlert.hide"), true));
  }

  /**
   * Returns the localized alert title suitable for compact UI placements.
   *
   * <p>The title is fetched from the node's localization bundle and does not contain dynamic
   * values. Implementations should treat the returned string as read-only and display it without
   * additional markup.
   *
   * @return a non-null, localized title describing the alert in one line
   */
  @Override
  public String getTitle() {
    return NodeL10n.getBase().getString("NotEnoughNiceLevelsUserAlert.title");
  }

  /**
   * Returns the full, localized text of the alert with numeric details.
   *
   * <p>The message includes the number of available native priority levels detected at runtime and
   * the number considered sufficient by the node. The string is intended for plain-text contexts
   * and will have any special characters already localized and safely encoded by the rendering
   * layer.
   *
   * @return a non-null, localized explanatory message containing counts
   */
  @Override
  public String getText() {
    return NodeL10n.getBase()
        .getString(
            "NotEnoughNiceLevelsUserAlert.content",
            new String[] {"available", "required"},
            new String[] {
              String.valueOf(NativeThread.NATIVE_PRIORITY_RANGE),
              String.valueOf(NativeThread.ENOUGH_NICE_LEVELS)
            });
  }

  /**
   * Returns a shortened, localized summary appropriate for lists or toasts.
   *
   * <p>The short text communicates the condition succinctly without embedded numbers or formatting,
   * allowing UIs to pair it with additional context such as timestamps or category icons.
   *
   * @return a non-null, localized short description of this alert
   */
  @Override
  public String getShortText() {
    return NodeL10n.getBase().getString("NotEnoughNiceLevelsUserAlert.short");
  }

  /**
   * Returns an HTML node containing the alert text for rich rendering.
   *
   * <p>The returned element wraps the plain-text {@link #getText()} in a {@code <div>} so that
   * consumers using HTML-capable views can style it consistently. Callers should not mutate or
   * reuse the node across unrelated UI trees.
   *
   * @return a new {@link HTMLNode} with the message as its text content
   */
  @Override
  public HTMLNode getHTMLText() {
    return new HTMLNode("div", getText());
  }
}
