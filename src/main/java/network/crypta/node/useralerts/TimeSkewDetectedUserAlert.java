package network.crypta.node.useralerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;

/**
 * User alert displayed when the local system clock appears to be significantly skewed.
 *
 * <p>A noticeable time skew can have surprising, user-visible side effects for a Crypta node,
 * including failed handshakes, rejected messages, and misleading retry or timeout behavior. This
 * alert provides a concise explanation along with a clear call to action so the operator can adjust
 * the system clock or enable network time synchronization. The alert is intended to be created and
 * shown by the node during startup or early runtime checks when skew is detected, and then left in
 * place until the user dismisses it or the condition clears.
 *
 * <p>Instances of this alert are immutable after construction and are safe to publish to
 * user-facing UI components. The title, short text, and body text are localized via {@link
 * NodeL10n} using the {@code TimeSkewDetectedUserAlert.*} resource keys. Rendering helpers may use
 * {@link #getHTMLText()} to obtain a simple HTML representation suitable for inclusion in status or
 * alerts panels.
 *
 * <ul>
 *   <li>Responsibility: convey detected clock skew and recommended remediation.
 *   <li>Severity: reported as a critical error to increase visibility.
 *   <li>Dismissal: end users can hide the alert via the provided dismiss option.
 * </ul>
 *
 * @see AbstractUserAlert
 * @see UserAlert
 * @see HTMLNode
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class TimeSkewDetectedUserAlert extends AbstractUserAlert {

  /**
   * Creates a new alert describing that a significant local time skew has been detected.
   *
   * <p>The constructed alert marks itself as a critical user-facing error and attaches a
   * user-controllable {@link DismissOptions} choice that hides the alert without altering the
   * underlying detection state. All visible strings are resolved lazily through {@link
   * NodeL10n#getBase()} using the {@code TimeSkewDetectedUserAlert.*} keys.
   *
   * <pre>{@code
   * // Typical usage during startup checks when skew is detected
   * var alert = new TimeSkewDetectedUserAlert();
   * alertManager.enqueue(alert);
   * }</pre>
   */
  public TimeSkewDetectedUserAlert() {
    super(
        false,
        null,
        null,
        UserAlert.CRITICAL_ERROR,
        false,
        new DismissOptions(NodeL10n.getBase().getString("UserAlert.hide"), false));
  }

  /**
   * Returns a localized title summarizing the alert.
   *
   * <p>The title is retrieved from {@link NodeL10n} using the {@code
   * TimeSkewDetectedUserAlert.title} resource key. Implementations typically display this string
   * prominently in alert headers or dialog captions.
   *
   * @return a short, localized title suitable for alert headers; never {@code null}.
   */
  @Override
  public String getTitle() {
    return l10n("title");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("TimeSkewDetectedUserAlert." + key);
  }

  /**
   * Returns the full localized body text explaining the clock skew condition.
   *
   * <p>The body text is obtained from {@link NodeL10n} using the {@code
   * TimeSkewDetectedUserAlert.text} key. It is intended for detailed descriptions in message areas
   * or expandable sections and may include actionable guidance.
   *
   * @return full, localized explanatory text for the alert; never {@code null}.
   */
  @Override
  public String getText() {
    return l10n("text");
  }

  /**
   * Returns a concise, localized summary appropriate for compact displays.
   *
   * <p>The summary is resolved from the {@code TimeSkewDetectedUserAlert.shortText} resource key
   * and is suitable for notification toasts, table rows, or list items where space is constrained.
   *
   * @return brief, localized summary text describing the alert; never {@code null}.
   */
  @Override
  public String getShortText() {
    return l10n("shortText");
  }

  /**
   * Returns a minimal HTML representation of the alert body.
   *
   * <p>The returned {@link HTMLNode} wraps the same content provided by {@link #getText()} inside a
   * simple {@code <div>} for embedding into HTML-capable UI components. No additional markup is
   * added by this class.
   *
   * @return an HTML node containing the localized body text; ownership remains with the caller.
   */
  @Override
  public HTMLNode getHTMLText() {
    return new HTMLNode("div", getText());
  }
}
