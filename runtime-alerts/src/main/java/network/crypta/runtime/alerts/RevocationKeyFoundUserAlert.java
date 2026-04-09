package network.crypta.runtime.alerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;

/**
 * User alert indicating that the updater revocation signal has been detected.
 *
 * <p>This alert is shown when the node determines that the Crypta auto-update channel is no longer
 * trustworthy. Two closely related scenarios are supported: (1) a hard revocation where a trusted
 * party has published a signed message stating that the updater keys are compromised, and (2) a
 * defensive disablement where the node locally turns off the updater due to suspicious conditions
 * that may indicate compromise. In both cases the alert is marked as a {@link
 * UserAlert#CRITICAL_ERROR} and is not user-dismissible.
 *
 * <p>The textual body is provided both as plain concatenated text (for log- or text-only consumers)
 * and as structured HTML paragraphs intended for rendering in the UI. The HTML content is created
 * using {@link HTMLNode} and mirrors the localized strings used for the plain text so that both
 * representations remain consistent. Once constructed, instances are effectively immutable and
 * thread-safe to share across components; changing validity requests are ignored to ensure the
 * alert persists until the application logic removes it.
 *
 * <ul>
 *   <li>Priority: critical; not dismissible by end users.
 *   <li>Body: localized summary plus a detail paragraph with the supplied message.
 *   <li>Use when updater compromise or defensive disablement must be surfaced immediately.
 * </ul>
 *
 * <p>This alert type is typically instantiated by updater management code that remains in {@code
 * :runtime-node}.
 *
 * @see AbstractUserAlert
 * @see UserAlert
 */
public class RevocationKeyFoundUserAlert extends AbstractUserAlert {
  private static final String L10N_PARAM_MESSAGE = "message";

  /**
   * Builds a critical, non-dismissible alert describing an updater compromise or disablement.
   *
   * <p>When {@code disabledNotBlown} is {@code true}, the alert communicates that the updater has
   * been disabled locally due to a suspected issue, and the title/body reflect that state. When it
   * is {@code false}, the alert communicates that a signed revocation message was found and the
   * updater appears compromised. In both cases, the alert exposes a short text, a long text, and an
   * HTML body consisting of two paragraphs derived from localized resources.
   *
   * <pre>{@code
   * // Example: construct and register the alert
   * var alert = new RevocationKeyFoundUserAlert(message, true);
   * }</pre>
   *
   * @param msg human-readable detail appended to the localized body; may contain paths or other
   *     diagnostic context; must be safe to display to end users and may be empty but not {@code
   *     null}.
   * @param disabledNotBlown when {@code true}, indicates the updater was disabled defensively; when
   *     {@code false}, indicates a hard revocation was detected and the updater appears
   *     compromised.
   */
  public RevocationKeyFoundUserAlert(String msg, boolean disabledNotBlown) {
    super(
        false,
        getTitle(disabledNotBlown),
        Body.of(
            getText(disabledNotBlown, msg),
            getText(disabledNotBlown, msg),
            getHTML(disabledNotBlown, msg)),
        UserAlert.CRITICAL_ERROR,
        true,
        new DismissOptions(null, false));
  }

  private static HTMLNode getHTML(boolean disabledNotBlown, String msg) {
    HTMLNode div = new HTMLNode("div");
    if (disabledNotBlown) {
      div.addChild("p", NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.textDisabled"));
      div.addChild(
          "p",
          NodeL10n.getBase()
              .getString(
                  "RevocationKeyFoundUserAlert.textDisabledDetail", L10N_PARAM_MESSAGE, msg));
    } else {
      div.addChild("p", NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.text"));
      div.addChild(
          "p",
          NodeL10n.getBase()
              .getString("RevocationKeyFoundUserAlert.textDetail", L10N_PARAM_MESSAGE, msg));
    }
    return div;
  }

  private static String getText(boolean disabledNotBlown, String msg) {
    if (disabledNotBlown) {
      return NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.textDisabled")
          + " "
          + NodeL10n.getBase()
              .getString("RevocationKeyFoundUserAlert.textDisabledDetail", L10N_PARAM_MESSAGE, msg);
    } else {
      return NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.text")
          + " "
          + NodeL10n.getBase()
              .getString("RevocationKeyFoundUserAlert.textDetail", L10N_PARAM_MESSAGE, msg);
    }
  }

  private static String getTitle(boolean disabledNotBlown) {
    if (disabledNotBlown)
      return NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.titleDisabled");
    else return NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.title");
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation intentionally ignores the requested validity and keeps the alert valid
   * at all times. The parameter is accepted for API compatibility but has no effect. This behavior
   * ensures that a compromise warning remains visible until explicitly removed by the node.
   *
   * @param b requested validity flag; ignored by this implementation to preserve alert visibility.
   */
  @Override
  public void isValid(boolean b) {
    // We ignore it: it's ALWAYS valid!
  }
}
