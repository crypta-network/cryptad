package network.crypta.runtime.alerts;

import network.crypta.compat.bandwidth.BandwidthLimit;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;

/**
 * Presents a user-facing alert inviting the operator to review and, if desired, upgrade the
 * configured connection speed limits for the node. The alert renders a short explanation together
 * with a small HTML form that pre-populates download and upload limits and posts back to the root
 * endpoint to apply the changes.
 *
 * <p>This alert is intended to be created programmatically via {@link
 * #createAlert(network.crypta.node.Node, network.crypta.compat.bandwidth.BandwidthLimit)} when the
 * node has detected that higher bandwidth limits are appropriate (for example, after environment or
 * capacity checks). The instance maintains two bits of transient UI state: an optional one-shot
 * {@code error} message that is shown once on the next render and then cleared, and an {@code
 * upgraded} flag that switches the content to a compact success message and adjusts the Dismiss
 * button text accordingly.
 *
 * <p>Instances are straightforward and mutable and perform no synchronization. Callers should
 * confine mutations such as {@link #setError(String)} and {@link #setUpgraded(boolean)} to the same
 * thread or arrange for external synchronization if accessed concurrently by multiple request
 * handlers. The alert unregisters itself when dismissed by the user.
 *
 * <ul>
 *   <li>Renders current limits and suggested values formatted via {@link
 *       SizeUtil#formatSize(long)}.
 *   <li>Posts hidden fields including a form password and an action key used by the handler.
 *   <li>Adjusts the visible content after a successful upgrade (based on {@code upgraded}).
 * </ul>
 *
 * @see AbstractUserAlert
 * @see UserAlertManager
 * @see network.crypta.compat.bandwidth.BandwidthLimit
 */
public class UpgradeConnectionSpeedUserAlert extends AbstractUserAlert {

  private static final String INPUT = "input";
  private static final String OUTPUT = "output";
  private static final String STYLE = "style";
  private static final String VALUE = "value";

  private final Node node;
  private final BandwidthLimit bandwidthLimit;
  private boolean upgraded;
  private String error;

  private UpgradeConnectionSpeedUserAlert(Node node, BandwidthLimit bandwidthLimit) {
    this.node = node;
    this.bandwidthLimit = bandwidthLimit;
  }

  /**
   * Registers a new upgrade alert with the node's {@link UserAlertManager} using the supplied
   * bandwidth limits as the initial, pre-filled values in the form. Existing alerts of other types
   * are unaffected.
   *
   * <p>The supplied limits are displayed using the same human-readable units and formatting as
   * {@link SizeUtil#formatSize(long)}. This method creates a single alert instance and registers it
   * immediately; ownership is transferred to the alert manager.
   *
   * <pre>{@code
   * // Example: display an upgrade prompt derived from detected bandwidth
   * BandwidthLimit limit = detector.detect();
   * UpgradeConnectionSpeedUserAlert.createAlert(node, limit);
   * }</pre>
   *
   * @param node the node whose alert manager receives the new alert; must not be {@code null} and
   *     must provide an initialized client core and alert subsystem.
   * @param bandwidthLimit the suggested download/upload limits used to prefill the form; values are
   *     interpreted as bytes per second and formatted for display. Must not be {@code null}.
   */
  public static void createAlert(Node node, BandwidthLimit bandwidthLimit) {
    node.services()
        .clientCore()
        .getAlerts()
        .register(new UpgradeConnectionSpeedUserAlert(node, bandwidthLimit));
  }

  /** {@inheritDoc} */
  @Override
  public String getTitle() {
    return l10n("title");
  }

  /**
   * Builds the HTML content for the alert. When {@link #setUpgraded(boolean) upgraded} is {@code
   * true}, a short confirmation paragraph is returned. Otherwise, a form is produced with current
   * and proposed limits, a hidden action marker, and the node's form password.
   *
   * <p>If an {@linkplain #setError(String) error message} has been set, it is rendered once and
   * cleared so later renders do not repeat it.
   *
   * @return a non-{@code null} container node representing the alert body and embedded form. The
   *     returned node is not reused between calls and may be freely modified by the caller.
   */
  @Override
  public HTMLNode getHTMLText() {
    HTMLNode content = new HTMLNode("div");

    if (upgraded) {
      content.addChild("p", l10n("upgraded"));
      return content;
    }
    content.addChild(
        "p",
        l10nText(
            new String[] {INPUT, OUTPUT},
            new String[] {
              SizeUtil.formatSize(node.getConfig().get("node").getInt("inputBandwidthLimit")),
              SizeUtil.formatSize(node.getConfig().get("node").getInt("outputBandwidthLimit"))
            }));
    if (error != null) {
      content.addChild("p", error);
      error = null;
    }
    HTMLNode form =
        content.addChild("form", new String[] {"action", "method"}, new String[] {"/", "post"});
    HTMLNode bandwidthInput =
        form.addChild(
            "div",
            new String[] {STYLE},
            new String[] {"display: inline-block; text-align: right;"});
    bandwidthInput.addChild("span", STYLE, "margin-right: .5em;", l10n("downloadLimit"));
    bandwidthInput.addChild(
        INPUT,
        new String[] {"type", "name", VALUE},
        new String[] {
          "text", "inputBandwidthLimit", SizeUtil.formatSize(bandwidthLimit.downBytes())
        });
    bandwidthInput.addChild("br");
    bandwidthInput.addChild("span", STYLE, "margin-right: .5em;", l10n("uploadLimit"));
    bandwidthInput.addChild(
        INPUT,
        new String[] {"type", "name", VALUE},
        new String[] {
          "text", "outputBandwidthLimit", SizeUtil.formatSize(bandwidthLimit.upBytes())
        });

    form.addChild(
        INPUT,
        new String[] {"type", "name", VALUE},
        new String[] {"hidden", "upgradeConnectionSpeed", "upgradeConnectionSpeed"});
    form.addChild(
        INPUT,
        new String[] {"type", "name", VALUE},
        new String[] {"hidden", "formPassword", node.services().clientCore().getFormPassword()});
    form.addChild(INPUT, new String[] {"type", VALUE}, new String[] {"submit", "Upgrade"});

    return content;
  }

  /** {@inheritDoc} */
  @Override
  public String dismissButtonText() {
    return upgraded
        ? NodeL10n.getBase().getString("Toadlet.ok")
        : NodeL10n.getBase().getString("Toadlet.no");
  }

  /** {@inheritDoc} */
  @Override
  public boolean userCanDismiss() {
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public boolean shouldUnregisterOnDismiss() {
    return true;
  }

  /**
   * Sets an error message to be displayed above the form on the next render. The message is treated
   * as transient UI state: it is emitted once by {@link #getHTMLText()} and then cleared so that
   * later renders do not repeat it.
   *
   * @param error human-readable message explaining why the previous attempt failed or why the
   *     suggested values are invalid. A {@code null} value clears any pending message without
   *     displaying one.
   */
  public void setError(String error) {
    this.error = error;
  }

  /**
   * Marks the alert as upgraded, switching the rendered content to a compact success text and
   * changing the Dismiss button to an affirmative label. Callers typically set this to {@code true}
   * after successfully applying the submitted bandwidth limits.
   *
   * @param upgraded when {@code true}, subsequent {@link #getHTMLText()} calls return a short
   *     confirmation paragraph and the Dismiss button text becomes an "OK" equivalent; when {@code
   *     false}, the full form is rendered.
   */
  public void setUpgraded(boolean upgraded) {
    this.upgraded = upgraded;
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("UpgradeConnectionSpeedUserAlert." + key);
  }

  private String l10nText(String[] patterns, String[] values) {
    return NodeL10n.getBase().getString("UpgradeConnectionSpeedUserAlert.text", patterns, values);
  }
}
