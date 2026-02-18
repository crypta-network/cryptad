package network.crypta.node.useralerts;

import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.support.HTMLNode;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Alert presented to the user when the node cannot determine an external IP address.
 *
 * <p>This alert explains the probable causes and offers concrete next steps. Depending on the
 * current {@link Node} state, it may indicate that detection is still running, that no detector
 * plugins are loaded, or that the address remains unknown and the user should provide a temporary
 * hint or adjust network configuration.
 *
 * <ul>
 *   <li>Suggests loading detection plugins (e.g., UPnP) from the Plugins page.
 *   <li>Embeds a link to the relevant configuration section and a form for a temporary IP hint.
 *   <li>Recommends forwarding one or two UDP ports to improve reachability.
 * </ul>
 *
 * <p>The alert is considered valid while the node is likely unreachable (few connectible peers) or
 * when active detection is not occurring after a brief startup period. It does not display when
 * Opennet mode is enabled. Instances are lightweight and keep only a reference to the {@link Node};
 * all content is localized and computed at render time. Thread-safety follows the caller’s UI or
 * notification model; this class reads state from the node without synchronization.
 *
 * @see AbstractUserAlert
 * @see Node
 * @see network.crypta.node.NodeIPDetector
 */
public class IPUndetectedUserAlert extends AbstractUserAlert {
  private static final String L10N_PREFIX = "IPUndetectedUserAlert.";
  private static final String HTML_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_CLASS = "class";

  /**
   * Constructs an alert bound to a specific node instance.
   *
   * <p>The alert does not modify configuration. It renders localized text and provides a
   * configuration form that posts to the node’s configuration endpoint. Eligibility to display is
   * determined by {@link #isValid()} at the time of evaluation.
   *
   * @param n the node used to query detection status, peers, ports, and configuration; must not be
   *     {@code null} because all content is derived from this instance
   */
  public IPUndetectedUserAlert(Node n) {
    super(
        true,
        null,
        null,
        (short) 0,
        true,
        new AbstractUserAlert.DismissOptions(
            NodeL10n.getBase().getString("UserAlert.hide"), false));
    this.node = n;
  }

  final Node node;

  /**
   * Returns a localized short title summarizing the condition.
   *
   * <p>The title is intentionally brief so it fits alert headers and overview panels. It maps to
   * the localization key {@code IPUndetectedUserAlert.unknownAddressTitle} and does not include
   * dynamic data. Callers may display it alongside {@link #getShortText()} or {@link #getText()}
   * depending on the available space and the desired level of detail.
   *
   * @return a concise, localized title such as “Unknown external address”
   */
  @Override
  public String getTitle() {
    return l10n("unknownAddressTitle");
  }

  /**
   * Creates the plain-text body describing the current detection state and suggested actions.
   *
   * <p>The content varies by node state:
   *
   * <ul>
   *   <li>If no detector plugins are present, instructs the user to load them.
   *   <li>If detection is running, informs that the node is attempting discovery.
   *   <li>Otherwise, explains the unknown address and appends a port-forwarding suggestion.
   * </ul>
   *
   * @return a localized explanatory message that may include port numbers and guidance
   */
  @Override
  public String getText() {
    if (node.network().ipDetector().noDetectPlugins()) return l10n("noDetectorPlugins");
    if (node.network().ipDetector().isDetecting()) return l10n("detecting");
    else
      return l10n("unknownAddress", "port", Integer.toString(node.network().darknetPortNumber()))
          + ' '
          + textPortForwardSuggestion();
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  private String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, pattern, value);
  }

  // Removed the unused-generic l10n overload for arrays; only a specific key was used in this
  // class.

  /**
   * Determines whether the alert should be displayed for the current node state.
   *
   * <p>The alert is hidden when Opennet is enabled. Otherwise it remains valid if there are fewer
   * than five connectible peers or if the node has been up for at least one minute and detection is
   * not in progress.
   *
   * @return {@code true} when the alert should be shown to the user
   */
  @Override
  public boolean isValid() {
    if (node.network().isOpennetEnabled()) return false;
    return node.network().peers().countConnectiblePeers() < 5
        || (node.network().uptime() >= MINUTES.toMillis(1)
            && !node.network().ipDetector().isDetecting());
  }

  /**
   * Generates a localized HTML fragment with guidance and inline configuration controls.
   *
   * <p>The fragment includes:
   *
   * <ul>
   *   <li>A paragraph with a link to the configuration section.
   *   <li>Optional plugin-loading guidance when no detector is available.
   *   <li>A suggestion to forward one or two UDP ports determined from node settings.
   *   <li>A form to submit a temporary IP address hint (including a form password).
   * </ul>
   *
   * @return a mutable {@link HTMLNode} representing the alert body ready for rendering
   */
  @Override
  public HTMLNode getHTMLText() {
    HTMLNode textNode = new HTMLNode("div");
    SubConfig sc = node.getConfig().get("node");
    Option<?> o = sc.getOption("tempIPAddressHint");

    NodeL10n.getBase()
        .addL10nSubstitution(
            textNode,
            L10N_PREFIX
                + (node.network().ipDetector().isDetecting()
                    ? "detectingWithConfigLink"
                    : "unknownAddressWithConfigLink"),
            new String[] {"link"},
            new HTMLNode[] {HTMLNode.link("/config/" + sc.getPrefix())});

    int peers = node.network().peers().roster().getDarknetPeers().length;
    if (peers > 0)
      textNode.addChild("p", l10n("noIPMaybeFromPeers", "number", Integer.toString(peers)));

    if (node.network().ipDetector().noDetectPlugins()) {
      HTMLNode p = textNode.addChild("p");
      NodeL10n.getBase()
          .addL10nSubstitution(
              p,
              "IPUndetectedUserAlert.loadDetectPlugins",
              new String[] {
                "plugins", "config",
              },
              new HTMLNode[] {HTMLNode.link("/plugins/"), HTMLNode.link("/config/node")});
    } else if (!node.network().ipDetector().hasJSTUN()
        && !node.network().ipDetector().isDetecting()) {
      HTMLNode p = textNode.addChild("p");
      NodeL10n.getBase()
          .addL10nSubstitution(
              p,
              "IPUndetectedUserAlert.loadJSTUN",
              new String[] {"plugins"},
              new HTMLNode[] {HTMLNode.link("/plugins/")});
    }

    addPortForwardSuggestion(textNode);

    HTMLNode formNode =
        textNode.addChild(
            "form",
            new String[] {"action", "method"},
            new String[] {"/config/" + sc.getPrefix(), "post"});
    formNode.addChild(
        HTML_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "formPassword", node.services().clientCore().getFormPassword()});
    formNode.addChild(
        HTML_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "subconfig", sc.getPrefix()});
    HTMLNode listNode = formNode.addChild("ul", ATTR_CLASS, "config");
    HTMLNode itemNode = listNode.addChild("li");
    itemNode
        .addChild("span", ATTR_CLASS, "configshortdesc", o.getLocalisedShortDesc())
        .addChild(
            HTML_INPUT,
            new String[] {"type", "name", ATTR_VALUE},
            new String[] {
              "text", sc.getPrefix() + ".tempIPAddressHint", o.getValueDisplayString()
            });
    itemNode.addChild("span", ATTR_CLASS, "configlongdesc", o.getLocalisedLongDesc());
    formNode.addChild(
        HTML_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {"submit", NodeL10n.getBase().getString("UserAlert.apply")});
    formNode.addChild(
        HTML_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {"reset", NodeL10n.getBase().getString("UserAlert.reset")});

    return textNode;
  }

  private void addPortForwardSuggestion(HTMLNode textNode) {
    // Note: This alert suggests forwarding the standard darknet/opennet ports.
    // Supporting arbitrary numbers of ports and protocols would require broader L10n changes.
    int darknetPort = node.network().darknetPortNumber();
    int opennetPort = node.network().opennetFnpPort();
    if (opennetPort <= 0) {
      textNode.addChild(
          "#", " " + l10n("suggestForwardPort", "port", Integer.toString(darknetPort)));
    } else {
      textNode.addChild(
          "#",
          " "
              + NodeL10n.getBase()
                  .getString(
                      L10N_PREFIX + "suggestForwardTwoPorts",
                      new String[] {"port1", "port2"},
                      new String[] {Integer.toString(darknetPort), Integer.toString(opennetPort)}));
    }
  }

  private String textPortForwardSuggestion() {
    // Note: This text mirrors the current single/two-port suggestion behavior.
    // Expanding to multiple ports would entail non-trivial localization updates.
    int darknetPort = node.network().darknetPortNumber();
    int opennetPort = node.network().opennetFnpPort();
    if (opennetPort <= 0) {
      return l10n("suggestForwardPort", "port", Integer.toString(darknetPort));
    } else {
      return " "
          + NodeL10n.getBase()
              .getString(
                  L10N_PREFIX + "suggestForwardTwoPorts",
                  new String[] {"port1", "port2"},
                  new String[] {Integer.toString(darknetPort), Integer.toString(opennetPort)});
    }
  }

  /**
   * Reports the alert severity for ordering and visual emphasis.
   *
   * <p>The mapping is stable and idempotent for a given node state: while detection is running, the
   * severity is {@link UserAlert#WARNING}; when detection is not in progress and the address
   * remains unknown, the severity is {@link UserAlert#ERROR}. UI components can use this to group
   * or sort alerts by impact and to choose appropriate colors or icons.
   *
   * @return a {@link UserAlert} priority constant indicating severity
   */
  @Override
  public short getPriorityClass() {
    if (node.network().ipDetector().isDetecting()) return UserAlert.WARNING;
    else return UserAlert.ERROR;
  }

  /**
   * Returns a concise description suitable for compact alert listings.
   *
   * <p>This text mirrors the semantics of {@link #getText()} using shorter localization keys (for
   * example, {@code detectingShort} or {@code unknownAddressShort}). It is designed for tables,
   * notifications, and other space-constrained contexts where a single sentence is preferred over a
   * multi-paragraph explanation. The string is fully localized and free of HTML, making it safe to
   * display as plain text without additional processing.
   *
   * @return a brief, localized summary mirroring the long text with short keys
   */
  @Override
  public String getShortText() {
    if (node.network().ipDetector().noDetectPlugins()) return l10n("noDetectorPlugins");
    if (node.network().ipDetector().isDetecting()) return l10n("detectingShort");
    else return l10n("unknownAddressShort");
  }
}
