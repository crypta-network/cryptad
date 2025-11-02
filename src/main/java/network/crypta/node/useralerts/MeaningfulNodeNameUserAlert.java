package network.crypta.node.useralerts;

import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.support.HTMLNode;

/**
 * User alert prompting the operator to choose a meaningful, human‑readable node name.
 *
 * <p>This alert is shown when the node runs without a customized name. The title and textual
 * content are localized at call time, and an HTML representation embeds a small configuration form
 * that posts to the node's configuration endpoint to update the {@code node.name} option. The form
 * includes the current value and the default as hints, helping users understand the impact before
 * applying the change. Implementations and callers should treat the HTML as a self‑contained
 * fragment that can be inserted into an existing page structure without additional scripts or
 * styles.
 *
 * <p>Instances follow the concurrency and lifecycle model defined by {@link AbstractUserAlert}.
 * They are not intrinsically thread‑safe; consumers that need a consistent snapshot should
 * synchronize on the instance, verify {@link #isValid()}, and then read title, text, and HTML in a
 * single critical section. Validity in this implementation is tied to peer presence (see {@link
 * #isValid()}) so that the prompt only appears when the node is actively participating in a
 * network.
 *
 * <ul>
 *   <li>Responsibilities: surface localized guidance and an inline configuration form.
 *   <li>HTML form: posts to {@code /config/<subconfig>} with a form password.
 *   <li>Dismissal: label and behavior are provided by the base class wiring.
 * </ul>
 *
 * @see AbstractUserAlert
 * @see UserAlert
 * @see Node
 */
public class MeaningfulNodeNameUserAlert extends AbstractUserAlert {
  private static final String ATTR_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_CLASS = "class";
  private final Node node;

  /**
   * Creates an alert bound to the provided node instance.
   *
   * <p>The alert reads and renders the current value of the {@code node.name} option and embeds the
   * node's CSRF form password in the generated HTML so the form can be submitted securely to the
   * configuration endpoint. Callers typically construct and register this alert when the node name
   * is empty or still at its default value.
   *
   * @param n the node whose configuration and localization resources are consulted when rendering
   *     text and HTML; the reference is stored for later calls and must remain usable for the
   *     lifetime of the alert.
   */
  public MeaningfulNodeNameUserAlert(Node n) {
    super(
        true,
        null,
        null,
        UserAlert.WARNING,
        true,
        new AbstractUserAlert.DismissOptions(NodeL10n.getBase().getString("UserAlert.hide"), true));
    this.node = n;
  }

  /** {@inheritDoc} */
  @Override
  public String getTitle() {
    return l10n("noNodeNickTitle");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("MeaningfulNodeNameUserAlert." + key);
  }

  /**
   * Returns the full, localized body text explaining why a meaningful node name is recommended.
   *
   * <p>The text is intended for primary content areas where a complete sentence or two can guide
   * the operator. It complements {@link #getShortText()}, which targets compact placements, and the
   * richer {@link #getHTMLText()} fragment that includes an inline form. Callers should render this
   * value as plain text; any HTML markup should be obtained from {@code getHTMLText()} instead to
   * avoid mixing presentation concerns.
   *
   * @return a localized explanatory message suitable for full‑width panels or dialogs; content is
   *     resolved from the node's localization bundle each time it is requested.
   */
  @Override
  public String getText() {
    return l10n("noNodeNick");
  }

  /**
   * Returns a compact, localized summary suitable for constrained UI locations.
   *
   * <p>The short text conveys the core recommendation in fewer words than {@link #getText()} so it
   * can fit notification banners, activity feeds, or lists where space is limited. Callers should
   * not assume a particular maximum length; apply their own truncation or wrapping as appropriate
   * for the target surface.
   *
   * @return a localized brief description encouraging the operator to set a meaningful node name;
   *     content is sourced from the node's localization bundle at call time.
   */
  @Override
  public String getShortText() {
    return l10n("noNodeNickShort");
  }

  /**
   * Builds an HTML fragment containing explanatory text and an inline configuration form.
   *
   * <p>The returned node contains: a paragraph that explains why naming is recommended; a form that
   * posts to the node configuration endpoint for the {@code node} sub‑configuration; hidden fields
   * carrying the CSRF form password and subconfig name; and a single text input bound to the {@code
   * node.name} option pre‑filled with the current value. The form includes submit and reset buttons
   * and renders both the short and long descriptions supplied by the underlying option metadata. No
   * client‑side scripts are required.
   *
   * @return an {@link HTMLNode} that callers may embed directly in an HTML page; ownership remains
   *     with the caller, and the fragment does not depend on external styles or scripts to be
   *     functional.
   */
  @Override
  public HTMLNode getHTMLText() {
    SubConfig sc = node.getConfig().get("node");
    Option<?> o = sc.getOption("name");

    HTMLNode alertNode = new HTMLNode("div");
    HTMLNode textNode = alertNode.addChild("div");
    textNode.addChild("#", l10n("noNodeNick"));
    HTMLNode formNode =
        alertNode.addChild(
            "form",
            new String[] {"action", "method"},
            new String[] {"/config/" + sc.getPrefix(), "post"});
    formNode.addChild(
        ATTR_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "formPassword", node.getClientCore().getFormPassword()});
    formNode.addChild(
        ATTR_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "subconfig", sc.getPrefix()});
    HTMLNode listNode = formNode.addChild("ul", ATTR_CLASS, "config");
    HTMLNode itemNode = listNode.addChild("li");
    itemNode
        .addChild(
            "span",
            new String[] {ATTR_CLASS, "title", "style"},
            new String[] {
              "configshortdesc",
              NodeL10n.getBase()
                  .getString(
                      "ConfigToadlet.defaultIs",
                      new String[] {"default"},
                      new String[] {o.getDefault()}),
              "cursor: help;"
            })
        .addChild(o.getShortDescNode());
    itemNode.addChild(
        ATTR_INPUT,
        new String[] {"type", ATTR_CLASS, "alt", "name", ATTR_VALUE},
        new String[] {"text", "config", o.getShortDesc(), "node.name", o.getValueDisplayString()});
    itemNode.addChild("span", ATTR_CLASS, "configlongdesc").addChild(o.getLongDescNode());
    formNode.addChild(
        ATTR_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {"submit", NodeL10n.getBase().getString("UserAlert.apply")});
    formNode.addChild(
        ATTR_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {"reset", NodeL10n.getBase().getString("UserAlert.reset")});

    return alertNode;
  }

  /**
   * Indicates whether the alert should currently be shown to the user.
   *
   * <p>This implementation bases validity on peer state and returns {@code true} when the node has
   * at least one Darknet peer (via {@code node.getPeers().anyDarknetPeers()}). This avoids
   * surfacing the prompt on isolated or bootstrap‑phase nodes while still encouraging identifiable
   * naming once the node participates in a network.
   *
   * @return {@code true} when the alert is considered applicable and should be displayed; {@code
   *     false} otherwise.
   */
  @Override
  public boolean isValid() {
    return node.getPeers().anyDarknetPeers();
  }
}
