package network.crypta.node.useralerts;

import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.support.HTMLNode;

/**
 * Alert raised when the node is configured with an {@code ipAddressOverride} that cannot be used
 * (for example, the value has invalid hostname/IP syntax or does not resolve). The alert guides the
 * operator to the Node configuration page and, when HTML is available, renders a small form that
 * allows correcting the value in-place.
 *
 * <p>Typical consumers display the localized title, a short summary for compact contexts, and a
 * longer explanation. For richer surfaces (such as the web UI), {@link #getHTMLText()} returns a
 * self-contained HTML fragment with a link to {@code /config/node} and a pre-populated text field
 * for {@code node.ipAddressOverride}. The alert class does not change configuration by itself; it
 * only renders guidance and a convenience form.
 *
 * <p>Instances are read-mostly after construction and can be safely rendered from multiple threads
 * as long as callers follow the usual {@link AbstractUserAlert} snapshot guidance (synchronize,
 * check {@link #isValid()}, then read fields). The priority is {@link UserAlert#ERROR} to ensure it
 * is prominent without blocking the UI like {@link UserAlert#CRITICAL_ERROR} would.
 *
 * <ul>
 *   <li>Responsibilities: inform about an unusable address override and point to a fix path.
 *   <li>Notable behavior: provides both plain text and structured HTML content.
 *   <li>Where used: created and registered by {@link network.crypta.node.NodeIPDetector} when the
 *       override value fails validation.
 * </ul>
 *
 * <pre>{@code
 * // Example: registering the alert when validation fails
 * var alert = new InvalidAddressOverrideUserAlert(node);
 * node.getClientCore().getAlerts().register(alert);
 * }</pre>
 */
public class InvalidAddressOverrideUserAlert extends AbstractUserAlert {

  /**
   * Creates the alert bound to a specific node instance whose configuration is used to render the
   * corrective form. The constructor does not perform validation; producers are expected to create
   * and register the alert when a bad {@code ipAddressOverride} value is detected.
   *
   * <p>The alert is created as dismissible={@code false}. It remains visible until either the
   * configuration is fixed or the producer unregisters it.
   *
   * @param n the owning {@link Node}; used to resolve the {@code node} sub-configuration, fetch the
   *     {@code ipAddressOverride} option, and obtain a form password for CSRF protection; must not
   *     be {@code null}.
   */
  public InvalidAddressOverrideUserAlert(Node n) {
    // No custom dismiss behavior or label
    super(false, null, null, (short) 0, true, null);
    this.node = n;
  }

  final Node node;

  // Deduplicate repeated literals for Sonar maintainability rule (java:S1192)
  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_CLASS = "class";

  /**
   * Returns a localized, succinct title suitable for listings and banners. The title communicates
   * that the configured address override is not recognized or valid. Titles are intentionally short
   * so they fit in compact UI areas without wrapping and remain readable across locales. The value
   * is stable for the lifetime of the alert and does not include punctuation or markup. User
   * interfaces may pair it with {@link #getShortText()} to provide a slightly longer summary when
   * space allows, and with {@link #getText()} or {@link #getHTMLText()} for full details.
   *
   * @return a localized one-line title indicating an unknown or invalid address override value.
   */
  @Override
  public String getTitle() {
    return l10n("unknownAddressTitle");
  }

  /**
   * Returns the plain-text explanation describing why the address override cannot be used and how
   * to correct it. This content is safe for text-only renderers and omits any markup. It is
   * appropriate for logs, feeds, or clients that do not render HTML. Callers should prefer this
   * text when sanitizing output or when embedding in contexts that strip tags. The message
   * typically instructs the operator to visit the node configuration page and adjust the {@code
   * ipAddressOverride} value to a syntactically valid hostname or IP address.
   *
   * @return a localized, plain-text body explaining the issue and pointing to configuration.
   */
  @Override
  public String getText() {
    return l10n("unknownAddress");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("InvalidAddressOverrideUserAlert." + key);
  }

  /**
   * Returns a structured HTML fragment that links to the node configuration page and embeds a small
   * form. The form contains the necessary hidden fields (including a form password), targets {@code
   * /config/node}, and includes a pre-populated text input for {@code node.ipAddressOverride}.
   * Callers can embed the returned node directly into their view. Submissions are handled by the
   * standard configuration endpoint; this class does not perform any client-side validation or
   * mutation on its own. When user interfaces render this fragment, they should ensure the
   * surrounding container allows forms and that the action URL is reachable in the current
   * environment.
   *
   * <p>The fragment is self-contained and does not rely on external scripts. Callers that cannot
   * render HTML should ignore this and use {@link #getText()} instead.
   *
   * @return an {@link HTMLNode} containing a <code>div</code> with explanatory text and a form that
   *     posts back to the node configuration endpoint.
   */
  @Override
  public HTMLNode getHTMLText() {
    SubConfig sc = node.getConfig().get("node");
    Option<?> o = sc.getOption("ipAddressOverride");

    HTMLNode textNode = new HTMLNode("div");
    NodeL10n.getBase()
        .addL10nSubstitution(
            textNode,
            "InvalidAddressOverrideUserAlert.unknownAddressWithConfigLink",
            new String[] {"link"},
            new HTMLNode[] {HTMLNode.link("/config/node")});
    HTMLNode formNode =
        textNode.addChild(
            "form", new String[] {"action", "method"}, new String[] {"/config/node", "post"});
    formNode.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "formPassword", node.getClientCore().getFormPassword()});
    formNode.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", "subconfig", sc.getPrefix()});
    HTMLNode listNode = formNode.addChild("ul", ATTR_CLASS, "config");
    HTMLNode itemNode = listNode.addChild("li");
    itemNode
        .addChild("span", ATTR_CLASS, "configshortdesc", o.getLocalisedShortDesc())
        .addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE},
            new String[] {
              "text", sc.getPrefix() + ".ipAddressOverride", o.getValueDisplayString()
            });
    itemNode.addChild("span", ATTR_CLASS, "configlongdesc", o.getLocalisedLongDesc());
    formNode.addChild(
        TAG_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {"submit", NodeL10n.getBase().getString("UserAlert.apply")});
    formNode.addChild(
        TAG_INPUT,
        new String[] {"type", ATTR_VALUE},
        new String[] {"reset", NodeL10n.getBase().getString("UserAlert.reset")});
    return textNode;
  }

  /**
   * Returns the severity class used for sorting and styling within alert consumers. {@link
   * UserAlert#ERROR} denotes a serious configuration problem that the operator should address soon,
   * but it is not as disruptive as {@link UserAlert#CRITICAL_ERROR}. Consumers commonly use the
   * priority to group and color-code alerts, and to decide default visibility. The value is
   * constant for the lifetime of this alert and does not change based on subsequent detections.
   *
   * @return {@link UserAlert#ERROR} to denote a serious, actionable configuration problem.
   */
  @Override
  public short getPriorityClass() {
    return UserAlert.ERROR;
  }

  /**
   * Returns a compact, single-line summary suitable for constrained placements such as list rows or
   * notifications. The summary communicates that the address override is not valid and invites the
   * user to review configuration. It is more concise than {@link #getText()} and is intended to be
   * readable even when truncated. Surfaces that show only summaries should link to a view with the
   * full explanation and, when possible, render the HTML fragment to offer an in-place correction
   * flow.
   *
   * @return a localized, concise summary describing the invalid address override condition.
   */
  @Override
  public String getShortText() {
    return l10n("unknownAddressShort");
  }
}
