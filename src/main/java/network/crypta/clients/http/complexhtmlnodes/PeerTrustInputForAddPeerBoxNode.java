package network.crypta.clients.http.complexhtmlnodes;

import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;

/**
 * Renders the peer trust chooser section inside the “Add peer” box.
 *
 * <p>This {@link HTMLNode} subclass builds a small HTML fragment that lets a user pick the initial
 * trust level for a new darknet peer connection. The fragment is a {@code <div>} containing a
 * localized title and introduction followed by one radio button per {@link
 * network.crypta.node.DarknetPeerNode.FRIEND_TRUST} value, ordered using {@link
 * DarknetPeerNode.FRIEND_TRUST#valuesBackwards()}.
 *
 * <p>The generated inputs share a stable {@code name="trust"} so the enclosing form submits a
 * single value. Each option is given a deterministic {@code id} derived from the enum constant name
 * (for label association), and the enum’s default value is marked as selected via the {@code
 * checked} attribute.
 *
 * <p>This type is a mutable builder for an HTML tree. It is intended to be created and populated
 * during request handling and then treated as effectively immutable once attached to the outgoing
 * page; it is not designed for concurrent mutation.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> Create and wire radio inputs, labels, and descriptions.
 *   <li><b>Notable behavior:</b> Selects the default trust option automatically.
 * </ul>
 */
public class PeerTrustInputForAddPeerBoxNode extends HTMLNode {

  private static final String TRUST = "trust";

  /**
   * Creates a {@code <div>} node populated with the peer trust radio-button inputs.
   *
   * <p>The constructor performs all rendering work eagerly by appending children to {@code this}.
   * It adds a localized title and introduction, then iterates over the available {@link
   * DarknetPeerNode.FRIEND_TRUST} values and emits one {@code <input type="radio">} per enum
   * constant. The option returned by {@link DarknetPeerNode.FRIEND_TRUST#isDefaultValue()} is
   * marked as selected, ensuring the resulting form has a sensible default even when the user does
   * not change the setting.
   *
   * <p>No network access or persistent state changes occur here; the constructor only constructs
   * the in-memory HTML node structure.
   */
  public PeerTrustInputForAddPeerBoxNode() {
    super("div");

    this.addChild("b", l10n("DarknetConnectionsToadlet.peerTrustTitle"));
    this.addChild("#", " ");
    this.addChild("#", l10n("DarknetConnectionsToadlet.peerTrustIntroduction"));
    for (DarknetPeerNode.FRIEND_TRUST trust : DarknetPeerNode.FRIEND_TRUST.valuesBackwards()) {
      HTMLNode input =
          this.addChild("br")
              .addChild(
                  "input",
                  new String[] {"type", "name", "value", "id"},
                  new String[] {"radio", TRUST, trust.name(), TRUST + trust.name()});
      if (trust.isDefaultValue()) {
        input.addAttribute("checked", "checked");
      }
      input
          .addChild("label", new String[] {"for"}, new String[] {TRUST + trust.name()})
          .addChild("b", l10n("DarknetConnectionsToadlet.peerTrust." + trust.name()));
      input.addChild("#", ": ");
      input.addChild("#", l10n("DarknetConnectionsToadlet.peerTrustExplain." + trust.name()));
    }
    this.addChild("br");
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(key);
  }
}
