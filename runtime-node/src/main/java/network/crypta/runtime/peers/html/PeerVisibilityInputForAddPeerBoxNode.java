package network.crypta.runtime.peers.html;

import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;

/**
 * Renders the "peer visibility" choice UI used by the Add Peer box in the web interface.
 *
 * <p>This node builds a small HTML fragment consisting of a title, an introductory sentence, and a
 * radio-button group for selecting a {@link DarknetPeerNode.FRIEND_VISIBILITY} value. The full
 * subtree is created eagerly in the constructor, so callers can simply add the instance to a larger
 * page structure without further configuration.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Uses the enum declaration order of {@link DarknetPeerNode.FRIEND_VISIBILITY#values()} when
 *       rendering options to preserve stable, user-facing ordering.
 *   <li>Marks the option whose {@code isDefaultValue()} returns {@code true} as checked.
 *   <li>Generates stable element IDs using a fixed prefix plus the enum constant name, and uses
 *       those IDs to bind {@code <label for="...">} elements to their corresponding inputs.
 * </ul>
 *
 * <p>Instances are mutable via the underlying {@link HTMLNode} tree and are intended to be used as
 * request-scoped objects. Do not share a single instance across threads without external
 * synchronization.
 */
public class PeerVisibilityInputForAddPeerBoxNode extends HTMLNode {

  private static final String INPUT_NAME_VISIBILITY = "visibility";
  private static final String VISIBILITY_ID_PREFIX = "visibility";

  /**
   * Creates a {@code <div>} containing the visibility selector UI.
   *
   * <p>The constructor appends child nodes that render:
   *
   * <ul>
   *   <li>A bolded title and a localized introduction.
   *   <li>A radio-button group named {@code "visibility"} with one option per {@link
   *       DarknetPeerNode.FRIEND_VISIBILITY} constant.
   * </ul>
   *
   * <p>The generated input {@code id} values use the fixed prefix {@code "visibility"} followed by
   * the enum constant name, and each option also includes a corresponding {@code <label>} that
   * references that id via its {@code for} attribute. Exactly one option is marked checked when the
   * enum indicates a default via {@code isDefaultValue()}.
   */
  public PeerVisibilityInputForAddPeerBoxNode() {
    super("div");

    this.addChild("b", l10n("DarknetConnectionsToadlet.peerVisibilityTitle"));
    this.addChild("#", " ");
    this.addChild("#", l10n("DarknetConnectionsToadlet.peerVisibilityIntroduction"));
    for (DarknetPeerNode.FRIEND_VISIBILITY visibility :
        DarknetPeerNode.FRIEND_VISIBILITY.values()) { // Keep enum order for compatibility.
      HTMLNode input =
          this.addChild("br")
              .addChild(
                  "input",
                  new String[] {"type", "name", "value", "id"},
                  new String[] {
                    "radio",
                    INPUT_NAME_VISIBILITY,
                    visibility.name(),
                    VISIBILITY_ID_PREFIX + visibility.name()
                  });
      if (visibility.isDefaultValue()) {
        input.addAttribute("checked", "checked");
      }
      input
          .addChild(
              "label",
              new String[] {"for"},
              new String[] {VISIBILITY_ID_PREFIX + visibility.name()})
          .addChild("b", l10n("DarknetConnectionsToadlet.peerVisibility." + visibility.name()));
      input.addChild("#", ": ");
      input.addChild(
          "#", l10n("DarknetConnectionsToadlet.peerVisibilityExplain." + visibility.name()));
    }
    this.addChild("br");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString(key);
  }
}
