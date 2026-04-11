package network.crypta.clients.http;

import java.util.function.Consumer;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.support.HTMLNode;

/**
 * Renders detached trust and visibility controls for legacy darknet peer forms.
 *
 * <p>This helper keeps the HTTP adapter's peer form markup local after the legacy add-peer input
 * nodes were removed from the runtime layer. It owns only the small HTML fragments that the adapter
 * still needs for the Friends page: the radio groups shown when adding a darknet peer and the
 * {@code <select>} options used by the bulk trust and visibility actions. The helper preserves the
 * legacy field names, enum ordering, default selections, and L10n keys so existing form POSTs and
 * translations continue to work without adapter code reaching back into runtime-owned HTML helpers.
 *
 * <p>The class is intentionally stateless. Callers provide the destination {@link HTMLNode}, and
 * this helper appends deterministic child nodes derived from {@link PeerTrust} and {@link
 * PeerVisibility}. Trust values render in reverse enum order to match the historic UI, while
 * visibility values render in declaration order.
 */
final class DarknetPeerFormOptions {
  /** Shared form-field name for add-peer trust controls. */
  private static final String TRUST = "trust";

  /** Shared form-field name for add-peer visibility controls. */
  private static final String VISIBILITY = "visibility";

  /** Attribute name used for {@code <option>} and radio-input values. */
  private static final String ATTR_VALUE = "value";

  /** Boolean HTML attribute used to mark the legacy default choice as selected. */
  private static final String ATTR_CHECKED = "checked";

  /** Prevents instantiation because the helper exposes only static rendering methods. */
  private DarknetPeerFormOptions() {}

  /**
   * Appends the add-peer trust and visibility radio groups to a darknet peer form.
   *
   * <p>The added controls keep the legacy {@code trust} and {@code visibility} field names so the
   * existing POST parser can continue to map submitted values directly to {@link PeerTrust} and
   * {@link PeerVisibility}. The rendered defaults remain {@link PeerTrust#NORMAL} for trust and
   * {@link PeerVisibility#YES} for visibility.
   *
   * @param parent the form node that should receive the add-peer radio-group fragments
   */
  static void addAddPeerInputs(HTMLNode parent) {
    parent.addChild(createTrustInputs());
    parent.addChild(createVisibilityInputs());
  }

  /**
   * Appends trust {@code <option>} nodes in the legacy Friends-page display order.
   *
   * <p>Darknet bulk trust updates historically present higher trust levels first, so this method
   * iterates the enum values in reverse declaration order before adding the localized option
   * labels.
   *
   * @param selectNode the select element that should receive the trust options
   */
  static void addTrustOptions(HTMLNode selectNode) {
    forEachTrustInDisplayOrder(
        trust ->
            selectNode.addChild(
                "option", ATTR_VALUE, trust.name(), l10n("peerTrust." + trust.name())));
  }

  /**
   * Appends visibility {@code <option>} nodes in declaration order.
   *
   * <p>The visibility bulk-action control follows the enum declaration order so the rendered
   * choices stay aligned with the longstanding Friends-page wording and submitted values.
   *
   * @param selectNode the select element that should receive the visibility options
   */
  static void addVisibilityOptions(HTMLNode selectNode) {
    for (PeerVisibility visibility : PeerVisibility.values()) {
      selectNode.addChild(
          "option", ATTR_VALUE, visibility.name(), l10n("peerVisibility." + visibility.name()));
    }
  }

  /**
   * Builds the trust radio-group fragment used by the add-peer form.
   *
   * @return detached node containing the localized trust title, introduction, and radio inputs
   */
  private static HTMLNode createTrustInputs() {
    HTMLNode node = new HTMLNode("div");
    node.addChild("b", l10n("peerTrustTitle"));
    node.addChild("#", " ");
    node.addChild("#", l10n("peerTrustIntroduction"));
    forEachTrustInDisplayOrder(
        trust -> {
          HTMLNode input =
              node.addChild("br")
                  .addChild(
                      "input",
                      new String[] {"type", "name", ATTR_VALUE, "id"},
                      new String[] {"radio", TRUST, trust.name(), TRUST + trust.name()});
          if (trust == PeerTrust.NORMAL) {
            input.addAttribute(ATTR_CHECKED, ATTR_CHECKED);
          }
          input
              .addChild("label", new String[] {"for"}, new String[] {TRUST + trust.name()})
              .addChild("b", l10n("peerTrust." + trust.name()));
          input.addChild("#", ": ");
          input.addChild("#", l10n("peerTrustExplain." + trust.name()));
        });
    node.addChild("br");
    return node;
  }

  /**
   * Builds the visibility radio-group fragment used by the add-peer form.
   *
   * @return detached node containing the localized visibility title, introduction, and radio inputs
   */
  private static HTMLNode createVisibilityInputs() {
    HTMLNode node = new HTMLNode("div");
    node.addChild("b", l10n("peerVisibilityTitle"));
    node.addChild("#", " ");
    node.addChild("#", l10n("peerVisibilityIntroduction"));
    for (PeerVisibility visibility : PeerVisibility.values()) {
      HTMLNode input =
          node.addChild("br")
              .addChild(
                  "input",
                  new String[] {"type", "name", ATTR_VALUE, "id"},
                  new String[] {
                    "radio", VISIBILITY, visibility.name(), VISIBILITY + visibility.name()
                  });
      if (visibility == PeerVisibility.YES) {
        input.addAttribute(ATTR_CHECKED, ATTR_CHECKED);
      }
      input
          .addChild("label", new String[] {"for"}, new String[] {VISIBILITY + visibility.name()})
          .addChild("b", l10n("peerVisibility." + visibility.name()));
      input.addChild("#", ": ");
      input.addChild("#", l10n("peerVisibilityExplain." + visibility.name()));
    }
    node.addChild("br");
    return node;
  }

  /**
   * Visits trust values in the order expected by the legacy UI.
   *
   * @param consumer callback invoked once per trust value, the highest trust first
   */
  private static void forEachTrustInDisplayOrder(Consumer<PeerTrust> consumer) {
    PeerTrust[] trusts = PeerTrust.values();
    for (int index = trusts.length - 1; index >= 0; index--) {
      consumer.accept(trusts[index]);
    }
  }

  /**
   * Resolves the localized string for a Darknet connections form key.
   *
   * @param key suffix beneath the {@code DarknetConnectionsToadlet} localization namespace
   * @return localized text for the supplied form key
   */
  private static String l10n(String key) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + key);
  }
}
