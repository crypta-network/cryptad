package network.crypta.clients.http.complexhtmlnodes;

import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;

public class PeerTrustInputForAddPeerBoxNode extends HTMLNode {

    public PeerTrustInputForAddPeerBoxNode() {
        super("div");

        this.addChild("b", l10n("DarknetConnectionsToadlet.peerTrustTitle"));
        this.addChild("#", " ");
        this.addChild("#", l10n("DarknetConnectionsToadlet.peerTrustIntroduction"));
        for (DarknetPeerNode.FRIEND_TRUST trust : DarknetPeerNode.FRIEND_TRUST.valuesBackwards()) { // FIXME reverse order
            HTMLNode input = this.addChild("br")
                    .addChild("input",
                            new String[] { "type", "name", "value", "id" },
                            new String[] { "radio", "trust", trust.name(), "trust" + trust.name() });
            if (trust.isDefaultValue())
                input.addAttribute("checked", "checked");
            input.addChild("label",
                new String[] { "for" },
                new String[] { "trust" + trust.name() }
                ).addChild("b", l10n("DarknetConnectionsToadlet.peerTrust." + trust.name()));
            input.addChild("#", ": ");
            input.addChild("#", l10n("DarknetConnectionsToadlet.peerTrustExplain." + trust.name()));
        }
        this.addChild("br");
    }

    private String l10n(String key) {
        return NodeL10n.getBase().getString(key);
    }
}
