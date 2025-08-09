package network.crypta.node.useralerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;

public class SimpleUserAlert extends AbstractUserAlert {

	public SimpleUserAlert(boolean canDismiss, String title, String text, String shortText, short type) {
		this(canDismiss, title, text, shortText, type, null);
	}
	
	public SimpleUserAlert(boolean canDismiss, String title, String text, String shortText, short type, Object userIdentifier) {
		super(canDismiss, title, text, shortText, new HTMLNode("div", text), type, true, NodeL10n.getBase().getString("UserAlert.hide"), true, userIdentifier);
	}

	@Override
	public void isValid(boolean validity) {
		// Do nothing
	}

}
