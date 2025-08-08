package network.crypta.node.useralerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.NativeThread;

/**
 * Tell the user about the lack of room nice-level wise
 * 
 * @see{freenet/support/io/NativeThread.java}
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class NotEnoughNiceLevelsUserAlert extends AbstractUserAlert {
	public NotEnoughNiceLevelsUserAlert() {
		super(true, null, null, null, null, UserAlert.WARNING, true, NodeL10n.getBase().getString("UserAlert.hide"), true, null);
	}
	
	@Override
	public String getTitle() {
		return NodeL10n.getBase().getString("NotEnoughNiceLevelsUserAlert.title");
	}
	
	@Override
	public String getText() {
		return NodeL10n.getBase().getString("NotEnoughNiceLevelsUserAlert.content",
			new String[] { "available", "required" },
			new String[] { 
				String.valueOf(NativeThread.NATIVE_PRIORITY_RANGE),
				String.valueOf(NativeThread.ENOUGH_NICE_LEVELS) 
			});
	}
	
	@Override
	public String getShortText() {
		return NodeL10n.getBase().getString("NotEnoughNiceLevelsUserAlert.short");
	}

	@Override
	public HTMLNode getHTMLText() {
		return new HTMLNode("div", getText());
	}

}
