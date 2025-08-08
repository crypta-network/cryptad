package network.crypta.node.useralerts;

import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.support.HTMLNode;

/**
 * Abstract base implementation of a {@link UserAlert}.
 * 
 * @author David &lsquo;Bombe&rsquo; Roden &lt;bombe@freenetproject.org&gt;
 * @version $Id$
 */
public abstract class AbstractUserAlert implements UserAlert {

	private final boolean userCanDismiss;
	private final String title;
	private final String text;
	private final String shortText;
	private final HTMLNode htmlText;
	private final short priorityClass;
	protected boolean valid;
	private final String dismissButtonText;
	private final boolean shouldUnregisterOnDismiss;
	private final Object userIdentifier;
	private final long creationTime;

	protected AbstractUserAlert() {
		this.userCanDismiss = false;
		this.title = null;
		this.text = null;
		this.htmlText = null;
		this.priorityClass = 0;
		this.valid = true;
		this.dismissButtonText = null;
		this.shouldUnregisterOnDismiss = false;
		this.userIdentifier = null;
		this.shortText = null;
		creationTime = System.currentTimeMillis();
	}

	protected AbstractUserAlert(boolean userCanDismiss, String title, String text, String shortText, HTMLNode htmlText, short priorityClass, boolean valid, String dismissButtonText, boolean shouldUnregisterOnDismiss, Object userIdentifier) {
		this.userCanDismiss = userCanDismiss;
		this.title = title;
		this.text = text;
		this.shortText = shortText;
		this.htmlText = htmlText;
		this.priorityClass = priorityClass;
		this.valid = valid;
		this.dismissButtonText = dismissButtonText;
		this.shouldUnregisterOnDismiss = shouldUnregisterOnDismiss;
		this.userIdentifier = userIdentifier;
		creationTime = System.currentTimeMillis();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean userCanDismiss() {
		return userCanDismiss;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getTitle() {
		return title;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getText() {
		return text;
	}
	
	@Override
	public String getShortText() {
		return shortText;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public HTMLNode getHTMLText() {
		return htmlText;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public short getPriorityClass() {
		return priorityClass;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isValid() {
		return valid;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void isValid(boolean valid) {
		if (userCanDismiss()) {
			this.valid = valid;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String dismissButtonText() {
		return dismissButtonText;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean shouldUnregisterOnDismiss() {
		return shouldUnregisterOnDismiss;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onDismiss() {
	}

	@Override
	public String anchor() {
		return Integer.toString(hashCode());
	}

	@Override
	public boolean isEventNotification() {
		return false;
	}

	public boolean isEvent() {
		return false;
	}

	@Override
	public long getUpdatedTime() {
		return creationTime;
	}

	@Override
	public FCPMessage getFCPMessage() {
		return new FeedMessage(getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
	}

}
