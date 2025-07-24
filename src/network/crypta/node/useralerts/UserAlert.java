/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.node.useralerts;

import network.crypta.clients.fcp.FCPMessage;
import network.crypta.support.HTMLNode;

public interface UserAlert {
	
	/**
	 * Can the user dismiss the alert?
	 * If not, it persists until it is unregistered.
	 */
    boolean userCanDismiss();
	
	/**
	 * Title of alert (must be short!).
	 */
    String getTitle();
	
	/**
	 * Content of alert (plain text).
	 */
    String getText();

	/**
	 * Content of alert (HTML).
	 */
    HTMLNode getHTMLText();
	
	/**
	 * *Really* concise text of alert. Should be comfortably under a line even when translated
	 * into a verbose language. Will link to the full details.
	 */
    String getShortText();
	
	/**
	 * Priority class
	 */
    short getPriorityClass();
	
	/**
	 * Is the alert valid right now? Suggested use is to synchronize on the
	 * alert, then check this, then get the data.
	 */
    boolean isValid();
	
	void isValid(boolean validity);
	
	String dismissButtonText();
	
	boolean shouldUnregisterOnDismiss();
	
	/**
	 * Method to be called upon alert dismissal
	 */
    void onDismiss();
	
	/**
	 * @return A unique, short name for the alert. Can be simply hashCode(), not visible to the user.
	 * MUST NOT contain spaces or commas.
	 */
    String anchor();

	/**
	 * @return True if this is an event notification. Event notifications can be bulk deleted.
	 * Eventually they will be handled differently - logged to a separate event log, and only
	 * the last few displayed on the homepage.
	 */
    boolean isEventNotification();

	/**
	 * @param The identifier of the subscription
	 * @return A FCPMessage that is sent subscribing FCPClients
	 */
    FCPMessage getFCPMessage();
	
	/**
	 * @return The Unix timestamp of when the alert was last updated
	 */
    long getUpdatedTime();

	/** An error which prevents normal operation */
    short CRITICAL_ERROR = 0;
	/** An error which prevents normal operation but might be temporary */
    short ERROR = 1;
	/** An error; limited anonymity due to not enough connections, for example */
    short WARNING = 2;
	/** Something minor */
    short MINOR = 3;
}
