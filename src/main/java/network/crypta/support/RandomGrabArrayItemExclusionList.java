package network.crypta.support;

import network.crypta.client.async.ClientContext;

public interface RandomGrabArrayItemExclusionList {
	
	/**
	 * Whether this item can be returned right now.
	 */
    long exclude(RandomGrabArrayItem item, ClientContext context, long now);

}
