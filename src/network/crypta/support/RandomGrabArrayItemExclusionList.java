/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.support;

import network.crypta.client.async.ClientContext;

public interface RandomGrabArrayItemExclusionList {
	
	/**
	 * Whether this item can be returned right now.
	 */
    long exclude(RandomGrabArrayItem item, ClientContext context, long now);

}
