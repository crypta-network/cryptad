/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.client.async;

import network.crypta.client.Metadata;

public interface SnoopMetadata {

	/** Spy on the metadata as a file is being fetched. Return true to cancel the request. */
    boolean snoopMetadata(Metadata meta, ClientContext context);
	
}
