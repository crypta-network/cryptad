/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.client.async;

import network.crypta.node.RequestClient;
import java.io.Serializable;

public abstract class BaseClientGetter extends ClientRequester implements
		GetCompletionCallback, Serializable {
	
    private static final long serialVersionUID = 1L;

    protected BaseClientGetter(short priorityClass, RequestClient requestClient) {
		super(priorityClass, requestClient);
	}
	
	/** Required because we implement {@link Serializable}. */
	protected BaseClientGetter() {
	}

}
