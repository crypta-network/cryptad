/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.client.async;

import network.crypta.client.FetchException;

/**
 * A ClientGetState.
 * Represents a stage in the fetch process.
 */
public interface ClientGetState {

	/** Schedule the request on the ClientRequestScheduler. */
    void schedule(ClientContext context);

	/** Cancel the request, and call onFailure() on the callback in order to tell 
	 * downstream (ultimately the client) that cancel has succeeded, and to allow
	 * it to call removeFrom() to avoid a database leak. */
    void cancel(ClientContext context);

	/** Get a long value which may be passed around to identify this request (e.g. by the USK fetching code). */
    long getToken();
	
	/** Called on restarting the node for a persistent request. The request must re-schedule 
	 * itself, as neither the KeyListener's nor the RGA's are persistent now. 
	 * @throws FetchException */
    void onResume(ClientContext context) throws FetchException;

	/** Called just before the final write of client.dat before the node shuts down. Should write
	 * any dirty data to disk etc. */
    void onShutdown(ClientContext context);
}
