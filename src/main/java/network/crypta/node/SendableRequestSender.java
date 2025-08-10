package network.crypta.node;

import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ClientContext;

/**
 * Interface for class responsible for doing the actual sending of requests.
 * Strictly non-persistent.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public interface SendableRequestSender {
	
	/** ONLY called by RequestStarter. Start the actual request using the NodeClientCore
	 * provided, and the key and key number earlier got from chooseKey(). Either use the 
	 * callbacks on the ChosenBlock, which will remove the key from KeysFetchingLocally, or
	 * do it directly (in obscure cases such as OfferedKeysList).
	 * @param sched The scheduler this request has just been grabbed from.
	 * @param request The ChosenBlock containing the key, the SendableRequestItem,
	 * and the methods to call to indicate success/failure.
	 * @return True if a request was sent, false otherwise (in which case the request will
	 * be removed if it hasn't already been). */
    boolean send(NodeClientCore node, RequestScheduler sched, ClientContext context, ChosenBlock request);

	boolean sendIsBlocking();
	
}
