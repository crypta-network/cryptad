package network.crypta.client.async;

import network.crypta.node.RequestClient;

import java.io.Serial;
import java.io.Serializable;

/** Base class for inserts, including site inserts, at the level of a ClientRequester.
 * 
 * WARNING: Changing non-transient members on classes that are Serializable can result in 
 * restarting downloads or losing uploads.
 */
public abstract class BaseClientPutter extends ClientRequester {

	@Serial private static final long serialVersionUID = 1L;

	/** Required because {@link Serializable} is implemented by the parent class. */
	protected BaseClientPutter() {
	}

	protected BaseClientPutter(short priorityClass, RequestClient requestClient) {
		super(priorityClass, requestClient);
	}

	public void dump() {
		// Do nothing
	}

	public abstract void onTransition(ClientPutState from, ClientPutState to, ClientContext context);

	public abstract int getMinSuccessFetchBlocks();
}
