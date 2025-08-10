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
