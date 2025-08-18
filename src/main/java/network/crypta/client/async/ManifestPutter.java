package network.crypta.client.async;

import network.crypta.node.RequestClient;

import java.io.Serial;
import java.io.Serializable;

import network.crypta.client.InsertException;

public abstract class ManifestPutter extends BaseClientPutter {

	@Serial private static final long serialVersionUID = 1L;

	/** Required because {@link Serializable} is implemented by a parent class. */
	protected ManifestPutter() {
	}

	protected ManifestPutter(short priorityClass, RequestClient requestClient) {
		super(priorityClass, requestClient);
	}

	public abstract int countFiles();
	public abstract long totalSize();
	public abstract void start(ClientContext context) throws InsertException;
	
	public byte[] getSplitfileCryptoKey() {
		return null;
	}
	
}
