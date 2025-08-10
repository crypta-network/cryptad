package network.crypta.support.compress;

import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutState;

public interface CompressJob {
	void tryCompress(ClientContext context) throws InsertException;
	void onFailure(InsertException e, ClientPutState c, ClientContext context);
}
