package network.crypta.client.async;

import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchResult;
import network.crypta.support.api.Bucket;

public class CacheFetchResult extends FetchResult {
	
	public final boolean alreadyFiltered;

	public CacheFetchResult(ClientMetadata dm, Bucket fetched, boolean alreadyFiltered) {
		super(dm, fetched);
		this.alreadyFiltered = alreadyFiltered;
	}

}
