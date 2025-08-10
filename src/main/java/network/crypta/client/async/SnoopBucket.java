package network.crypta.client.async;

import network.crypta.support.api.Bucket;

public interface SnoopBucket {

	/** Spy on the bucket as a file is being fetched. Return true to cancel the request. */
    boolean snoopBucket(Bucket data, boolean isMetadata, ClientContext context);
	
}
