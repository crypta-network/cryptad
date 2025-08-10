package network.crypta.client.async;

import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

public interface DownloadCache {
	
	CacheFetchResult lookupInstant(FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred);
	
	CacheFetchResult lookup(FreenetURI key, boolean noFilter, ClientContext context,
                            boolean mustCopy, Bucket preferred);

}
