package network.crypta.client.async;

import network.crypta.client.Metadata;

public interface SnoopMetadata {

	/** Spy on the metadata as a file is being fetched. Return true to cancel the request. */
    boolean snoopMetadata(Metadata meta, ClientContext context);
	
}
