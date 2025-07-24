package network.crypta.support.io;

import network.crypta.support.api.Bucket;

// A Bucket which does not support being stored to the database. E.g. SegmentedBCB.
public interface NotPersistentBucket extends Bucket {

	// No methods
	
}
