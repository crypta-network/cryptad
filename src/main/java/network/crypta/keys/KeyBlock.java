package network.crypta.keys;

import network.crypta.store.StorableBlock;

/**
 * Interface for fetched blocks. Can be decoded by using a ClientKey to 
 * construct a ClientKeyBlock, which can then be decoded to a Bucket.
 */
public interface KeyBlock extends StorableBlock {

    int HASH_SHA256 = 1;
	
    Key getKey();
    byte[] getRawHeaders();
    byte[] getRawData();
	byte[] getPubkeyBytes();

}
