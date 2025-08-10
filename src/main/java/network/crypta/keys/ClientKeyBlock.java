package network.crypta.keys;

import java.io.IOException;

import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;

/** A KeyBlock with a ClientKey. Can be decoded. Not a child of KeyBlock because of issues with equals().
 */
public interface ClientKeyBlock {

	/** Decode with the key
	 * @param factory The BucketFactory to use to create the Bucket to return the data in.
	 * @param maxLength The maximum size of the returned data in bytes.
	 */
	Bucket decode(BucketFactory factory, int maxLength, boolean dontDecompress) throws KeyDecodeException, IOException;

	/** Does the block contain metadata? If not, it contains real data. */
	boolean isMetadata();

    /** @return The ClientKey for this key. */
    ClientKey getClientKey();
    
    byte[] memoryDecode() throws KeyDecodeException;
    
    /** @return The underlying KeyBlock. */
    KeyBlock getBlock();

    /** @return The low-level Key for the block. */
	Key getKey();
	
	/** This is why ClientKeyBlock isn't instanceof KeyBlock: Two ClientKeyBlock's with the same content
	 * but different keys are not equals(), therefore a ClientKeyBlock and its KeyBlock have to be !equals
	 * too. Hence it's really a different kind of object, so not a child. */
	@Override
    boolean equals(Object o);
	
	/** Please be consistent with equals() */
	@Override
    int hashCode();

}
