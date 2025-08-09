package network.crypta.io.comm;

/**
 * Interface for something which counts bytes.
 */
public interface ByteCounter {
	
	/** Sent some bytes. *Includes* any bytes flagged as already-reported-to-throttle. */
    void sentBytes(int x);
	
	void receivedBytes(int x);
	
	/**
	 * Sent payload - only include the number of bytes of actual payload i.e. data from 
	 * the user's point of view, as opposed to overhead.
	 *  
	 * IMPORTANT: This will also be reported to sentBytes()! DO NOT ADD the total from sentBytes() 
	 * to the total from sentPayloadBytes(), or you will double-count.
	 *
	 * @param x Number of bytes sent
	 */
    void sentPayload(int x);

}
