package network.crypta.crypt;

import java.security.MessageDigest;
import org.bitpedia.collider.core.Ed2Handler;

/**
 * MessageDigest implementation for the eDonkey2000 (ED2K) hash.
 *
 * <p>This digest computes the ED2K value as defined by the historical eDonkey2000 protocol: split
 * the input into segments of 9,500 KiB (9,728,000 bytes), compute the MD4 of each segment, then
 * compute the MD4 of the concatenation of the segment digests. When the input fits within a single
 * segment, the ED2K hash is simply the MD4 of the entire input. The underlying logic is delegated
 * to {@link Ed2Handler}.
 *
 * <p>The algorithm name reported by this instance is {@code "ED2K"}. The digest length is 16 bytes.
 * Instances are not thread-safe.
 *
 * @author infinity0
 * @author toad
 */
@SuppressWarnings("java:S2257")
public class Ed2MessageDigest extends MessageDigest {

  /**
   * Underlying handler that maintains the ED2K hashing state and performs MD4 computations on
   * segments and on the top-level aggregate.
   */
  protected final Ed2Handler handler;

  /**
   * Creates a new ED2K message digest and initializes its internal state.
   *
   * <p>The superclass is constructed with the algorithm name {@code "ED2K"} and the internal {@link
   * Ed2Handler} is placed into its initial state.
   */
  public Ed2MessageDigest() {
    super("ED2K");
    handler = new Ed2Handler();
    handler.analyzeInit();
  }

  /**
   * Finishes the computation and returns the 16-byte ED2K digest.
   *
   * <p>This method delegates to {@link Ed2Handler#analyzeFinal()} and returns its result. Call
   * {@link #engineReset()} (or {@link #reset()}) before reusing the instance for a new computation.
   *
   * @return the ED2K digest, exactly 16 bytes long
   */
  @Override
  protected byte[] engineDigest() {
    return handler.analyzeFinal();
  }

  /** Resets the digest to its initial state, discarding any accumulated input. */
  @Override
  protected void engineReset() {
    handler.analyzeInit();
  }

  /**
   * Updates the digest with a single byte.
   *
   * <p>This is a convenience that forwards to {@link #engineUpdate(byte[], int, int)} with a
   * one-byte array.
   *
   * @param arg0 the byte to add to the digest
   */
  @Override
  protected void engineUpdate(byte arg0) {
    engineUpdate(new byte[] {arg0}, 0, 1);
  }

  /**
   * Updates the digest with a subrange of the given array.
   *
   * <p>The array contents are not retained after this call. Bounds checking follows the behavior of
   * {@link MessageDigest#update(byte[], int, int)}; invalid parameters will result in a runtime
   * exception.
   *
   * @param arg0 the source array
   * @param arg1 the offset within {@code arg0}
   * @param arg2 the number of bytes to read from {@code arg0}
   */
  @Override
  protected void engineUpdate(byte[] arg0, int arg1, int arg2) {
    handler.analyzeUpdate(arg0, arg1, arg2);
  }

  /**
   * Returns the length of the ED2K digest in bytes.
   *
   * @return always {@code 16}
   */
  @Override
  protected int engineGetDigestLength() {
    return 16;
  }
}
