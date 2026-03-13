/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Ed2Handler.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

/**
 * Streaming calculator for the eD2k-style hash chain used in Bitzi-style workflows.
 *
 * <p>The handler partitions an incoming byte stream into fixed-size segments of {@link #EDSEG_SIZE}
 * bytes (9,728,000 bytes). Each segment is hashed with {@link Md4Handler}; the resulting
 * per-segment digests are then fed to a second {@code Md4Handler} that yields the final aggregate
 * digest. This pattern matches the eDonkey/eMule verification model where chunks are validated
 * independently and again in aggregate.
 *
 * <p>Usage is straightforward: call {@link #analyzeInit()}, feed data through {@link
 * #analyzeUpdate(byte[], int, int)} in any chunking pattern, then finish with {@link
 * #analyzeFinal()}. Instances are mutable and not thread-safe; restrict each instance to a single
 * thread or synchronize externally when sharing.
 *
 * <ul>
 *   <li>Maintains both per-segment and top-level {@code Md4Handler} instances.
 *   <li>Ignores zero-length updates to avoid accidental counter drift.
 *   <li>Processes input that crosses segment boundaries in one call.
 * </ul>
 *
 * @see Md4Handler
 */
public class Ed2Handler {

  private static final int EDSEG_SIZE = 1024 * 9500;

  private Md4Handler seg; // the current 9,216,000 byte block
  private Md4Handler top; // the total file value
  private long nextPos;

  /**
   * Creates a new handler instance without initializing internal hash state.
   *
   * <p>Construction is deliberately lightweight; the segment and top-level {@link Md4Handler}
   * instances are allocated during {@link #analyzeInit()} so callers can create objects early and
   * initialize them only when a stream is ready to process. This constructor performs no I/O, does
   * not allocate large buffers, and is safe to invoke repeatedly when preparing pools of hashers
   * for concurrent workflows.
   */
  public Ed2Handler() {
    // Constructor intentionally no-op; state is allocated lazily in analyzeInit() so callers can
    // create instances early and initialize only when they are ready to stream data.
  }

  /**
   * Resets the handler, preparing to consume a fresh byte stream.
   *
   * <p>This initializes both internal {@link Md4Handler} instances and clears the byte position
   * counter so that subsequent calls to {@link #analyzeUpdate(byte[], int, int)} process input as
   * if no previous data had been seen. Invoke this before starting a new file or when reusing an
   * instance to avoid mixing state between different hash computations.
   */
  public void analyzeInit() {

    nextPos = 0;

    seg = new Md4Handler();
    seg.analyzeInit();

    top = new Md4Handler();
    top.analyzeInit();
  }

  /**
   * Updates the current segment hash with the provided bytes starting at offset zero.
   *
   * <p>This is a convenience overload that forwards to {@link #analyzeUpdate(byte[], int, int)}
   * with an offset of {@code 0}. The method treats a zero-length input as a no-op. When the call
   * causes a segment boundary to be crossed, the method finalizes the current segment, feeds its
   * digest into the top-level hash, and continues with the remaining data.
   *
   * @param input byte array containing the data to hash; must not be {@code null} and may be empty
   * @param inputLen number of bytes from the start of {@code input} to consume for hashing
   */
  public void analyzeUpdate(byte[] input, int inputLen) {

    analyzeUpdate(input, 0, inputLen);
  }

  /**
   * Streams a portion of the supplied buffer into the segment-oriented hash chain.
   *
   * <p>Bytes from {@code input} beginning at {@code ofs} are incorporated until {@code inputLen}
   * bytes have been consumed. If the update stays within the current segment, only the segment hash
   * is advanced. When the update reaches a segment boundary, the segment hash is finalized, its
   * digest fed to the top-level hash, and processing continues with any remaining bytes in the same
   * call. A zero-length update performs no work and leaves internal counters unchanged.
   *
   * @param input source buffer containing raw file data; must not be {@code null} and is read-only
   * @param ofs zero-based offset within {@code input} where hashing begins; must satisfy bounds
   * @param inputLen number of bytes to process starting at {@code ofs}; may be zero to signal noop
   */
  public void analyzeUpdate(byte[] input, int ofs, int inputLen) {

    // first, do no harm
    if (0 == inputLen) return;

    // now, close up any segment that's been completed
    if ((0 < nextPos) && (0 == (nextPos % EDSEG_SIZE))) {
      // finish
      byte[] innerDigest = seg.analyzeFinal();
      // feed it to the overall hash
      top.analyzeUpdate(innerDigest, 16);
      // reset the current segment
      seg.analyzeInit();
    }

    // now, handle the new data
    if ((nextPos / EDSEG_SIZE) == (nextPos + inputLen) / EDSEG_SIZE) {
      // not finishing any segments, just keep feeding segment hash
      seg.analyzeUpdate(input, ofs, inputLen);
      nextPos += inputLen;
      return;
    }
    // OK, we're reaching or crossing a segment-end

    // finish the current segment
    int firstLen = EDSEG_SIZE - (int) (nextPos % EDSEG_SIZE);
    seg.analyzeUpdate(input, ofs, firstLen);
    nextPos += firstLen;

    // continue with passed-in info
    analyzeUpdate(input, ofs + firstLen, inputLen - firstLen);
  }

  /**
   * Finalizes the hash computation and returns the resulting digest.
   *
   * <p>If only a single segment of data was processed, this method returns the segment's MD4 digest
   * directly. For multi-segment streams, it finalizes the current segment, feeds that digest into
   * the top-level hash, and returns the MD4 digest of all segment digests. Calling this method
   * multiple times without reinitializing will recompute based on the same buffered state.
   *
   * @return a 16-byte MD4 digest representing either the sole segment or the aggregate of segments
   */
  public byte[] analyzeFinal() {

    if (nextPos <= EDSEG_SIZE) {
      // there was only one segment; return its hash
      return seg.analyzeFinal();
    }

    // finish the segment in process
    byte[] innerDigest = seg.analyzeFinal();
    // feed it to the overall hash
    top.analyzeUpdate(innerDigest, 16);

    return top.analyzeFinal();
  }
}
