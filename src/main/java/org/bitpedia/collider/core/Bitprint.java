/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Bitprint.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

import java.util.Arrays;
import java.util.logging.Logger;
import org.bitpedia.util.Base32;
import org.bitpedia.util.Sha1;
import org.bitpedia.util.TigerTree;

/**
 * Utility for computing Bitzi “bitprint” identifiers by streaming SHA-1 and Tiger Tree hashes.
 *
 * <p>The class encapsulates the lifecycle needed to derive the combined binary digest used by the
 * Bitzi submission format: call {@link #analyzeInit()} to seed internal hashers, feed data chunks
 * through {@link #analyzeUpdate(byte[], int, int)}, then call {@link #analyzeFinal()} to get the
 * concatenated digest (SHA-1 bytes followed by Tiger Tree bytes). Clients are expected to encode
 * the result with {@link Base32} and split it at {@link #SHA_BASE32SIZE} characters when producing
 * the canonical dotted bitprint string. Instances maintain a mutable state and are not thread-safe.
 *
 * <p>Hashing is strictly forward-only: once {@link #analyzeFinal()} is called, the internal state
 * is consumed and the instance should be discarded or reinitialized before reuse. Built-in
 * self-tests guard against broken hash implementations by comparing outputs to known vectors for
 * empty, one byte, and one-kibibyte inputs.
 *
 * <ul>
 *   <li>Designed for streaming file hashing in {@link Submission} workflows.
 *   <li>Combines two digests so callers need not coordinate separate hashers.
 *   <li>Performs lightweight sanity checks to fail fast on incorrect crypto primitives.
 * </ul>
 *
 * @see Submission
 */
public class Bitprint {

  /* BITPRINT_RAW_LEN defines the length of the bitprint returned by the
  bitziCreateBitprint function. The bitprint argument needs to have
  at least BITPRINT_RAW_LEN bytes available. */
  /**
   * Total number of raw bytes in the combined bitprint digest (SHA-1 bytes followed by Tiger Tree
   * bytes); callers should allocate at least this many bytes when constructing buffers for the
   * binary form or when preparing to base32-encode the result for submission.
   */
  public static final int BITPRINT_RAW_LEN = 44;

  /**
   * Default buffer length, in bytes, for streaming reads when hashing large files; sized to a small
   * power-of-two-like chunk that balances I/O efficiency with minimal memory footprint in the
   * default {@link Submission} hashing loop.
   */
  public static final int BUFFER_LEN = 4096;

  /**
   * Length, in Base32 characters, of the SHA-1 portion of a bitprint; used when splitting the
   * encoded combined digest into {@code <sha1>.<tiger>} form expected by Bitzi consumers.
   */
  public static final int SHA_BASE32SIZE = 32;

  private static final int ONEK_SIZE = 1025;
  private static final String EMPTY_SHA = "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ";
  private static final String ONE_SHA = "GVVBSK3ZCOYEYVCXJUMMFDKG4Y4VIKFL";
  private static final String ONEK_SHA = "CAE54LXWDA55NWGAR4PNRX2II7TR66WL";
  private static final String EMPTY_TIGER = "LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ";
  private static final String ONE_TIGER = "QMLU34VTTAIWJQM5RVN4RIQKRM2JWIFZQFDYY3Y";
  private static final String ONEK_TIGER = "CDYY2OW6F6DTGCH3Q6NMSDLSRV7PNMAL3CED3DA";
  private static final Logger LOGGER = Logger.getLogger(Bitprint.class.getName());

  private Sha1 sha1;
  private TigerTree tt;

  /**
   * Creates a new bitprint calculator with no initialized hash state. Call {@link #analyzeInit()}
   * before supplying data and reuse each instance for one logical hashing session. The constructor
   * performs no allocation beyond the object itself, making it inexpensive to create per file or
   * per stream. Instances are mutable and should not be shared across threads without external
   * synchronization.
   */
  public Bitprint() {
    // Constructor intentionally empties: lifecycle begins when analyzeInit() allocates hash state.
  }

  /* NOTE: This function returns true if it failed the check! */
  private static boolean checkTigertreeHash(String expected, byte[] data, int len) {

    TigerTree tt = new TigerTree();
    tt.update(data, 0, len);
    String ttDigest = Base32.encode(tt.digest());

    return !ttDigest.equals(expected);
  }

  /* NOTE: This function returns true if it failed the check! */
  private static boolean checkSha1Hash(String expected, byte[] data, int len) {

    Sha1 sha = new Sha1();
    sha.engineUpdate(data, 0, len);
    String shaDigest = Base32.encode(sha.digest());

    return !shaDigest.equals(expected);
  }

  /* NOTE: This function returns true if it failed the check! */
  private static boolean hashSanityCheck() {

    byte[] data = new byte[] {'1'};

    if (checkTigertreeHash(EMPTY_TIGER, data, 0)) {
      return true;
    }
    if (checkSha1Hash(EMPTY_SHA, data, 0)) {
      return true;
    }
    if (checkTigertreeHash(ONE_TIGER, data, 1)) {
      return true;
    }
    if (checkSha1Hash(ONE_SHA, data, 1)) {
      return true;
    }

    data = new byte[ONEK_SIZE];
    Arrays.fill(data, (byte) 'a');
    if (checkTigertreeHash(ONEK_TIGER, data, ONEK_SIZE)) {
      return true;
    }
    return checkSha1Hash(ONEK_SHA, data, ONEK_SIZE);
  }

  /**
   * Initializes the internal SHA-1 and Tiger Tree hashers and performs a built-in sanity check
   * using known-good vectors. Must be called exactly once before any {@link #analyzeUpdate(byte[],
   * int, int)} or {@link #analyzeFinal()} invocation on a given instance.
   *
   * @return {@code true} when initialization succeeds and both hashers are ready; {@code false}
   *     when the sanity check fails, indicating corrupted or incompatible hash implementations.
   */
  public boolean analyzeInit() {

    if (hashSanityCheck()) {
      return false;
    }

    tt = new TigerTree();
    sha1 = new Sha1();

    return true;
  }

  /**
   * Streams a segment of data into both hash algorithms. The method may be called repeatedly with
   * sequential chunks and assumes {@link #analyzeInit()} has completed successfully. No internal
   * synchronization is performed, so callers must serialize updates when sharing an instance across
   * threads.
   *
   * @param buf source buffer containing the bytes to hash; must not be {@code null}.
   * @param ofs zero-based start offset within {@code buf} for the data to include in this update.
   * @param bufLen number of bytes from {@code buf} beginning at {@code ofs} to feed into the hash
   *     state; must be non-negative and within the buffer bounds.
   */
  public void analyzeUpdate(byte[] buf, int ofs, int bufLen) {

    tt.update(buf, ofs, bufLen);
    sha1.update(buf, ofs, bufLen);
  }

  /**
   * Finalizes both hashes and returns the combined binary digest. The first portion of the returned
   * array contains the SHA-1 bytes followed immediately by the Tiger Tree bytes, matching {@link
   * #BITPRINT_RAW_LEN}. After this call the internal state is consumed; invoke {@link
   * #analyzeInit()} again before reusing the instance for a new stream.
   *
   * @return newly allocated byte array containing the concatenated SHA-1 and Tiger Tree digests in
   *     that order; callers own the array and may encode or cache it freely.
   */
  public byte[] analyzeFinal() {

    byte[] ttDigest = tt.digest();
    byte[] sha1Digest = sha1.digest();

    byte[] res = new byte[sha1Digest.length + ttDigest.length];
    System.arraycopy(sha1Digest, 0, res, 0, sha1Digest.length);
    System.arraycopy(ttDigest, 0, res, sha1Digest.length, ttDigest.length);
    return res;
  }

  /**
   * Command-line entry point that runs the internal hash sanity check and logs the outcome. This
   * helper is intended for quick verification that the embedded SHA-1 and Tiger Tree
   * implementations produce the expected vectors on the current platform.
   */
  static void main() {

    if (hashSanityCheck()) {
      LOGGER.info("Hash test FAILED");
    } else {
      LOGGER.info("Hash test OK");
    }
  }
}
