/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Md4Handler.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;

/**
 * Incremental MD4 message-digest calculator used by collider utilities.
 *
 * <p>This handler exposes a minimal streaming-style API that mirrors classic digest interfaces:
 * call {@link #analyzeInit()} to reset the state, feed arbitrary-sized byte chunks through one of
 * the {@code analyzeUpdate} overloads, and finish with {@link #analyzeFinal()} to obtain the
 * 16-byte digest. Internally it maintains the four-word MD4 state, a byte buffer for partial
 * blocks, and a 64-bit bit-count tracker, all stored in reusable arrays to avoid allocations during
 * normal operation. The implementation intentionally follows the original specification rather than
 * relying on {@code java.security.MessageDigest}, keeping behavior predictable across runtime
 * environments.
 *
 * <p>Instances are mutable and <strong>not</strong> thread-safe; callers must serialize access or
 * create separate handlers per thread. Typical lifecycle is short-lived: construct, initialize,
 * stream data, finalize, then discard or reuse after another {@link #analyzeInit()} call. Because
 * padding and length encoding are applied only in {@link #analyzeFinal()}, callers should avoid
 * reusing the same instance without reinitializing. Performance is optimized for correctness and
 * simplicity over vectorized speedups.
 *
 * <ul>
 *   <li>Maintains internal little-endian transforms for MD4 processing.
 *   <li>Supports arbitrary input lengths; buffering handles non-aligned tails.
 *   <li>Returns digests in standard 16-byte little-endian word order.
 * </ul>
 *
 * @see java.security.MessageDigest
 */
public class Md4Handler {

  // Constants for MD4Transform routine.
  private static final int S11 = 3;
  private static final int S12 = 7;
  private static final int S13 = 11;
  private static final int S14 = 19;
  private static final int S21 = 3;
  private static final int S22 = 5;
  private static final int S23 = 9;
  private static final int S24 = 13;
  private static final int S31 = 3;
  private static final int S32 = 9;
  private static final int S33 = 11;
  private static final int S34 = 15;
  private static final int BLOCK_LENGTH = 64;

  private static final byte P0 = -128; // 0x80

  private static final byte[] PADDING = {
    P0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };

  private int[] state; /* state (ABCD) */
  private int[] count; /* number of bits, modulo 2^64 (lsb first) */
  private byte[] buffer;

  private static int f(int x, int y, int z) {
    return (((x) & (y)) | ((~x) & (z)));
  }

  private static int g(int x, int y, int z) {
    return (((x) & (y)) | ((x) & (z)) | ((y) & (z)));
  }

  private static int h(int x, int y, int z) {
    return ((x) ^ (y) ^ (z));
  }

  private static int rotateLeft(int x, int n) {
    return (((x) << (n)) | ((x) >>> (32 - (n))));
  }

  private static int ff(int a, int b, int c, int d, int x, int s) {
    a += f(b, c, d) + x;
    return rotateLeft(a, s);
  }

  private static int gg(int a, int b, int c, int d, int x, int s) {
    a += g(b, c, d) + x + 0x5a827999;
    return rotateLeft(a, s);
  }

  private static int hh(int a, int b, int c, int d, int x, int s) {
    a += h(b, c, d) + x + 0x6ed9eba1;
    return rotateLeft(a, s);
  }

  /**
   * Creates a new handler with uninitialized digest state arrays.
   *
   * <p>The constructor allocates the internal buffers but leaves the MD4 state in an undefined
   * configuration until {@link #analyzeInit()} is invoked. Constructing a handler is inexpensive
   * and side effect free; callers may cache a single instance and reuse it across multiple digest
   * runs as long as each run starts with a fresh initialization step. No external resources or
   * platform facilities are consulted during construction, so creation is deterministic and
   * suitable for use in tests or deterministic pipelines.
   */
  public Md4Handler() {
    // Constructor intentionally empty; state is allocated here but seeded later in analyzeInit() to
    // allow reuse between digests without reallocation.
  }

  /* Encodes input (int[]) into output (byte[]).
   * Assumes len is a multiple of 4. */
  private static void encode(byte[] output, int[] input, int len) {

    ByteBuffer buf = ByteBuffer.allocate(len);
    buf.order(ByteOrder.LITTLE_ENDIAN);
    IntBuffer intBuf = buf.asIntBuffer();
    intBuf.put(input, 0, len / 4);
    buf.get(output, 0, len);
  }

  /* Decodes input (unsigned char) into output (w32).
   * Assumes len is a multiple of 4. */
  private static void decode(int[] output, byte[] input, int ofs) {

    ByteBuffer buf = ByteBuffer.wrap(input, ofs, BLOCK_LENGTH);
    buf.order(ByteOrder.LITTLE_ENDIAN);
    IntBuffer intBuf = buf.asIntBuffer();
    intBuf.get(output, 0, BLOCK_LENGTH / 4);
  }

  private static void md4Transform(int[] state, byte[] block, int ofs) {

    int a = state[0];
    int b = state[1];
    int c = state[2];
    int d = state[3];
    int[] x = new int[16];

    decode(x, block, ofs);

    /* Round 1 */
    a = ff(a, b, c, d, x[0], S11); /* 1 */
    d = ff(d, a, b, c, x[1], S12); /* 2 */
    c = ff(c, d, a, b, x[2], S13); /* 3 */
    b = ff(b, c, d, a, x[3], S14); /* 4 */
    a = ff(a, b, c, d, x[4], S11); /* 5 */
    d = ff(d, a, b, c, x[5], S12); /* 6 */
    c = ff(c, d, a, b, x[6], S13); /* 7 */
    b = ff(b, c, d, a, x[7], S14); /* 8 */
    a = ff(a, b, c, d, x[8], S11); /* 9 */
    d = ff(d, a, b, c, x[9], S12); /* 10 */
    c = ff(c, d, a, b, x[10], S13); /* 11 */
    b = ff(b, c, d, a, x[11], S14); /* 12 */
    a = ff(a, b, c, d, x[12], S11); /* 13 */
    d = ff(d, a, b, c, x[13], S12); /* 14 */
    c = ff(c, d, a, b, x[14], S13); /* 15 */
    b = ff(b, c, d, a, x[15], S14); /* 16 */

    /* Round 2 */
    a = gg(a, b, c, d, x[0], S21); /* 17 */
    d = gg(d, a, b, c, x[4], S22); /* 18 */
    c = gg(c, d, a, b, x[8], S23); /* 19 */
    b = gg(b, c, d, a, x[12], S24); /* 20 */
    a = gg(a, b, c, d, x[1], S21); /* 21 */
    d = gg(d, a, b, c, x[5], S22); /* 22 */
    c = gg(c, d, a, b, x[9], S23); /* 23 */
    b = gg(b, c, d, a, x[13], S24); /* 24 */
    a = gg(a, b, c, d, x[2], S21); /* 25 */
    d = gg(d, a, b, c, x[6], S22); /* 26 */
    c = gg(c, d, a, b, x[10], S23); /* 27 */
    b = gg(b, c, d, a, x[14], S24); /* 28 */
    a = gg(a, b, c, d, x[3], S21); /* 29 */
    d = gg(d, a, b, c, x[7], S22); /* 30 */
    c = gg(c, d, a, b, x[11], S23); /* 31 */
    b = gg(b, c, d, a, x[15], S24); /* 32 */

    /* Round 3 */
    a = hh(a, b, c, d, x[0], S31); /* 33 */
    d = hh(d, a, b, c, x[8], S32); /* 34 */
    c = hh(c, d, a, b, x[4], S33); /* 35 */
    b = hh(b, c, d, a, x[12], S34); /* 36 */
    a = hh(a, b, c, d, x[2], S31); /* 37 */
    d = hh(d, a, b, c, x[10], S32); /* 38 */
    c = hh(c, d, a, b, x[6], S33); /* 39 */
    b = hh(b, c, d, a, x[14], S34); /* 40 */
    a = hh(a, b, c, d, x[1], S31); /* 41 */
    d = hh(d, a, b, c, x[9], S32); /* 42 */
    c = hh(c, d, a, b, x[5], S33); /* 43 */
    b = hh(b, c, d, a, x[13], S34); /* 44 */
    a = hh(a, b, c, d, x[3], S31); /* 45 */
    d = hh(d, a, b, c, x[11], S32); /* 46 */
    c = hh(c, d, a, b, x[7], S33); /* 47 */
    b = hh(b, c, d, a, x[15], S34); /* 48 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
  }

  /**
   * Initializes the MD4 state for a new digest computation.
   *
   * <p>This method resets the bit counters, primes the four-word state with the MD4 initial
   * constants, and clears the working buffer. It must be called before supplying any input via the
   * {@code analyzeUpdate} overloads; reusing an instance across multiple digests requires invoking
   * this method between runs. The operation is idempotent with respect to newly created instances
   * and performs no I/O. Thread safety is the caller's responsibility.
   */
  public void analyzeInit() {

    count = new int[] {0, 0};
    state = new int[] {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    buffer = new byte[64];
  }

  /**
   * Updates the digest with a contiguous range of bytes starting at offset zero.
   *
   * <p>This convenience overload delegates to {@link #analyzeUpdate(byte[], int, int)} using a zero
   * offset. Callers should ensure that {@code inputLen} does not exceed the available bytes in
   * {@code input}. The method preserves the existing state prepared by {@link #analyzeInit()} and
   * may be called repeatedly to stream large inputs in manageable chunks.
   *
   * @param input input buffer supplying first bytes to digest; must be non-null.
   * @param inputLen number of bytes from start to process; must fit the buffer.
   */
  public void analyzeUpdate(byte[] input, int inputLen) {

    analyzeUpdate(input, 0, inputLen);
  }

  /**
   * Streams a slice of input bytes into the ongoing MD4 computation.
   *
   * <p>The method updates the internal bit-count tracker, absorbs complete 64-byte blocks through
   * the MD4 transform, and retains any remaining tail bytes in the working buffer for the next
   * call. Offsets and lengths are interpreted exactly as provided; the caller is responsible for
   * ensuring bounds safety on {@code input}. Because state is mutated in place, concurrent calls on
   * the same instance are unsupported. Invoking this method without first calling {@link
   * #analyzeInit()} leaves the digest state undefined.
   *
   * @param input source buffer containing bytes to digest; must be non-null.
   * @param ofs zero-based offset where processing begins within the input array.
   * @param inputLen number of bytes to process starting at {@code ofs}; ensure bounds.
   */
  public void analyzeUpdate(byte[] input, int ofs, int inputLen) {

    /* Compute number of bytes mod 64 */
    int i;
    int index = ((count[0] >> 3) & 0x3F);
    /* Update number of bits */
    count[0] += inputLen << 3;
    if (count[0] < (inputLen << 3)) {
      count[1]++;
    }
    count[1] += (inputLen >> 29);

    int partLen = 64 - index;

    /* Transform as many times as possible.*/
    if (partLen <= inputLen) {
      System.arraycopy(input, ofs, buffer, index, partLen);
      md4Transform(state, buffer, 0);

      for (i = partLen; i + 63 < inputLen; i += 64) {
        md4Transform(state, input, i + ofs);
      }

      index = 0;
    } else {
      i = 0;
    }

    /* Buffer remaining input */
    System.arraycopy(input, i + ofs, buffer, index, inputLen - i);
  }

  /**
   * Completes the digest computation and returns the 16-byte MD4 hash.
   *
   * <p>The method applies MD4 padding, appends the total message length in bits, and processes any
   * remaining buffered data before serializing the state words into the output array. After
   * completion the internal state reflects the finalized digest; callers should invoke {@link
   * #analyzeInit()} before reusing the instance for a new message. The returned array is a fresh
   * copy owned by the caller and can be modified without affecting handler state.
   *
   * @return newly allocated 16-byte array containing the MD4 digest in little-endian word order.
   */
  public byte[] analyzeFinal() {

    byte[] bits = new byte[8];

    /* Save number of bits */
    encode(bits, count, 8);

    /* Pad out to 56 mod 64. */
    int index = ((count[0] >> 3) & 0x3f);
    int padLen = (index < 56) ? (56 - index) : (120 - index);
    analyzeUpdate(PADDING, padLen);

    /* Append length (before padding) */
    analyzeUpdate(bits, 8);
    /* Store state in digest */
    byte[] digest = new byte[16];
    encode(digest, state, 16);

    return digest;
  }
}
