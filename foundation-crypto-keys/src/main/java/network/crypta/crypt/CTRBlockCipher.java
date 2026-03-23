/**
 * Derived from Bouncy Castle 1.47 {@code SICBlockCipher}. We avoid depending on the JCE provider
 * directly here due to policy-file constraints in some environments. Bouncy Castle is distributed
 * under a permissive (MIT-like) license that is compatible with the GPL.
 */
package network.crypta.crypt;

/**
 * Implements the Segmented Integer Counter (SIC) mode on top of a simple block cipher. This mode is
 * also known as CTR. The keystream is produced by encrypting successive values of a counter; the
 * input is XORed with that keystream to produce the output. Encryption and decryption are identical
 * operations.
 *
 * <p>Instances are stateful and not thread-safe. Use one instance per independent stream and
 * initialize it exactly once per IV.
 */
public class CTRBlockCipher {
  /** Underlying block cipher instance. */
  private final BlockCipher cipher;

  /** Block size in bytes; equals {@code ivBytes.length == counter.length == counterOut.length}. */
  private final int blockSize;

  /** Initialization vector; copied into {@link #counter} during {@link #init(byte[], int, int)}. */
  private final byte[] ivBytes;

  /**
   * Plaintext block counter. After each keystream block is generated, the counter is incremented as
   * an unsigned big-endian integer (carry propagates from the last byte toward index {@code 0}).
   */
  private final byte[] counter;

  /**
   * Keystream block. This is {@code E_K(counter)} and is XORed with the input to produce the
   * output. It is regenerated whenever the current block is fully consumed.
   */
  private final byte[] counterOut;

  /** Offset within the current block. */
  private int blockOffset;

  /**
   * Creates a new CTR adapter for the given block cipher.
   *
   * @param c the block cipher to use. Its reported block size determines the counter/IV length.
   */
  public CTRBlockCipher(BlockCipher c) {
    this.cipher = c;
    this.blockSize = cipher.getBlockSize() / 8;
    this.ivBytes = new byte[blockSize];
    this.counter = new byte[blockSize];
    this.counterOut = new byte[blockSize];
    this.blockOffset = ivBytes.length;
  }

  /**
   * Returns the underlying block cipher.
   *
   * @return the cipher used to generate the CTR keystream
   */
  public BlockCipher getUnderlyingCipher() {
    return cipher;
  }

  /**
   * Initializes the keystream with an IV and generates the first keystream block. Call exactly once
   * per stream/IV.
   *
   * @param iv the array containing the IV bytes
   * @param offset start index of the IV in {@code iv}
   * @param length number of IV bytes; must equal the cipher block size in bytes
   * @throws IllegalArgumentException if {@code length} does not equal the required IV length
   * @throws ArrayIndexOutOfBoundsException if {@code offset + length} exceeds {@code iv.length}
   * @throws NullPointerException if {@code iv} is {@code null}
   * @implNote Reusing an IV with the same key compromises security in CTR mode.
   */
  public void init(byte[] iv, int offset, int length) throws IllegalArgumentException {
    if (length != ivBytes.length) throw new IllegalArgumentException();
    System.arraycopy(iv, offset, ivBytes, 0, ivBytes.length);
    System.arraycopy(ivBytes, 0, counter, 0, counter.length);
    processBlock();
  }

  /**
   * Convenience overload that initializes from a whole-array IV.
   *
   * @param iv IV bytes; length must equal the cipher block size in bytes
   * @throws IllegalArgumentException if {@code iv.length} is invalid for this cipher
   * @throws NullPointerException if {@code iv} is {@code null}
   */
  public void init(byte[] iv) throws IllegalArgumentException {
    init(iv, 0, iv.length);
  }

  /**
   * Returns the block size of the underlying cipher in bits (delegates to {@link
   * BlockCipher#getBlockSize()}). Internal counters and IVs have length {@code getBlockSize()/8}
   * bytes.
   */
  public int getBlockSize() {
    return cipher.getBlockSize();
  }

  /**
   * Encrypts or decrypts a single byte at the current position in the keystream.
   *
   * <p>If the current keystream block is exhausted, a new block is generated and the counter is
   * incremented before XORing.
   *
   * @param in the input byte
   * @return the output byte after XOR with the keystream
   */
  public byte processByte(byte in) {
    if (blockOffset == counterOut.length) {
      processBlock();
    }
    return (byte) (in ^ counterOut[blockOffset++]);
  }

  /**
   * Encrypts or decrypts a sequence of bytes.
   *
   * <p>Processing is symmetric for encryption and decryption. This method may be called repeatedly;
   * the internal counter and block offset advance across calls.
   *
   * <p>In-place operation is supported when {@code input == output} and {@code offsetIn ==
   * offsetOut}. Other overlapping layouts are not defined.
   *
   * @param input input array containing data to process
   * @param offsetIn start index in {@code input}
   * @param length number of bytes to process
   * @param output destination array for the result
   * @param offsetOut start index in {@code output}
   */
  public void processBytes(byte[] input, int offsetIn, int length, byte[] output, int offsetOut) {
    // XOR input with the current keystream until the block is exhausted, then generate the next
    // block by calling processBlock().

    if (blockOffset != 0) {
      /* Handle an initial partially consumed keystream block. */
      int len = Math.min(blockSize - blockOffset, length);
      length -= len;
      while (len-- > 0)
        output[offsetOut++] = (byte) (input[offsetIn++] ^ counterOut[blockOffset++]);
      if (length == 0) return;
      processBlock();
    }
    if (blockOffset != 0) {
      throw new IllegalStateException("blockOffset must be 0 when starting full-block processing");
    }
    while (length > blockSize) {
      /* Consume as many full blocks as possible. Skip the last full block to avoid an extra
       * processBlock() when the final partial block (if any) can reuse the current keystream. */
      length -= blockSize;
      while (blockOffset < blockSize)
        output[offsetOut++] = (byte) (input[offsetIn++] ^ counterOut[blockOffset++]);
      processBlock();
    }
    // At this point, the loop above ensures length <= blockSize.
    if (blockOffset != 0) {
      throw new IllegalStateException("blockOffset must be 0 before final block processing");
    }
    if (length == 0) return;
    while (length-- > 0) {
      /* Handle the tail bytes in the final (possibly partial) block. */
      output[offsetOut++] = (byte) (input[offsetIn++] ^ counterOut[blockOffset++]);
    }
  }

  /**
   * Generates the next keystream block by encrypting {@link #counter} into {@link #counterOut},
   * then increments {@link #counter} as an unsigned big-endian integer. Resets {@link #blockOffset}
   * to {@code 0}.
   */
  private void processBlock() throws IllegalStateException {
    // Some cipher implementations write in-place into the destination array. Copy the counter to
    // counterOut and then encrypt in-place to avoid clobbering the counter state.
    System.arraycopy(counter, 0, counterOut, 0, counter.length);
    cipher.encipher(counterOut, counterOut);

    // Increment counter as a big-endian integer (propagate carry from the last byte backward).
    for (int i = counter.length - 1; i >= 0; i--) {
      if (++counter[i] != (byte) 0) {
        break; // stop when no carry
      }
    }
    blockOffset = 0;
  }
}
