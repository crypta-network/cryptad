package network.crypta.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Byte-oriented implementation of Periodic Cipher Feedback (PCFB) mode over a {@link BlockCipher}.
 *
 * <p>The mode maintains a feedback register whose size equals the cipher's block size in bytes. For
 * each processed byte, one byte from the register is used as keystream and is XORed with the input
 * byte; the resulting ciphertext (for {@link #encipher(int)}) or the consumed ciphertext (for
 * {@link #decipher(int)}) is written back into the same register position. When the register is
 * exhausted, the entire register is encrypted in place to produce the next block of keystream—the
 * "periodic" step in PCFB.
 *
 * <p>Specification reference: <a
 * href="https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/pcfb/pcfb-spec.pdf">PCFB
 * mode (proposed)</a>.
 *
 * <p>Instances are stateful and not thread-safe. A unique, unpredictable IV must be used for every
 * key. The helper methods {@link #writeIV(RandomSource, OutputStream)} and {@link
 * #readIV(InputStream)} are provided for IV transport.
 */
public class PCFBMode {

  /** The underlying block cipher. */
  protected final BlockCipher c;

  /** The register, with which data is XOR'ed. */
  protected final byte[] feedbackRegister;

  /** When this reaches the end of the register, we refillBuffer() i.e. re-encrypt the register. */
  protected int registerPointer;

  /**
   * Creates a PCFB instance with an explicit IV starting at offset {@code 0}.
   *
   * <p>The register pointer is positioned at the end so the next operation re-encrypts the register
   * before any data is processed.
   *
   * @param c the underlying block cipher
   * @param iv the initialization vector; must contain at least {@link #lengthIV(BlockCipher)} bytes
   *     for {@code c}
   * @return a new PCFB instance
   * @throws ArrayIndexOutOfBoundsException if {@code iv} is shorter than {@code lengthIV(c)}
   */
  public static PCFBMode create(BlockCipher c, byte[] iv) {
    return create(c, iv, 0);
  }

  /**
   * Creates a PCFB instance with an explicit IV region in {@code iv}.
   *
   * <p>The bytes {@code iv[offset .. offset + lengthIV(c))} are copied into the register. The
   * register pointer is positioned at the end so the next operation re-encrypts the register before
   * any data is processed. For a given key, IVs must be unique and unpredictable.
   *
   * @param c the underlying block cipher
   * @param iv the buffer containing the IV
   * @param offset the starting offset of the IV within {@code iv}
   * @return a new PCFB instance
   * @throws ArrayIndexOutOfBoundsException if {@code iv} does not contain {@code lengthIV(c)} bytes
   *     from {@code offset}
   */
  public static PCFBMode create(BlockCipher c, byte[] iv, int offset) {
    return new PCFBMode(c, iv, offset);
  }

  /**
   * Constructs a PCFB instance with a zero IV.
   *
   * <p>The register is filled with zeros and the pointer is set to the end, causing an immediate
   * re-encryption on first use.
   *
   * @param c the underlying block cipher
   */
  protected PCFBMode(BlockCipher c) {
    this.c = c;
    feedbackRegister = new byte[c.getBlockSize() >> 3];
    registerPointer = feedbackRegister.length;
  }

  /**
   * Constructs a PCFB instance and initializes it with an IV segment from {@code iv}.
   *
   * @param c the underlying block cipher
   * @param iv the buffer that contains the IV bytes
   * @param offset the starting offset of the IV within {@code iv}
   * @throws ArrayIndexOutOfBoundsException if the IV segment is shorter than {@code lengthIV(c)}
   */
  protected PCFBMode(BlockCipher c, byte[] iv, int offset) {
    this(c);
    System.arraycopy(iv, offset, feedbackRegister, 0, feedbackRegister.length);
    // Register pointer is already at end from this(c); the next operation will refill immediately.
  }

  /**
   * Resets the internal register to the given IV and positions the pointer at the end.
   *
   * <p>The next encipher/decipher call re-encrypts the register before processing data.
   *
   * @param iv the initialization vector; must be {@link #lengthIV()} bytes long
   */
  public final void reset(byte[] iv) {
    System.arraycopy(iv, 0, feedbackRegister, 0, feedbackRegister.length);
    registerPointer = feedbackRegister.length;
  }

  /**
   * Resets the internal register to the IV segment beginning at {@code offset} and positions the
   * pointer at the end.
   *
   * <p>The next encipher/decipher call re-encrypts the register before processing data.
   *
   * @param iv the buffer containing the IV
   * @param offset the starting offset of the IV within {@code iv}
   * @throws ArrayIndexOutOfBoundsException if the IV segment is shorter than {@link #lengthIV()}
   *     bytes
   */
  public final void reset(byte[] iv, int offset) {
    System.arraycopy(iv, offset, feedbackRegister, 0, feedbackRegister.length);
    registerPointer = feedbackRegister.length;
  }

  /**
   * Generates a fresh random IV, stores it into the internal register, and writes it to the output
   * stream.
   *
   * <p>Although the IV is sent in the clear, it is encrypted in place before any payload bytes are
   * processed because the register pointer is positioned to force an immediate refill.
   *
   * @param rs the random source used to generate the IV
   * @param out the stream to which the IV is written
   * @throws IOException if writing to {@code out} fails
   */
  public void writeIV(RandomSource rs, OutputStream out) throws IOException {
    rs.nextBytes(feedbackRegister);
    out.write(feedbackRegister);
  }

  /**
   * Reads exactly {@link #lengthIV()} bytes from {@code in} into the internal register.
   *
   * @param in the stream to read the IV from
   * @throws IOException if reading the required number of bytes fails
   */
  public void readIV(InputStream in) throws IOException {
    Util.readFully(in, feedbackRegister);
  }

  /**
   * Returns the IV length, in bytes, for this instance.
   *
   * @return the IV length in bytes
   */
  public int lengthIV() {
    return feedbackRegister.length;
  }

  /**
   * Returns the IV length, in bytes, for PCFB over the given cipher.
   *
   * @param c the block cipher
   * @return the IV length in bytes, equal to {@code c.getBlockSize() / 8}
   */
  public static int lengthIV(BlockCipher c) {
    return c.getBlockSize() >> 3;
  }

  /**
   * Deciphers a single byte.
   *
   * <p>The method XORs the next keystream byte from the register with {@code b} and returns the
   * plaintext. The ciphertext {@code b} is written into the current register position. When the
   * register is exhausted, it is re-encrypted to produce the next block of keystream.
   *
   * @param b the ciphertext byte as an unsigned value in {@code 0..255}
   * @return the plaintext byte as an unsigned value in {@code 0..255}
   */
  public int decipher(int b) {
    if (registerPointer == feedbackRegister.length) refillBuffer();
    int rv = (feedbackRegister[registerPointer] ^ (byte) b) & 0xff;
    feedbackRegister[registerPointer++] = (byte) b;
    return rv;
  }

  /**
   * Deciphers {@code len} bytes in place in {@code buf} starting at {@code off}.
   *
   * @param buf the buffer containing ciphertext; replaced with plaintext
   * @param off the starting offset within {@code buf}
   * @param len the number of bytes to process
   */
  public void blockDecipher(byte[] buf, int off, int len) {
    for (int i = 0; i < len; i++) {
      buf[off + i] = (byte) decipher(buf[off + i] & 0xFF);
    }
  }

  /**
   * Enciphers a single byte.
   *
   * <p>The method XORs the next keystream byte from the register with {@code b}, writes the
   * resulting ciphertext into the current register position, and returns it. When the register is
   * exhausted, it is re-encrypted to produce the next block of keystream.
   *
   * @param b the plaintext byte as an unsigned value in {@code 0..255}
   * @return the ciphertext byte as an unsigned value in {@code 0..255}
   */
  public int encipher(int b) {
    if (registerPointer == feedbackRegister.length) refillBuffer();
    feedbackRegister[registerPointer] ^= (byte) b;
    return feedbackRegister[registerPointer++] & 0xff;
  }

  /**
   * Enciphers {@code len} bytes in place in {@code buf} starting at {@code off}.
   *
   * @param buf the buffer containing plaintext; replaced with ciphertext
   * @param off the starting offset within {@code buf}
   * @param len the number of bytes to process
   */
  public void blockEncipher(byte[] buf, int off, int len) {
    for (int i = 0; i < len; i++) {
      buf[off + i] = (byte) encipher(buf[off + i] & 0xFF);
    }
  }

  /**
   * Encrypts the feedback register in place to produce the next keystream block and resets the
   * pointer to the beginning of the register.
   */
  protected void refillBuffer() {
    // Encrypt current register to derive fresh keystream bytes.
    c.encipher(feedbackRegister, feedbackRegister);

    registerPointer = 0;
  }
}
