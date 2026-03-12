package network.crypta.crypt;

import java.io.DataInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.jetbrains.annotations.NotNull;

/**
 * InputStream that decrypts and authenticates data produced by an AEAD encoder using AES-GCM.
 *
 * <p>This stream expects a fixed 16-byte written prefix before the ciphertext. The first 12 bytes
 * of that prefix are used as the GCM IV/nonce; the remaining 4 bytes are reserved. The total
 * overhead for AES-GCM is therefore 32 bytes (16-byte prefix + 16-byte tag).
 *
 * <p>Authentication is verified only when the end of the stream is reached (during {@code
 * doFinal()}). Until then, data returned by {@link #read()} is not yet authenticated. If the final
 * authentication check fails, reads that reach end-of-stream or {@link #close()} will throw {@link
 * AEADVerificationFailedException}.
 *
 * <p>Thread-safety: instances are not thread-safe. Mark/reset is not supported.
 */
public final class AEADInputStream extends FilterInputStream {

  private static final int MAC_SIZE_BITS = AEADOutputStream.MAC_SIZE_BITS;
  private final AEADCipher cipher;
  private boolean finished;

  /**
   * Creates a decrypting, authenticating stream using AES-GCM.
   *
   * <p>Format: the underlying stream begins with a 16-byte written prefix. The first 12 bytes are
   * used as the GCM nonce/IV; the remaining 4 bytes are reserved. This reader does not implement
   * legacy OCB compatibility.
   *
   * <p>Authentication is verified at end-of-stream when {@code doFinal()} is invoked. Do not ignore
   * {@link IOException}s thrown by {@link #close()} because that is where authentication failures
   * surface.
   *
   * @param is the underlying source stream.
   * @param key the encryption key; must be valid for the provided AES implementation.
   * @param mainCipher the block cipher (AES) used by GCM; not a block mode.
   * @throws IOException if the prefix cannot be read or the underlying stream fails.
   */
  public AEADInputStream(InputStream is, byte[] key, BlockCipher mainCipher) throws IOException {
    super(is);
    // Read the 16-byte written prefix and take the first 12 bytes as the GCM nonce.
    final int blockSize = mainCipher.getBlockSize();
    byte[] writtenNonce = new byte[blockSize];
    DataInputStream dis = new DataInputStream(is);
    dis.readFully(writtenNonce);
    byte[] nonce = new byte[AEADOutputStream.GCM_NONCE_SIZE];
    System.arraycopy(writtenNonce, 0, nonce, 0, nonce.length);
    cipher = GCMBlockCipher.newInstance(mainCipher);
    KeyParameter keyParam = new KeyParameter(key);
    AEADParameters params = new AEADParameters(keyParam, MAC_SIZE_BITS, nonce);
    cipher.init(false, params);
    excess = new byte[mainCipher.getBlockSize()];
    excessEnd = 0;
    excessPtr = 0;
  }

  /**
   * Returns the size, in bytes, of the IV/nonce used by AES-GCM (12).
   *
   * <p>This value is distinct from the written prefix size (16 bytes).
   *
   * @return nonce size in bytes.
   */
  public final int getIVSize() {
    return AEADOutputStream.GCM_NONCE_SIZE;
  }

  private final byte[] excess;
  private int excessEnd;
  private int excessPtr;

  /**
   * Reads a single byte of plaintext.
   *
   * @return the byte value {@code 0..255}, or {@code -1} if end of stream.
   * @throws AEADVerificationFailedException if authentication fails when the end of the stream is
   *     reached.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int read() throws IOException {
    byte[] buf = new byte[1];
    int length = read(buf, 0, 1);
    if (length > 0) {
      return Byte.toUnsignedInt(buf[0]);
    }
    return -1;
  }

  /**
   * Reads plaintext bytes into the given buffer.
   *
   * @param buf destination array.
   * @return number of bytes read, or {@code -1} if end of stream.
   * @throws AEADVerificationFailedException if authentication fails when the end of the stream is
   *     reached.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int read(byte @NotNull [] buf) throws IOException {
    return read(buf, 0, buf.length);
  }

  /**
   * Reads up to {@code length} plaintext bytes into {@code buf} starting at {@code offset}.
   *
   * <p>Returns as soon as any plaintext is available or end-of-stream is reached. A return value of
   * {@code 0} is possible when the underlying stream reports {@code 0} readable bytes.
   *
   * @param buf destination array.
   * @param offset start offset in {@code buf}.
   * @param length maximum number of bytes to read; negative values yield {@code -1}.
   * @return number of bytes read, {@code 0}, or {@code -1} on end of stream.
   * @throws AEADVerificationFailedException if authentication fails when the end of the stream is
   *     reached.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int read(byte @NotNull [] buf, int offset, int length) throws IOException {
    if (length < 0) return -1;
    if (length == 0) return 0;

    int copied = copyFromExcess(buf, offset, length);
    if (copied > 0) return copied;

    if (finished) return -1;

    // Allocate a temporary input buffer to avoid aliasing of input/output arrays passed to
    // cipher.processBytes(). Any optimization must preserve this separation for correctness.
    while (true) {
      byte[] temp = new byte[length];
      int readCount = in.read(temp);
      if (readCount == 0) return 0; // Propagate as-is to match InputStream contract.
      if (readCount < 0) {
        return handleEndOfStream(buf, offset, length);
      }

      // Compute the exact space needed for this update; AEAD may emit more than it consumes.
      int outLength = cipher.getUpdateOutputSize(readCount);
      if (outLength > length) {
        return processWithExcess(temp, readCount, buf, offset, length, outLength);
      } else {
        int decryptedBytes = cipher.processBytes(temp, 0, readCount, buf, offset);
        if (decryptedBytes > 0) return decryptedBytes;
      }
    }
  }

  private int copyFromExcess(byte[] buf, int offset, int maxLen) {
    if (excessEnd == 0) return 0;
    int toCopy = Math.min(maxLen, excessEnd - excessPtr);
    if (toCopy <= 0) return 0;
    System.arraycopy(excess, excessPtr, buf, offset, toCopy);
    excessPtr += toCopy;
    if (excessEnd == excessPtr) {
      excessEnd = 0;
      excessPtr = 0;
    }
    return toCopy;
  }

  private int handleEndOfStream(byte[] buf, int offset, int length) throws IOException {
    // End of stream: retrieve remaining bytes from cipher via doFinal(), which also verifies the
    // authentication tag.
    try {
      excessEnd = cipher.doFinal(excess, 0);
    } catch (InvalidCipherTextException _) {
      throw new AEADVerificationFailedException();
    }
    finished = true;
    if (excessEnd > 0) return read(buf, offset, length);
    return -1;
  }

  private int processWithExcess(
      byte[] input, int readCount, byte[] buf, int offset, int length, int outLength) {
    byte[] outputTemp = new byte[outLength];
    int decryptedBytes = cipher.processBytes(input, 0, readCount, outputTemp, 0);
    assert (decryptedBytes == outLength);
    System.arraycopy(outputTemp, 0, buf, offset, length);
    excessEnd = outLength - length;
    assert (excessEnd < excess.length);
    System.arraycopy(outputTemp, length, excess, 0, excessEnd);
    return length;
  }

  /**
   * Returns an estimate of the number of bytes that can be read without blocking.
   *
   * <p>This value accounts for internal buffering but may not reflect the final plaintext length,
   * because AEAD buffering and the trailing authentication tag affect how many bytes the underlying
   * stream reports as available.
   *
   * @return an estimate of available bytes.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int available() throws IOException {
    int availableExcess = excessEnd - excessPtr;
    if (availableExcess > 0) return availableExcess;
    if (finished) return 0;
    // NOTE: Not exact; AEAD buffering and tag bytes mean the underlying stream availability does
    // not represent the total plaintext length.
    return in.available();
  }

  /**
   * Skips up to {@code n} bytes of plaintext by reading and discarding them.
   *
   * <p>Authentication is still enforced. If the final tag is invalid, a {@link
   * AEADVerificationFailedException} is thrown when the end of the stream is reached.
   *
   * @param n maximum number of bytes to skip.
   * @return the actual number of bytes skipped.
   * @throws AEADVerificationFailedException if authentication fails when the end of the stream is
   *     reached.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public long skip(long n) throws IOException {
    // Consume and discard plaintext to advance the stream while preserving authentication checks.
    long skipped = 0;
    byte[] temp = new byte[excess.length];
    while (n > 0) {
      int excessLeft = excessEnd - excessPtr;
      if (excessLeft > 0) {
        if (n < excessLeft) {
          excessPtr += (int) n;
          return n;
        }
        n -= excessLeft;
        skipped += excessLeft;
        excessEnd = 0;
        excessPtr = 0;
        continue;
      }
      int read;
      if (n < temp.length) {
        read = read(temp, 0, (int) n);
      } else {
        read = read(temp);
      }
      if (read <= 0) return skipped;
      skipped += read;
      n -= read;
    }
    return skipped;
  }

  /**
   * Closes the stream after consuming any remaining ciphertext to verify the authentication tag.
   *
   * <p>If tag verification fails, this method throws {@link AEADVerificationFailedException}. After
   * verification, the underlying stream is closed.
   *
   * @throws AEADVerificationFailedException if authentication fails when the end of the stream is
   *     reached.
   * @throws IOException if an I/O error occurs while reading or closing the underlying stream.
   */
  @Override
  public void close() throws IOException {
    if (!finished) {
      // Drain remaining data to trigger authentication and avoid silently ignoring failures.
      // Check the return value to satisfy static analyzers; loop until progress stops.
      while (!finished) {
        long justSkipped = skip(Long.MAX_VALUE);
        if (justSkipped <= 0) break;
      }
    }
    in.close();
  }

  /**
   * Returns {@code false}; mark/reset is not supported.
   *
   * @return {@code false}.
   */
  @Override
  public boolean markSupported() {
    return false;
  }

  /** Unsupported; calling this method always throws {@link UnsupportedOperationException}. */
  @Override
  public void mark(int readlimit) {
    throw new UnsupportedOperationException();
  }

  /** Unsupported; calling this method always throws an {@link IOException}. */
  @Override
  public void reset() throws IOException {
    throw new IOException("Mark/reset not supported");
  }

  /**
   * Convenience factory for an AES-GCM {@link AEADInputStream}.
   *
   * @param is the underlying source stream.
   * @param key the encryption key for AES.
   * @return a new instance configured for AES-GCM.
   * @throws IOException if the prefix cannot be read or the underlying stream fails.
   */
  public static AEADInputStream createAES(InputStream is, byte[] key) throws IOException {
    BlockCipher mainCipher = BlockCiphers.aes();
    return new AEADInputStream(is, key, mainCipher);
  }
}
