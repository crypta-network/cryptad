package network.crypta.crypt;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Random;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Uses bouncycastle's AEAD code. BC provides Cipher*Stream but they don't work with authenticating.
 * FIXME This probably needs an internal buffer. Shouldn't be too inefficient provided that any
 * short writes are buffered before they reach here though.
 *
 * @author toad
 */
public class AEADOutputStream extends FilterOutputStream {

  private final AEADBlockCipher cipher;

  /**
   * Create an encrypting, authenticating OutputStream using AES-GCM.
   *
   * <p>Format: Writes a 16-byte prefix to the stream. GCM uses only the first 12 bytes as the
   * nonce/IV; the remaining 4 bytes are currently unused and reserved. Keeping a 16-byte prefix
   * preserves overall overhead (16-byte prefix + 16-byte tag).
   *
   * @param os The underlying OutputStream.
   * @param key The encryption key.
   * @param writtenNonce The 16-byte prefix to persist at the start of the stream.
   * @param gcmNonce The 12-byte GCM nonce (first 12 bytes of {@code writtenNonce}).
   * @param mainCipher The BlockCipher (AES) used by GCM; not a block mode.
   * @param hashCipher Unused for GCM (retained for signature compatibility).
   */
  public AEADOutputStream(
      OutputStream os,
      byte[] key,
      byte[] writtenNonce,
      byte[] gcmNonce,
      BlockCipher hashCipher,
      BlockCipher mainCipher)
      throws IOException {
    super(os);
    // Persist the 16-byte prefix (block size: 16 for AES) to keep file overhead stable.
    os.write(writtenNonce);
    AEADBlockCipher gcm = new GCMBlockCipher(mainCipher);
    cipher = gcm;
    KeyParameter keyParam = new KeyParameter(key);
    AEADParameters params = new AEADParameters(keyParam, MAC_SIZE_BITS, gcmNonce);
    cipher.init(true, params);
  }

  @Override
  public void write(int b) throws IOException {
    write(new byte[] {(byte) b});
  }

  @Override
  public void write(byte[] buf) throws IOException {
    write(buf, 0, buf.length);
  }

  @Override
  public void write(byte[] buf, int offset, int length) throws IOException {
    byte[] output = new byte[cipher.getUpdateOutputSize(length)];
    cipher.processBytes(buf, offset, length, output, 0);
    out.write(output);
  }

  @Override
  public void close() throws IOException {
    byte[] output = new byte[cipher.getOutputSize(0)];
    try {
      cipher.doFinal(output, 0);
    } catch (InvalidCipherTextException e) {
      // Impossible???
      throw new RuntimeException("Impossible: " + e);
    }
    out.write(output);
    out.close();
  }

  static final int MAC_SIZE_BITS = 128;
  static final int MAC_SIZE_BYTES = MAC_SIZE_BITS / 8;
  // Recommended GCM nonce size is 12 bytes.
  static final int GCM_NONCE_SIZE = 12;
  // Number of bytes we write before the ciphertext to store the nonce on disk.
  // For AES we preserve the historical 16-byte prefix for compatibility.
  static final int WRITTEN_NONCE_SIZE = 16;
  public static final int AES_OVERHEAD = WRITTEN_NONCE_SIZE + MAC_SIZE_BYTES;

  public static AEADOutputStream createAES(OutputStream os, byte[] key, SecureRandom random)
      throws IOException {
    return innerCreateAES(os, key, random);
  }

  /** For unit tests only */
  static AEADOutputStream innerCreateAES(OutputStream os, byte[] key, Random random)
      throws IOException {
    BlockCipher mainCipher = BlockCiphers.aes();
    BlockCipher hashCipher = BlockCiphers.aes();
    byte[] writtenNonce = new byte[WRITTEN_NONCE_SIZE];
    random.nextBytes(writtenNonce);
    // GCM uses the first 12 bytes of the prefix as nonce.
    byte[] gcmNonce = new byte[GCM_NONCE_SIZE];
    System.arraycopy(writtenNonce, 0, gcmNonce, 0, gcmNonce.length);
    return new AEADOutputStream(os, key, writtenNonce, gcmNonce, hashCipher, mainCipher);
  }

  @Override
  public String toString() {
    return "AEADOutputStream:" + out.toString();
  }
}
