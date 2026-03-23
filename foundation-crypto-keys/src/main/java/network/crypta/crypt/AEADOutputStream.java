package network.crypta.crypt;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.jetbrains.annotations.NotNull;

/**
 * OutputStream that performs authenticated encryption using AES‑GCM.
 *
 * <p>The stream writes a fixed, 16‑byte prefix before any ciphertext. The first 12 bytes of this
 * prefix form the GCM nonce/IV; the remaining 4 bytes are currently reserved to preserve the
 * historical on‑disk layout and overhead. The authentication tag (128 bits) is appended when the
 * stream is closed. Total overhead for AES is therefore 32 bytes (16‑byte prefix + 16‑byte tag).
 *
 * <p>Design notes:
 *
 * <ul>
 *   <li>The class is not thread‑safe.
 *   <li>No Additional Authenticated Data (AAD) is used; callers cannot attach external headers.
 *   <li>The constructor writes the 16‑byte prefix immediately; the underlying stream must be ready
 *       for output at construction time.
 *   <li>No extra buffering is performed here. For small writes, wrap this stream in a buffered
 *       stream upstream if needed.
 *   <li>Pairs with {@link AEADInputStream} which consumes the same 16‑byte prefix and GCM tag on
 *       read.
 * </ul>
 *
 * @author toad
 */
public final class AEADOutputStream extends FilterOutputStream {

  private final AEADCipher cipher;

  /**
   * Constructs an encrypting stream that writes AES‑GCM ciphertext to {@code os}.
   *
   * <p>On construction, this method writes {@code writtenNonce} to {@code os}. GCM uses only the
   * first 12 bytes of that prefix as its nonce/IV; the remaining 4 bytes are reserved to preserve a
   * 16‑byte on‑disk prefix for compatibility.
   *
   * @param os underlying destination; must be open and writable.
   * @param key secret key material for AES; must be non‑null and of a valid AES length.
   * @param writtenNonce 16‑byte prefix persisted verbatim before the ciphertext.
   * @param gcmNonce 12‑byte nonce passed to GCM (the first 12 bytes of {@code writtenNonce}).
   * @param mainCipher block cipher instance (AES) used by GCM; not a mode wrapper.
   * @throws IOException if writing the prefix fails or if finalization fails later.
   */
  public AEADOutputStream(
      OutputStream os, byte[] key, byte[] writtenNonce, byte[] gcmNonce, BlockCipher mainCipher)
      throws IOException {
    Objects.requireNonNull(mainCipher, "mainCipher");
    super(os);
    // Persist the 16‑byte prefix (AES block size is 16) to keep the on‑disk overhead stable.
    os.write(writtenNonce);
    cipher = GCMBlockCipher.newInstance(mainCipher);
    KeyParameter keyParam = new KeyParameter(key);
    AEADParameters params = new AEADParameters(keyParam, MAC_SIZE_BITS, gcmNonce);
    cipher.init(true, params);
  }

  @Override
  public void write(int b) throws IOException {
    write(new byte[] {(byte) b});
  }

  @Override
  public void write(byte @NotNull [] buf) throws IOException {
    write(buf, 0, buf.length);
  }

  @Override
  public void write(byte @NotNull [] buf, int offset, int length) throws IOException {
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
      // Encryption should not fail during normal operation. Wrap in an IOException so callers are
      // informed that authentication/tag finalization failed.
      throw new IOException("AEAD finalization failed", e);
    }
    out.write(output);
    out.close();
  }

  static final int MAC_SIZE_BITS = 128;
  static final int MAC_SIZE_BYTES = MAC_SIZE_BITS / 8;
  // GCM nonce: 12 bytes is the NIST‑recommended size; keeps counters unique and efficient.
  static final int GCM_NONCE_SIZE = 12;
  // Bytes written before ciphertext. We preserve a 16‑byte prefix on disk for compatibility even
  // though GCM itself consumes only 12 bytes as the nonce.
  static final int WRITTEN_NONCE_SIZE = 16;
  public static final int AES_OVERHEAD = WRITTEN_NONCE_SIZE + MAC_SIZE_BYTES;

  /**
   * Creates an AES‑GCM {@code AEADOutputStream} with a randomly generated 16‑byte written prefix
   * and a 12‑byte GCM nonce (the first 12 bytes of that prefix).
   *
   * <p>The returned stream immediately writes the prefix to {@code os}. Callers should ensure the
   * destination is ready and that the prefix is retained alongside the ciphertext for decryption by
   * {@link AEADInputStream}.
   *
   * @param os underlying destination; must be open and writable.
   * @param key secret key material for AES; must be non‑null and of a valid AES length.
   * @param random source of entropy used to fill the 16‑byte written prefix.
   * @return an encrypting stream that outputs AES‑GCM with a 128‑bit tag.
   * @throws IOException if writing the prefix fails.
   */
  public static AEADOutputStream createAES(OutputStream os, byte[] key, SecureRandom random)
      throws IOException {
    return innerCreateAES(os, key, random);
  }

  /** For unit tests only */
  static AEADOutputStream innerCreateAES(OutputStream os, byte[] key, Random random)
      throws IOException {
    BlockCipher mainCipher = BlockCiphers.aes();
    byte[] writtenNonce = new byte[WRITTEN_NONCE_SIZE];
    random.nextBytes(writtenNonce);
    // GCM uses the first 12 bytes of the prefix as nonce.
    byte[] gcmNonce = new byte[GCM_NONCE_SIZE];
    System.arraycopy(writtenNonce, 0, gcmNonce, 0, gcmNonce.length);
    return new AEADOutputStream(os, key, writtenNonce, gcmNonce, mainCipher);
  }

  @Override
  public String toString() {
    // Include the underlying stream’s toString() to aid debugging/logs.
    return "AEADOutputStream:" + out.toString();
  }
}
