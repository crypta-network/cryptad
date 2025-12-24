package network.crypta.crypt;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Utilities for constructing block cipher implementations.
 *
 * <p>Currently provides a factory for AES in ECB mode (no padding). At runtime the factory prefers
 * a JCE-backed implementation when available for the configured key sizes; otherwise it falls back
 * to BouncyCastle's {@link AESEngine}.
 *
 * <p>This is an internal utility; returned cipher instances are stateful and not thread-safe.
 */
class BlockCiphers {
  private BlockCiphers() {
    throw new IllegalStateException("Utility class");
  }

  // Prefer JCE when it supports AES with 128/192/256-bit keys (sizes are in bytes).
  private static final boolean USE_JCE_FOR_AES = checkJceSupported(16, 24, 32);

  /**
   * Creates a new AES block cipher in ECB mode with no padding.
   *
   * <p>The returned instance implements BouncyCastle's {@link BlockCipher} API. When the JCE
   * provider can initialize AES for 128/192/256-bit keys, a lightweight adapter around {@link
   * javax.crypto.Cipher} is returned; otherwise a new {@link AESEngine} instance is used.
   *
   * <p>The cipher is stateful and not thread-safe; create one instance per thread or synchronize
   * external access.
   *
   * @return a fresh {@link BlockCipher} for AES/ECB/NoPadding.
   * @throws IllegalStateException if the algorithm or padding is unavailable or initialization
   *     fails.
   */
  static BlockCipher aes() {
    try {
      return USE_JCE_FOR_AES ? new JceEcbBlockCipher("AES") : AESEngine.newInstance();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static final class JceEcbBlockCipher implements BlockCipher {
    private final String algorithm;
    private final Cipher cipher;
    private final int blockSize;
    // Scratch output buffer to support in == out semantics expected by BlockCipher callers.
    private final byte[] buf;

    JceEcbBlockCipher(String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException {
      this.algorithm = algorithm;
      this.cipher = Cipher.getInstance(algorithm + "/ECB/NoPadding");
      this.blockSize = cipher.getBlockSize();
      this.buf = new byte[blockSize];
    }

    /**
     * Initializes the cipher for single-block operations.
     *
     * @param forEncryption {@code true} to encrypt; {@code false} to decrypt.
     * @param params {@link KeyParameter} containing the raw AES key bytes.
     * @throws IllegalArgumentException if the key is invalid for the provider.
     */
    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException {
      Key key = new SecretKeySpec(((KeyParameter) params).getKey(), "AES");
      try {
        cipher.init(forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
      } catch (InvalidKeyException e) {
        throw new IllegalArgumentException(e);
      }
    }

    /** Returns the base algorithm name (for example, {@code "AES"}). */
    @Override
    public String getAlgorithmName() {
      return algorithm;
    }

    /** Returns the cipher block size in bytes (AES is 16). */
    @Override
    public int getBlockSize() {
      return blockSize;
    }

    /**
     * Processes exactly one block.
     *
     * <p>Callers may pass the same array for {@code in} and {@code out}. To avoid JCE-internal
     * temporary allocations and to honor the {@link BlockCipher} allowance for overlapping buffers,
     * this implementation writes into an internal scratch buffer and then copies the bytes to
     * {@code out}.
     *
     * @param in source array containing {@code blockSize} bytes at {@code inOff}.
     * @param inOff offset in {@code in}.
     * @param out destination array with room for {@code blockSize} bytes at {@code outOff}.
     * @param outOff offset in {@code out}.
     * @return {@code blockSize}.
     * @throws DataLengthException if the output buffer is too small or offsets/length are invalid.
     */
    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException {
      try {
        // Write to the scratch buffer first to avoid any provider-specific constraints on
        // overlapping input/output arrays, then copy the result to the caller-provided buffer.
        cipher.update(in, inOff, blockSize, buf, 0);
        System.arraycopy(buf, 0, out, outOff, blockSize);
        return blockSize;
      } catch (ShortBufferException e) {
        throw new DataLengthException(e.getMessage());
      }
    }

    /**
     * Clears internal scratch state.
     *
     * <p>This does not reinitialize the underlying {@link Cipher}. The current key and mode remain
     * in effect until {@link #init(boolean, CipherParameters)} is called again.
     */
    @Override
    public void reset() {
      Arrays.fill(buf, (byte) 0);
    }
  }

  /*
   * Returns whether the JCE provider can initialize AES for the provided key sizes.
   *
   * Key sizes are expressed in bytes (16/24/32 → 128/192/256 bits). Any exception during
   * initialization is treated as lack of support.
   */
  private static boolean checkJceSupported(int... keySizes) {
    try {
      for (int keySize : keySizes) {
        new JceEcbBlockCipher("AES").init(false, new KeyParameter(new byte[keySize]));
      }
      return true;
    } catch (Exception _) {
      return false;
    }
  }
}
