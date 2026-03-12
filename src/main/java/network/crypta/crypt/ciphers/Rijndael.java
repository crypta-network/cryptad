package network.crypta.crypt.ciphers;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.Security;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.JceLoader;
import network.crypta.crypt.UnsupportedCipherException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 This code is part of the Java Adaptive Network Client by Ian Clarke.
 It is distributed under the GNU Public License (GPL) version 2.  See
 http://www.gnu.org/ for further details of the GPL.
*/

/**
 * Block cipher implementation of the Rijndael algorithm (the family from which AES derives).
 *
 * <p>This class provides a pure-Java single-block Rijndael implementation used by the {@link
 * network.crypta.crypt.BlockCipher} interface, supporting key sizes of 128, 192, or 256 bits and
 * block sizes of 128 or 256 bits. It also exposes utility accessors for the chosen JCA provider for
 * {@code AES/CTR/NoPadding} (selected at class initialization), which other components may use for
 * stream modes.
 *
 * <p>Instances keep the computed key schedule in a per-instance field. Callers must invoke {@link
 * #initialize(byte[])} before calling {@link #encipher(byte[], byte[])} or {@link #decipher(byte[],
 * byte[])}.
 */
public final class Rijndael implements BlockCipher {
  private static final Logger LOG = LoggerFactory.getLogger(Rijndael.class);

  private Object sessionKey;
  private final int keysize;
  private final int blocksize;

  private static final Provider EMPTY_PROVIDER = new EmptyProvider();
  private static final Provider AesCtrProvider = detectAesCtrProvider();

  /**
   * Returns the name of the selected JCA provider for {@code AES/CTR/NoPadding}, or {@code null}
   * when no suitable provider was detected (e.g., when restricted to 128-bit keys).
   *
   * <p>The provider is chosen once during class initialization. When available, the selection may
   * prefer a faster implementation (for example, Bouncy Castle) based on a small micro-benchmark.
   *
   * @return the provider name, or {@code null} if detection failed or is unavailable.
   */
  public static String getProviderName() {
    return AesCtrProvider != null ? AesCtrProvider.getName() : null;
  }

  /**
   * Returns the selected JCA {@link Provider} for {@code AES/CTR/NoPadding}, or {@code null} when
   * no suitable provider was detected.
   *
   * <p>This accessor is provided for components that need to construct JCA ciphers with the same
   * provider decision as this class.
   *
   * @return the chosen provider, or {@code null} if none was selected.
   */
  public static Provider getAesCtrProvider() {
    return nullIfEmptyProvider(resolveConfiguredProvider());
  }

  private static Provider resolveConfiguredProvider() {
    Provider configuredProvider = AesCtrProvider;
    if (configuredProvider == null) {
      return EMPTY_PROVIDER;
    }
    Provider resolvedProvider = Security.getProvider(configuredProvider.getName());
    return resolvedProvider == null ? EMPTY_PROVIDER : resolvedProvider;
  }

  private static Provider nullIfEmptyProvider(Provider provider) {
    return provider instanceof EmptyProvider ? null : provider;
  }

  private static final class EmptyProvider extends Provider {
    private EmptyProvider() {
      super("EmptyProvider", "1.0", "Placeholder for unavailable provider");
    }
  }

  private static long benchmark(Cipher cipher, SecretKeySpec key) throws GeneralSecurityException {
    long times = Long.MAX_VALUE;
    byte[] input = new byte[1024];
    byte[] output = new byte[input.length * 32];
    cipher.init(Cipher.ENCRYPT_MODE, key, randomIv());
    // warm-up
    for (int i = 0; i < 32; i++) {
      cipher.doFinal(input, 0, input.length, output, 0);
      System.arraycopy(output, 0, input, 0, input.length);
    }
    for (int i = 0; i < 128; i++) {
      long startTime = System.nanoTime();
      cipher.init(Cipher.ENCRYPT_MODE, key, randomIv());
      for (int j = 0; j < 4; j++) {
        int ofs = 0;
        for (int k = 0; k < 32; k++) {
          ofs += cipher.update(input, 0, input.length, output, ofs);
        }
        cipher.doFinal(output, ofs);
      }
      long endTime = System.nanoTime();
      times = Math.min(endTime - startTime, times);
      System.arraycopy(output, 0, input, 0, input.length);
    }
    return times;
  }

  /**
   * Detects a JCA provider for {@code AES/CTR/NoPadding} and verifies 256-bit key support.
   *
   * <p>If detection succeeds, the provider may be compared against Bouncy Castle (when available)
   * using a short benchmark, preferring the faster provider. Returns {@code null} when detection
   * fails (for example, if the runtime restricts key sizes to 128 bits).
   *
   * @return the selected provider, or {@code null} when unavailable.
   */
  private static Provider detectAesCtrProvider() {
    Provider provider = null;
    try {
      final String algo = "AES/CTR/NOPADDING";
      final Provider bcastle = JceLoader.getBouncyCastle();

      byte[] key = new byte[32]; // Verify that 256-bit keys are permitted.
      byte[] plaintext = new byte[16];
      SecretKeySpec k = new SecretKeySpec(key, "AES");

      Cipher c = Cipher.getInstance(algo);
      c.init(Cipher.ENCRYPT_MODE, k, randomIv());
      // Resolve the default provider by initializing the cipher once.
      provider = c.getProvider();
      if (bcastle != null) {
        // Optionally prefer Bouncy Castle when it benchmarks faster.
        provider = maybeUseBouncyCastleProvider(algo, bcastle, provider, k);
      }
      c = Cipher.getInstance(algo, provider);
      c.init(Cipher.ENCRYPT_MODE, k, randomIv());
      c.doFinal(plaintext);
      LOG.info("Using JCA: provider {}", provider);
    } catch (GeneralSecurityException e) {
      LOG.warn(
          "Not using JCA as it is crippled (can't use 256-bit keys). Will use built-in encryption."
              + " ",
          e);
    }
    return provider;
  }

  // Provider detection/benchmarking does not require unpredictable IVs. Use a fixed IV to avoid
  // blocking entropy sources during class initialization. This IV is never used for real data.
  private static final IvParameterSpec DETECT_IV = new IvParameterSpec(new byte[16]);

  private static IvParameterSpec randomIv() {
    return DETECT_IV;
  }

  @SuppressWarnings({"SameParameterValue", "java:S1181"})
  private static Provider maybeUseBouncyCastleProvider(
      String algo, Provider bcastle, Provider currentProvider, SecretKeySpec key) {
    try {
      Cipher current = Cipher.getInstance(algo, currentProvider);
      current.init(Cipher.ENCRYPT_MODE, key, randomIv());

      Cipher bouncy = Cipher.getInstance(algo, bcastle);
      bouncy.init(Cipher.ENCRYPT_MODE, key, randomIv());

      Provider bouncyProvider = bouncy.getProvider();
      if (Objects.equals(currentProvider, bouncyProvider)) return currentProvider;

      long timeDef = benchmark(current, key);
      long timeBouncy = benchmark(bouncy, key);
      LOG.debug("{}/{}: {}ns", algo, currentProvider, timeDef);
      LOG.debug("{}/{}: {}ns", algo, bouncyProvider, timeBouncy);
      return (timeBouncy < timeDef) ? bouncyProvider : currentProvider;
    } catch (GeneralSecurityException e) {
      LOG.warn("{}@{} benchmark failed", algo, bcastle, e);
      return currentProvider;
    } catch (Throwable t) {
      LOG.error("{}@{} benchmark failed", algo, bcastle, t);
      return currentProvider;
    }
  }

  /**
   * Constructs a Rijndael cipher with the given key and block sizes.
   *
   * <p>Supported key sizes are 128, 192, and 256 bits. Supported block sizes are 128 and 256 bits.
   * The instance stores the key schedule after {@link #initialize(byte[])} is called.
   *
   * @param keysize the key size in bits; must be 128, 192, or 256.
   * @param blocksize the block size in bits; must be 128 or 256.
   * @throws UnsupportedCipherException if either size is not supported.
   */
  public Rijndael(int keysize, int blocksize) throws UnsupportedCipherException {
    if (!((keysize == 128) || (keysize == 192) || (keysize == 256)))
      throw new UnsupportedCipherException("Invalid keysize");
    if (!((blocksize == 128) || (blocksize == 256)))
      throw new UnsupportedCipherException("Invalid blocksize");
    this.keysize = keysize;
    this.blocksize = blocksize;
  }

  // No-arg constructor for reflective instantiation (e.g., Util.getCipherByName).
  public Rijndael() {
    this.keysize = 128;
    this.blocksize = 128;
  }

  /**
   * Returns the block size in bits for this instance.
   *
   * @return the block size in bits (128 or 256).
   */
  @Override
  public final int getBlockSize() {
    return blocksize;
  }

  /**
   * Returns the configured key size in bits for this instance.
   *
   * @return the key size in bits (128, 192, or 256).
   */
  @Override
  public final int getKeySize() {
    return keysize;
  }

  /**
   * Initializes the cipher with a raw key.
   *
   * <p>Only the first {@code keySize/8} bytes of {@code key} are used; excess bytes are ignored.
   * The derived key schedule is stored in the instance for later operations.
   *
   * @param key the raw key material; must contain at least {@code keySize/8} bytes.
   */
  @Override
  public final void initialize(byte[] key) {
    try {
      byte[] nkey = new byte[keysize >> 3];
      System.arraycopy(key, 0, nkey, 0, nkey.length);
      sessionKey = RijndaelAlgorithm.makeKey(nkey, blocksize / 8);
    } catch (InvalidKeyException e) {
      LOG.error("Invalid key", e);
    }
  }

  /**
   * Encrypts one block.
   *
   * <p>Both {@code block} and {@code result} must be exactly {@code blockSize/8} bytes long.
   *
   * @param block the plaintext block to encrypt.
   * @param result the destination buffer for the ciphertext.
   * @throws IllegalArgumentException if {@code block.length != blockSize/8}.
   */
  @Override
  public final void encipher(byte[] block, byte[] result) {
    if (block.length != blocksize / 8) throw new IllegalArgumentException();
    RijndaelAlgorithm.blockEncrypt(block, result, 0, sessionKey, blocksize / 8);
  }

  /**
   * Decrypts one block.
   *
   * <p>Both {@code block} and {@code result} must be exactly {@code blockSize/8} bytes long.
   *
   * @param block the ciphertext block to decrypt.
   * @param result the destination buffer for the plaintext.
   * @throws IllegalArgumentException if {@code block.length != blockSize/8}.
   */
  @Override
  public final void decipher(byte[] block, byte[] result) {
    if (block.length != blocksize / 8) throw new IllegalArgumentException();
    RijndaelAlgorithm.blockDecrypt(block, result, 0, sessionKey, blocksize / 8);
  }
}
