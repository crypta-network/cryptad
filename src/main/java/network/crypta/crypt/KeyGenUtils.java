package network.crypta.crypt;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import network.crypta.node.NodeStarter;
import network.crypta.support.Fields;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Utility methods for generating and converting cryptographic keys and IVs.
 *
 * <p>This class provides helpers to:
 *
 * <ul>
 *   <li>Generate asymmetric {@link KeyPair}s for supported algorithms.
 *   <li>Generate symmetric {@link SecretKey}s for a given {@link KeyType}.
 *   <li>Wrap encoded keys (byte array or {@link ByteBuffer}) into {@link PublicKey}, {@link
 *       PrivateKey}, or {@link KeyPair} instances.
 *   <li>Create random nonces and initialization vectors (IVs).
 *   <li>Derive keys and IVs via HMAC‑SHA‑512 using a caller‑provided context string.
 * </ul>
 *
 * <p>Overloads accepting {@link ByteBuffer} read the buffer’s remaining bytes and advance the
 * buffer’s position to its limit.
 *
 * <p>On Java 7, Bouncy Castle is used explicitly for certain primitives; newer runtimes use the
 * default JCE provider resolution.
 *
 * @author unixninja92
 */
public final class KeyGenUtils {

  private static final BouncyCastleProvider bcProvider = new BouncyCastleProvider();

  private KeyGenUtils() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Returns the Java major version as an integer.
   *
   * <p>Examples: {@code 8}, {@code 9}, {@code 11}, {@code 21}.
   *
   * @return the Java major version (e.g., 8, 11, 21)
   * @since 12130 from <a href="https://github.com/openstreetmap/josm/">JOSM</a>, GPLv2 or later
   */
  private static int getJavaVersion() {
    String version = System.getProperty("java.version");
    if (version.startsWith("1.")) {
      version = version.substring(2);
    }
    // Accept common version formats:
    // 1.8.0_72-ea
    // 9-ea
    // 9
    // 9.0.1
    // 21
    int dotPos = version.indexOf('.');
    int dashPos = version.indexOf('-');
    int end = version.length();
    if (dotPos > -1 && dotPos < end) {
      end = dotPos;
    }
    if (dashPos > -1 && dashPos < end) {
      end = dashPos;
    }
    return Integer.parseInt(version.substring(0, end));
  }

  private static boolean isJava7() {
    return getJavaVersion() <= 7;
  }

  /**
   * Generates a public/private key pair for the given algorithm.
   *
   * <p>DSA is not supported.
   *
   * @param type algorithm and parameter specification
   * @return generated key pair
   * @throws IllegalStateException if the algorithm is unavailable or the parameters are invalid
   */
  public static KeyPair genKeyPair(KeyPairType type) {
    if (type.spec == null) {
      throw new UnsupportedTypeException(type);
    }
    try {
      KeyPairGenerator kg;
      if (isJava7()) {
        kg = KeyPairGenerator.getInstance(type.alg, bcProvider);
      } else {
        kg = KeyPairGenerator.getInstance(type.alg);
      }
      kg.initialize(type.spec);
      return kg.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      // Should not occur for supported algorithms and specs.
      throw new IllegalStateException(e);
    }
  }

  /**
   * Decodes an X.509‑encoded public key for the specified algorithm.
   *
   * <p>DSA is not supported.
   *
   * @param type key algorithm
   * @param pub X.509‑encoded public key bytes
   * @return decoded public key
   * @throws IllegalStateException if the algorithm is unavailable
   * @throws IllegalArgumentException if the encoding is invalid for the algorithm
   */
  public static PublicKey getPublicKey(KeyPairType type, byte[] pub) {
    if (type.spec == null) {
      throw new UnsupportedTypeException(type);
    }
    try {
      KeyFactory kf;
      if (isJava7()) {
        kf = KeyFactory.getInstance(type.alg, bcProvider);
      } else {
        kf = KeyFactory.getInstance(type.alg);
      }
      X509EncodedKeySpec xks = new X509EncodedKeySpec(pub);
      return kf.generatePublic(xks);
    } catch (NoSuchAlgorithmException e) {
      // Should not occur for supported algorithms.
      throw new IllegalStateException(e);
    } catch (InvalidKeySpecException e) {
      // The provided bytes are not a valid X.509 key for the given algorithm.
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Decodes an X.509‑encoded public key from a buffer.
   *
   * <p>Reads the buffer’s remaining bytes and advances its position to the limit. DSA is not
   * supported.
   *
   * @param type key algorithm
   * @param pub buffer containing the X.509‑encoded public key
   * @return decoded public key
   */
  public static PublicKey getPublicKey(KeyPairType type, ByteBuffer pub) {
    return getPublicKey(type, Fields.copyToArray(pub));
  }

  /**
   * Wraps a decoded public key in a {@link KeyPair} with a {@code null} private key.
   *
   * <p>DSA is not supported.
   *
   * @param type key algorithm
   * @param pub X.509‑encoded public key bytes
   * @return key pair containing the public key and a {@code null} private key
   */
  public static KeyPair getPublicKeyPair(KeyPairType type, byte[] pub) {
    return getKeyPair(getPublicKey(type, pub), null);
  }

  /**
   * Wraps a decoded public key (from a buffer) in a {@link KeyPair} with a {@code null} private
   * key.
   *
   * <p>Reads the buffer’s remaining bytes and advances its position to the limit. DSA is not
   * supported.
   *
   * @param type key algorithm
   * @param pub buffer containing the X.509‑encoded public key
   * @return key pair containing the public key and a {@code null} private key
   */
  public static KeyPair getPublicKeyPair(KeyPairType type, ByteBuffer pub) {
    return getPublicKeyPair(type, Fields.copyToArray(pub));
  }

  /**
   * Decodes X.509 public and PKCS#8 private keys and returns them as a {@link KeyPair}.
   *
   * <p>DSA is not supported.
   *
   * @param type key algorithm
   * @param pub X.509‑encoded public key bytes
   * @param pri PKCS#8‑encoded private key bytes
   * @return key pair containing the decoded keys
   * @throws IllegalStateException if the algorithm is unavailable
   * @throws IllegalArgumentException if either encoding is invalid for the algorithm
   */
  public static KeyPair getKeyPair(KeyPairType type, byte[] pub, byte[] pri) {
    if (type.spec == null) {
      throw new UnsupportedTypeException(type);
    }
    try {
      KeyFactory kf;
      if (isJava7()) {
        kf = KeyFactory.getInstance(type.alg, bcProvider);
      } else {
        kf = KeyFactory.getInstance(type.alg);
      }

      PublicKey pubK = getPublicKey(type, pub);

      PKCS8EncodedKeySpec pks = new PKCS8EncodedKeySpec(pri);
      PrivateKey privK = kf.generatePrivate(pks);
      return getKeyPair(pubK, privK);
    } catch (UnsupportedTypeException | NoSuchAlgorithmException e) {
      // Should not occur for supported algorithms.
      throw new IllegalStateException(e);
    } catch (InvalidKeySpecException e) {
      // The provided bytes are not valid encodings for the given algorithm.
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Decodes keys from buffers (X.509 public, PKCS#8 private) and returns them as a {@link KeyPair}.
   *
   * <p>Reads each buffer’s remaining bytes and advances their positions to the limit. DSA is not
   * supported.
   *
   * @param type key algorithm
   * @param pub buffer containing the X.509‑encoded public key
   * @param pri buffer containing the PKCS#8‑encoded private key
   * @return key pair containing the decoded keys
   */
  public static KeyPair getKeyPair(KeyPairType type, ByteBuffer pub, ByteBuffer pri) {
    return getKeyPair(type, Fields.copyToArray(pub), Fields.copyToArray(pri));
  }

  /**
   * Constructs a {@link KeyPair} from the given keys.
   *
   * @param pubK public key
   * @param privK private key (may be {@code null})
   * @return key pair containing the provided keys
   */
  public static KeyPair getKeyPair(PublicKey pubK, PrivateKey privK) {
    return new KeyPair(pubK, privK);
  }

  /**
   * Generates a secret key for the specified symmetric algorithm.
   *
   * @param type key type (algorithm and key size)
   * @return generated secret key
   * @throws IllegalStateException if the algorithm is unavailable
   */
  public static SecretKey genSecretKey(KeyType type) {
    try {
      KeyGenerator kg;
      if (isJava7()) {
        kg = KeyGenerator.getInstance(type.alg, bcProvider);
      } else {
        kg = KeyGenerator.getInstance(type.alg);
      }
      kg.init(type.keySize);
      return kg.generateKey();
    } catch (NoSuchAlgorithmException e) {
      // Should not occur for supported algorithms.
      throw new IllegalStateException(e);
    }
  }

  /**
   * Wraps raw key bytes in a {@link SecretKey} for the specified algorithm.
   *
   * <p>For non‑HMAC algorithms, the length must match {@code type.keySize/8}. HMAC keys accept any
   * length.
   *
   * @param type key type (algorithm and key size)
   * @param key raw key bytes
   * @return secret key backed by the provided bytes
   * @throws IllegalArgumentException if the key length does not match the type (non‑HMAC)
   */
  public static SecretKey getSecretKey(KeyType type, byte[] key) {
    if (!type.name().startsWith("HMAC") && key.length != type.keySize >> 3) {
      throw new IllegalArgumentException("Key size does not match KeyType");
    }
    return new SecretKeySpec(key, type.alg);
  }

  /**
   * Wraps key material from a buffer in a {@link SecretKey} for the specified algorithm.
   *
   * <p>Reads the buffer’s remaining bytes and advances its position to the limit.
   *
   * @param type key type (algorithm and key size)
   * @param key buffer containing raw key bytes
   * @return secret key backed by the provided bytes
   */
  public static SecretKey getSecretKey(KeyType type, ByteBuffer key) {
    return getSecretKey(type, Fields.copyToArray(key));
  }

  /**
   * Generates random bytes of the requested length.
   *
   * @param length number of bytes to generate
   * @return new array filled with random bytes
   */
  private static byte[] genRandomBytes(int length) {
    byte[] randBytes = new byte[length];
    NodeStarter.getGlobalSecureRandom().nextBytes(randBytes);
    return randBytes;
  }

  /**
   * Generates a random nonce of the specified length.
   *
   * @param length number of bytes
   * @return nonce bytes wrapped in a {@link ByteBuffer}
   */
  public static ByteBuffer genNonce(int length) {
    return ByteBuffer.wrap(genRandomBytes(length));
  }

  /**
   * Generates a random initialization vector (IV) of the specified length.
   *
   * @param length IV length in bytes
   * @return IV wrapped in an {@link IvParameterSpec}
   */
  @SuppressWarnings("java:S3329")
  public static IvParameterSpec genIV(int length) {
    // Use the shared SecureRandom to avoid re-seeding overhead and potential blocking on
    // some platforms. Keep IV generation aligned with genNonce()/genRandomBytes().
    return new IvParameterSpec(genRandomBytes(length));
  }

  /**
   * Wraps a region of a byte array as an {@link IvParameterSpec}.
   *
   * @param iv source array containing the IV
   * @param offset start offset of the IV within {@code iv}
   * @param length IV length in bytes
   * @return IV view as an {@link IvParameterSpec}
   */
  public static IvParameterSpec getIvParameterSpec(byte[] iv, int offset, int length) {
    return new IvParameterSpec(iv, offset, length);
  }

  /**
   * Wraps bytes from a buffer as an {@link IvParameterSpec}.
   *
   * <p>Reads the buffer’s remaining bytes and advances its position to the limit.
   *
   * @param iv buffer containing the IV
   * @return IV view as an {@link IvParameterSpec}
   */
  @SuppressWarnings("java:S3329")
  public static IvParameterSpec getIvParameterSpec(ByteBuffer iv) {
    return new IvParameterSpec(Fields.copyToArray(iv));
  }

  /**
   * Derives 64 bytes using HMAC‑SHA‑512 of {@code className + kdfString} keyed by {@code kdfKey}.
   *
   * @param kdfKey base key used as the HMAC key
   * @param c class whose name provides context for domain separation
   * @param kdfString additional context string for domain separation
   * @return 64 derived bytes as a {@link ByteBuffer}
   * @throws InvalidKeyException if {@code kdfKey} is not valid for HMAC‑SHA‑512
   */
  private static ByteBuffer deriveBytes(SecretKey kdfKey, Class<?> c, String kdfString)
      throws InvalidKeyException {
    if (kdfString == null) {
      throw new NullPointerException();
    }
    MessageAuthCode kdf = new MessageAuthCode(MACType.HMAC_SHA512, kdfKey);
    return kdf.genMac((c.getName() + kdfString).getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Derives bytes as in {@link #deriveBytes(SecretKey, Class, String)} and truncates to {@code len}
   * bytes.
   *
   * @param kdfKey base key used as the HMAC key
   * @param c class whose name provides context for domain separation
   * @param kdfString additional context string for domain separation
   * @param len number of bytes to return
   * @return derived bytes of length {@code len}
   * @throws InvalidKeyException if {@code kdfKey} is not valid for HMAC‑SHA‑512
   */
  private static ByteBuffer deriveBytesTruncated(
      SecretKey kdfKey, Class<?> c, String kdfString, int len) throws InvalidKeyException {
    byte[] key = new byte[len];
    deriveBytes(kdfKey, c, kdfString).get(key);
    return ByteBuffer.wrap(key);
  }

  /**
   * Derives a {@link SecretKey} of the requested {@link KeyType} using HMAC‑SHA‑512.
   *
   * <p>The derivation input is {@code className + kdfString}. The output is truncated to the
   * algorithm’s key size.
   *
   * @param kdfKey base key used as the HMAC key
   * @param c class whose name provides context for domain separation
   * @param kdfString additional context string for domain separation
   * @param type target key type (algorithm and key size)
   * @return derived secret key
   * @throws InvalidKeyException if {@code kdfKey} is not valid for HMAC‑SHA‑512
   */
  public static SecretKey deriveSecretKey(
      SecretKey kdfKey, Class<?> c, String kdfString, KeyType type) throws InvalidKeyException {
    return getSecretKey(type, deriveBytesTruncated(kdfKey, c, kdfString, type.keySize >> 3));
  }

  /**
   * Derives an initialization vector (IV) using HMAC‑SHA‑512 and returns it as an {@link
   * IvParameterSpec}.
   *
   * <p>The derivation input is {@code className + kdfString}. The output is truncated to {@code
   * ivType.ivSize/8} bytes.
   *
   * @param kdfKey base key used as the HMAC key
   * @param c class whose name provides context for domain separation
   * @param kdfString additional context string for domain separation
   * @param ivType target IV type (provides the IV size)
   * @return derived IV wrapped in an {@link IvParameterSpec}
   * @throws InvalidKeyException if {@code kdfKey} is not valid for HMAC‑SHA‑512
   */
  public static IvParameterSpec deriveIvParameterSpec(
      SecretKey kdfKey, Class<?> c, String kdfString, KeyType ivType) throws InvalidKeyException {
    return getIvParameterSpec(deriveBytesTruncated(kdfKey, c, kdfString, ivType.ivSize >> 3));
  }
}
