package network.crypta.crypt;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import network.crypta.support.Fields;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;

/**
 * Generates and verifies message authentication codes (MACs) for supplied data using a {@link
 * MACType}-selected algorithm and a secret key.
 *
 * <p>This class is a thin wrapper around a JCE {@link javax.crypto.Mac} instance. Some algorithms
 * supported by {@link MACType} require an initialization vector (IV); for those, this class can
 * generate an IV or accept one provided by the caller via {@link IvParameterSpec}.
 *
 * <p>Instances are not thread-safe. Use a separate instance per thread or add external
 * synchronization if calling from multiple threads.
 *
 * @author unixninja92
 */
public final class MessageAuthCode {
  private final MACType type;
  private final Mac mac;
  private final SecretKey key;
  private IvParameterSpec iv;

  /**
   * Creates an instance configured with the given algorithm and key. When the chosen algorithm
   * requires an IV, an IV is either generated or taken from the provided parameter.
   *
   * @param type the MAC algorithm to use
   * @param key the secret key
   * @param genIV when {@code true} and the algorithm requires an IV, generate a new IV; otherwise
   *     use {@code iv}
   * @param iv the IV to use when {@code genIV == false}; may be {@code null} when not required
   * @throws InvalidKeyException if the key is not valid for the underlying MAC implementation
   * @throws IllegalArgumentException if the IV is invalid for the selected algorithm
   */
  private MessageAuthCode(MACType type, SecretKey key, boolean genIV, IvParameterSpec iv)
      throws InvalidKeyException {
    this.type = type;
    mac = type.get();
    this.key = key;
    try {
      if (type.ivlen != -1) {
        checkPoly1305Key(key.getEncoded());
        if (genIV) {
          genIV();
        } else {
          setIV(iv);
        }
        mac.init(key, this.iv);
      } else {
        mac.init(key);
      }
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException(e); // Definitely a bug ...
    }
  }

  /**
   * Creates an instance that uses the specified algorithm and key.
   *
   * <p>Do not use this constructor for algorithms that require an IV; a specified key paired with
   * an implicit or random IV is rarely meaningful for MACs that mandate an IV.
   *
   * @param type the MAC algorithm to use
   * @param cryptoKey the secret key
   * @throws InvalidKeyException if the key is not valid for the underlying MAC implementation
   */
  public MessageAuthCode(MACType type, SecretKey cryptoKey) throws InvalidKeyException {
    this(type, cryptoKey, false, null);
  }

  /**
   * Creates an instance using the specified algorithm and a key provided as a byte array. The key
   * bytes are converted to a {@link SecretKey} with the {@link MACType#keyType}.
   *
   * <p>Do not use this constructor for algorithms that require an IV.
   *
   * @param type the MAC algorithm to use
   * @param cryptoKey the raw key bytes
   * @throws InvalidKeyException if the key is not valid for the underlying MAC implementation
   */
  public MessageAuthCode(MACType type, byte[] cryptoKey) throws InvalidKeyException {
    this(type, KeyGenUtils.getSecretKey(type.keyType, cryptoKey));
  }

  /**
   * Creates an instance using the specified algorithm and a key provided as a {@link ByteBuffer}.
   * The remaining bytes are copied and converted to a {@link SecretKey}. If the algorithm requires
   * an IV, one is generated.
   *
   * @param type the MAC algorithm to use
   * @param cryptoKey the buffer whose remaining bytes provide the raw key material
   * @throws InvalidKeyException if the key is not valid for the underlying MAC implementation
   */
  @SuppressWarnings("unused")
  public MessageAuthCode(MACType type, ByteBuffer cryptoKey) throws InvalidKeyException {
    this(type, Fields.copyToArray(cryptoKey));
  }

  /**
   * Creates an instance that uses the specified algorithm and a freshly generated secret key. If
   * the algorithm requires an IV, a new IV is generated as well.
   *
   * @param type the MAC algorithm to use
   * @throws InvalidKeyException if key generation yields a key rejected by the MAC implementation
   */
  @SuppressWarnings("unused")
  public MessageAuthCode(MACType type) throws InvalidKeyException {
    this(type, KeyGenUtils.genSecretKey(type.keyType), true, null);
  }

  /**
   * Creates an instance for the given algorithm with the specified key and IV. Use this only for
   * algorithms that require an IV.
   *
   * @param type the MAC algorithm to use
   * @param key the secret key
   * @param iv the IV to use
   * @throws InvalidKeyException if the key is not valid for the underlying MAC implementation
   * @throws IllegalArgumentException if the IV is invalid for the selected algorithm
   */
  public MessageAuthCode(MACType type, SecretKey key, IvParameterSpec iv)
      throws InvalidKeyException {
    this(type, key, false, iv);
  }

  /**
   * Creates an instance for the given algorithm with the specified key bytes and IV.
   *
   * @param type the MAC algorithm to use
   * @param key the raw key bytes
   * @param iv the IV to use
   * @throws InvalidKeyException if the key is not valid for the underlying MAC implementation
   * @throws IllegalArgumentException if the IV is invalid for the selected algorithm
   */
  public MessageAuthCode(MACType type, byte[] key, IvParameterSpec iv) throws InvalidKeyException {
    this(type, KeyGenUtils.getSecretKey(type.keyType, key), iv);
  }

  /**
   * Validates that the provided key is acceptable for the Poly1305-AES MAC.
   *
   * @param encodedKey key material to validate
   * @throws UnsupportedTypeException if {@link MACType#POLY1305_AES} is not the active type
   */
  private void checkPoly1305Key(byte[] encodedKey) {
    if (type != MACType.POLY1305_AES) {
      throw new UnsupportedTypeException(type);
    }
    Poly1305KeyGenerator.checkKey(encodedKey);
  }

  /**
   * Adds a single byte to the MAC input accumulated by this instance.
   *
   * @param input the byte to add
   */
  public void addByte(byte input) {
    mac.update(input);
  }

  /**
   * Adds one or more byte arrays to the MAC input accumulated by this instance.
   *
   * @param input the arrays to add; none may be {@code null}
   * @throws NullPointerException if any array is {@code null}
   */
  public void addBytes(byte[]... input) {
    for (byte[] b : input) {
      if (b == null) {
        throw new NullPointerException();
      }
      mac.update(b);
    }
  }

  /**
   * Adds the remaining bytes of the provided {@link ByteBuffer} to the MAC input accumulated by
   * this instance.
   *
   * <p>All bytes from {@code input.position()} up to (but not including) {@code input.limit()} are
   * processed. On return, the buffer's position equals its limit; the limit itself is unchanged.
   *
   * @param input the buffer whose remaining bytes will be read
   */
  public void addBytes(ByteBuffer input) {
    mac.update(input);
  }

  /**
   * Adds a slice of the given array to the MAC input accumulated by this instance.
   *
   * @param input the source array
   * @param offset the index of the first byte to add
   * @param len the number of bytes to add
   * @throws NullPointerException if {@code input} is {@code null}
   * @throws IndexOutOfBoundsException if {@code offset} or {@code len} are out of range for the
   *     array
   */
  public void addBytes(byte[] input, int offset, int len) {
    if (input == null) {
      throw new NullPointerException();
    }
    mac.update(input, offset, len);
  }

  /**
   * Finalizes and returns the MAC over the bytes added so far.
   *
   * <p>The underlying {@link Mac} is reset after this call (i.e., its internal state is cleared).
   * The returned buffer wraps a newly created array with offset {@code 0}.
   *
   * @return the computed MAC as a {@link ByteBuffer}
   */
  public ByteBuffer genMac() {
    return ByteBuffer.wrap(mac.doFinal());
  }

  /**
   * Computes a MAC for the provided arrays only. Any previously accumulated input is discarded
   * before processing, and the internal state is reset again after computation.
   *
   * @param input the arrays to authenticate; none may be {@code null}
   * @return the computed MAC as a {@link ByteBuffer}
   * @throws NullPointerException if any array is {@code null}
   */
  public ByteBuffer genMac(byte[]... input) {
    mac.reset();
    addBytes(input);
    return genMac();
  }

  /**
   * Computes a MAC for the remaining bytes of the provided buffer only. Any previously accumulated
   * input is discarded before processing, and the internal state is reset again after computation.
   *
   * @param input the buffer whose remaining bytes will be authenticated
   * @return the computed MAC as a {@link ByteBuffer}
   */
  public ByteBuffer genMac(ByteBuffer input) {
    mac.reset();
    addBytes(input);
    return genMac();
  }

  /**
   * Compares two MAC values for equality in constant time (to the extent provided by {@link
   * MessageDigest#isEqual(byte[], byte[])}).
   *
   * @param mac1 the first MAC value; may be {@code null}
   * @param mac2 the second MAC value; may be {@code null}
   * @return {@code true} if both are the same object or have identical contents; otherwise {@code
   *     false}
   */
  public static boolean verify(byte[] mac1, byte[] mac2) {
    /*
     * JDK 8u change (April 2015) made MessageDigest.isEqual tolerate nulls. Mimic that behavior
     * for consistency across runtimes that may not include the patch.
     * See: http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/10929#l8.13
     */
    if (mac1 == mac2) {
      return true;
    }
    if (mac1 == null || mac2 == null) {
      return false;
    }
    return MessageDigest.isEqual(mac1, mac2);
  }

  /**
   * Compares two MAC values provided as {@link ByteBuffer}s. Both buffers are fully consumed (their
   * positions advance to their limits).
   *
   * @param mac1 the first MAC value
   * @param mac2 the second MAC value
   * @return {@code true} if the MAC values are identical; otherwise {@code false}
   */
  public static boolean verify(ByteBuffer mac1, ByteBuffer mac2) {
    // Must be constant time, or as close as we can
    return MessageDigest.isEqual(Fields.copyToArray(mac1), Fields.copyToArray(mac2));
  }

  /**
   * Computes a MAC over the provided arrays and compares it to {@code otherMac} in constant time.
   * Any previously accumulated input is discarded before processing, and the internal state is
   * reset again after computation.
   *
   * @param otherMac the expected MAC value
   * @param data the data to authenticate
   * @return {@code true} if the computed MAC matches {@code otherMac}; otherwise {@code false}
   */
  public boolean verifyData(byte[] otherMac, byte[]... data) {
    return verify(Fields.copyToArray(genMac(data)), otherMac);
  }

  /**
   * Computes a MAC over the remaining bytes of {@code data} and compares it to {@code otherMac} in
   * constant time. Any previously accumulated input is discarded before processing, and the
   * internal state is reset again after computation.
   *
   * @param otherMac the expected MAC value
   * @param data the buffer whose remaining bytes are authenticated
   * @return {@code true} if the computed MAC matches {@code otherMac}; otherwise {@code false}
   */
  public boolean verifyData(ByteBuffer otherMac, ByteBuffer data) {
    return verify(genMac(data), otherMac);
  }

  /**
   * Returns the secret key associated with this instance.
   *
   * @return the key as a {@link SecretKey}
   */
  public SecretKey getKey() {
    return key;
  }

  /**
   * Returns the IV currently configured for this instance.
   *
   * <p>Only valid for algorithms that support IVs.
   *
   * @return the IV as an {@link IvParameterSpec}
   * @throws UnsupportedTypeException if the current algorithm does not use an IV
   */
  public IvParameterSpec getIv() {
    if (type.ivlen == -1) {
      throw new UnsupportedTypeException(type);
    }
    return iv;
  }

  /**
   * Replaces the current IV with the provided value.
   *
   * <p>Only valid for algorithms that support IVs.
   *
   * @param iv the new IV
   * @throws InvalidAlgorithmParameterException if the IV is not acceptable for the underlying MAC
   *     implementation
   * @throws UnsupportedTypeException if the current algorithm does not use an IV
   * @throws IllegalArgumentException if the MAC cannot be reinitialized with the provided IV
   */
  public void setIV(IvParameterSpec iv) throws InvalidAlgorithmParameterException {
    if (type.ivlen == -1) {
      throw new UnsupportedTypeException(type);
    }
    this.iv = iv;
    try {
      mac.init(key, iv);
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException(e); // Definitely a bug ...
    }
  }

  /**
   * Generates and installs a new IV for this instance.
   *
   * <p>Only valid for algorithms that support IVs.
   *
   * @return the generated IV
   * @throws UnsupportedTypeException if the current algorithm does not use an IV
   * @throws IllegalArgumentException if the MAC cannot be reinitialized with the generated IV
   */
  public IvParameterSpec genIV() {
    if (type.ivlen == -1) {
      throw new UnsupportedTypeException(type);
    }
    try {
      setIV(KeyGenUtils.genIV(type.ivlen));
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException(e); // Definitely a bug ...
    }
    return this.iv;
  }
}
