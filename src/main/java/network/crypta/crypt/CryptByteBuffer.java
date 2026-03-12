package network.crypta.crypt;

import java.io.Serial;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import network.crypta.support.Fields;

/**
 * Symmetric byte/Buffer encryption and decryption with stream-like semantics.
 *
 * <p>This utility encrypts and decrypts {@code byte[]} and {@link ByteBuffer} data using the
 * algorithm parameters provided by {@link CryptByteBufferType}. The transformation is
 * size-preserving: ciphertext has the same length as plaintext. This is achieved by using stream
 * ciphers or block ciphers in a non-padded stream mode (for example, CTR), and therefore inputs do
 * not require padding.
 *
 * <p>Instances maintain internal positions for the encrypt and decrypt paths. Successive calls
 * continue from the previous position, so encrypting the same input twice with the same instance
 * does not yield the same output. This state is included in the serialized form and is restored on
 * deserialization to preserve keystream continuity.
 *
 * <p>Thread-safety: This class is NOT thread-safe. Do not share one instance across threads or use
 * a single instance for multiple independent streams. Create a new instance per independent stream
 * or reset the IV as appropriate for the chosen {@link CryptByteBufferType}.
 *
 * @author unixninja92
 *     <p>Suggested {@link CryptByteBufferType}: {@link CryptByteBufferType#CHACHA_128}
 */
public final class CryptByteBuffer implements Serializable {
  @Serial private static final long serialVersionUID = 6143338995971755362L;
  private final CryptByteBufferType type;
  private final SecretKey key;
  // IvParameterSpec itself is not guaranteed to be Serializable; persist raw bytes alongside.
  private transient IvParameterSpec iv;
  private byte[] ivBytes; // serialized form of IV; null when type.hasIV() == false

  // Cipher instances for the configured algorithm (e.g., AES-CTR or ChaCha20).
  private transient Cipher encryptCipher;
  private transient Cipher decryptCipher;

  // Track processed-byte positions so we can resume keystreams after deserialization.
  private long encryptPos;
  private long decryptPos;

  // Only stream-style algorithms are supported here; Rijndael/PCFB is not supported.

  /**
   * Creates an encrypt/decrypt context for the given type, key, and optional IV.
   *
   * <p>If the {@link CryptByteBufferType} requires an IV and {@code iv} is {@code null}, a random
   * IV is generated via {@link #genIV()}. If the type does not use an IV and a non-{@code null}
   * {@code iv} is provided, an {@link UnsupportedTypeException} is thrown.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Secret key; must be non-null and valid for {@code type}.
   * @param iv Initialization vector to use when {@code type.hasIV()} is true; may be {@code null}
   *     to auto-generate.
   * @throws InvalidAlgorithmParameterException If the IV is the wrong size for {@code type}.
   * @throws InvalidKeyException If {@code key} is not acceptable for {@code type}.
   * @throws UnsupportedTypeException If an IV is provided for a type that does not use IVs.
   * @throws NullPointerException If {@code type} or {@code key} is {@code null}.
   */
  public CryptByteBuffer(CryptByteBufferType type, SecretKey key, IvParameterSpec iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    this.type = Objects.requireNonNull(type, "type");
    this.key = Objects.requireNonNull(key, "key");

    if (iv != null && !this.type.hasIV()) {
      throw new UnsupportedTypeException(this.type, "This type does not take an IV.");
    } else if (iv != null) {
      this.iv = iv;
      this.ivBytes = Arrays.copyOf(iv.getIV(), iv.getIV().length);
    } else if (this.type.hasIV()) {
      genIV();
    }
    try {
      encryptCipher = Cipher.getInstance(this.type.algName);
      decryptCipher = Cipher.getInstance(this.type.algName);

      encryptCipher.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
      decryptCipher.init(Cipher.DECRYPT_MODE, this.key, this.iv);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      // Should be impossible with bundled provider and non-padded modes
      throw new IllegalStateException(e);
    }
  }

  /**
   * Creates a context for the given type and key, generating a random IV when required.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Secret key; must be non-null and valid for {@code type}.
   * @throws GeneralSecurityException If the key or generated IV is not acceptable.
   * @throws NullPointerException If {@code type} or {@code key} is {@code null}.
   */
  public CryptByteBuffer(CryptByteBufferType type, SecretKey key) throws GeneralSecurityException {
    this(type, key, (IvParameterSpec) null);
  }

  /**
   * Creates a context from a raw key, generating a random IV when required.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Raw key bytes; length must be valid for {@code type.keyType}.
   * @throws GeneralSecurityException If the key is not acceptable or IV generation fails.
   * @throws NullPointerException If {@code type} or {@code key} is {@code null}.
   */
  public CryptByteBuffer(CryptByteBufferType type, byte[] key) throws GeneralSecurityException {
    this(type, KeyGenUtils.getSecretKey(type.keyType, key));
  }

  /**
   * Creates a context from a key held in a {@link ByteBuffer}, generating a random IV when
   * required.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Buffer containing raw key bytes; only the readable portion is consumed.
   * @throws GeneralSecurityException If the key is not acceptable or IV generation fails.
   * @throws NullPointerException If {@code type} or {@code key} is {@code null}.
   */
  @SuppressWarnings("unused")
  public CryptByteBuffer(CryptByteBufferType type, ByteBuffer key) throws GeneralSecurityException {
    this(type, Fields.copyToArray(key));
  }

  /**
   * Creates a context for the given type, key, and IV stored within a byte array slice.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Secret key; must be non-null and valid for {@code type}.
   * @param iv Array containing IV bytes.
   * @param offset Offset within {@code iv} where the IV begins; {@code type.ivSize} bytes are used.
   * @throws InvalidKeyException If {@code key} is not acceptable for {@code type}.
   * @throws InvalidAlgorithmParameterException If the IV slice length is incorrect.
   * @throws UnsupportedTypeException If the type does not use an IV.
   * @throws NullPointerException If {@code type}, {@code key}, or {@code iv} is {@code null}.
   */
  public CryptByteBuffer(CryptByteBufferType type, SecretKey key, byte[] iv, int offset)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    this(type, key, new IvParameterSpec(iv, offset, type.ivSize));
  }

  /**
   * Creates a context for the given type, key, and IV stored in a contiguous array.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Secret key; must be non-null and valid for {@code type}.
   * @param iv IV bytes; length must equal {@code type.ivSize}.
   * @throws InvalidAlgorithmParameterException If the IV length is incorrect.
   * @throws InvalidKeyException If {@code key} is not acceptable for {@code type}.
   * @throws UnsupportedTypeException If the type does not use an IV.
   * @throws NullPointerException If {@code type}, {@code key}, or {@code iv} is {@code null}.
   */
  public CryptByteBuffer(CryptByteBufferType type, SecretKey key, byte[] iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    this(type, key, iv, 0);
  }

  /**
   * Creates a context for the given type, key, and IV stored in a {@link ByteBuffer}.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Secret key; must be non-null and valid for {@code type}.
   * @param iv Buffer containing IV bytes; only the readable portion is consumed.
   * @throws InvalidAlgorithmParameterException If the IV length is incorrect.
   * @throws InvalidKeyException If {@code key} is not acceptable for {@code type}.
   * @throws UnsupportedTypeException If the type does not use an IV.
   * @throws NullPointerException If {@code type}, {@code key}, or {@code iv} is {@code null}.
   */
  @SuppressWarnings("unused")
  public CryptByteBuffer(CryptByteBufferType type, SecretKey key, ByteBuffer iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    this(type, key, Fields.copyToArray(iv), 0);
  }

  /**
   * Creates a context from raw key bytes and an IV provided via a slice of an array.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Raw key bytes; length must be valid for {@code type.keyType}.
   * @param iv Array containing IV bytes.
   * @param offset Offset within {@code iv} where the IV begins; {@code type.ivSize} bytes are used.
   * @throws InvalidKeyException If {@code key} is not acceptable for {@code type}.
   * @throws InvalidAlgorithmParameterException If the IV slice length is incorrect.
   * @throws UnsupportedTypeException If the type does not use an IV.
   * @throws NullPointerException If {@code type}, {@code key}, or {@code iv} is {@code null}.
   */
  public CryptByteBuffer(CryptByteBufferType type, byte[] key, byte[] iv, int offset)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    this(type, KeyGenUtils.getSecretKey(type.keyType, key), iv, offset);
  }

  /**
   * Creates a context from raw key bytes and an IV stored in a contiguous array.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Raw key bytes; length must be valid for {@code type.keyType}.
   * @param iv IV bytes; length must equal {@code type.ivSize}.
   * @throws InvalidAlgorithmParameterException If the IV length is incorrect.
   * @throws InvalidKeyException If {@code key} is not acceptable for {@code type}.
   * @throws UnsupportedTypeException If the type does not use an IV.
   * @throws NullPointerException If {@code type}, {@code key}, or {@code iv} is {@code null}.
   */
  public CryptByteBuffer(CryptByteBufferType type, byte[] key, byte[] iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    this(type, key, iv, 0);
  }

  /**
   * Creates a context from a key and IV both held in {@link ByteBuffer} instances.
   *
   * @param type Algorithm and size parameters to use; must be non-null.
   * @param key Buffer containing raw key bytes; only the readable portion is consumed.
   * @param iv Buffer containing IV bytes; only the readable portion is consumed.
   * @throws InvalidAlgorithmParameterException If the IV length is incorrect.
   * @throws InvalidKeyException If {@code key} is not acceptable for {@code type}.
   * @throws UnsupportedTypeException If the type does not use an IV.
   * @throws NullPointerException If {@code type}, {@code key}, or {@code iv} is {@code null}.
   */
  @SuppressWarnings("unused")
  public CryptByteBuffer(CryptByteBufferType type, ByteBuffer key, ByteBuffer iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    this(type, Fields.copyToArray(key), Fields.copyToArray(iv), 0);
  }

  /**
   * Encrypts a range from {@code input} into {@code output} without modifying {@code input}.
   *
   * @param input Source array containing plaintext bytes.
   * @param offset Index of the first byte to encrypt in {@code input}.
   * @param len Number of bytes to encrypt.
   * @param output Destination array to receive ciphertext.
   * @param outputOffset Index in {@code output} to place the first ciphertext byte.
   * @throws IllegalArgumentException If the source range is invalid or if the destination is too
   *     small for the requested output.
   * @throws IllegalStateException If the underlying transformation does not behave like a stream
   *     (should not occur for supported types).
   */
  public void encrypt(byte[] input, int offset, int len, byte[] output, int outputOffset) {
    if (offset + len > input.length) throw new IllegalArgumentException();
    if (input == output && offset != outputOffset) {
      // Copy via temporary buffer when source and destination ranges may overlap.
      byte[] temp = Arrays.copyOfRange(input, offset, offset + len);
      encrypt(temp, 0, temp.length);
      System.arraycopy(temp, 0, output, outputOffset, len);
      return;
    }
    try {
      int copied = encryptCipher.update(input, offset, len, output, outputOffset);
      if (copied != len) throw new IllegalStateException("Not a stream cipher???");
      encryptPos += copied;
    } catch (ShortBufferException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Encrypts a range of {@code input} in place.
   *
   * @param input Array to modify with ciphertext.
   * @param offset Index of the first byte to encrypt.
   * @param len Number of bytes to encrypt.
   * @throws IllegalArgumentException If the specified range is invalid.
   */
  public void encrypt(byte[] input, int offset, int len) {
    encrypt(input, offset, len, input, offset);
  }

  /**
   * Encrypts a slice of {@code input} and returns a newly allocated array containing the result.
   *
   * @param input Bytes to encrypt. Contents are not modified.
   * @param offset Starting index in {@code input}.
   * @param len Number of bytes to encrypt.
   * @return Newly allocated ciphertext array of length {@code len}.
   * @throws IllegalArgumentException If the specified range is invalid.
   */
  public byte[] encryptCopy(byte[] input, int offset, int len) {
    byte[] output = Arrays.copyOfRange(input, offset, offset + len);
    encrypt(input, offset, len, output, 0);
    return output;
  }

  /**
   * Encrypts all bytes from {@code input} and returns a new array.
   *
   * @param input Bytes to encrypt.
   * @return Newly allocated ciphertext array; {@code input} is not modified.
   */
  public byte[] encryptCopy(byte[] input) {
    return encryptCopy(input, 0, input.length);
  }

  /**
   * Encrypts the readable portion of {@code input} and returns a new {@link ByteBuffer}.
   *
   * <p>Only bytes in the range {@code [position, limit)} are read. The returned buffer has a
   * backing array, position {@code 0}, and capacity equal to the number of bytes encrypted.
   *
   * @param input Buffer to encrypt.
   * @return Newly allocated buffer containing ciphertext.
   */
  public ByteBuffer encryptCopy(ByteBuffer input) {
    if (input.hasArray())
      return ByteBuffer.wrap(
          encryptCopy(input.array(), input.arrayOffset() + input.position(), input.remaining()));
    else {
      return ByteBuffer.wrap(encryptCopy(Fields.copyToArray(input)));
    }
  }

  /**
   * Encrypts bytes from {@code input} into {@code output}.
   *
   * <p>At most {@code min(input.remaining(), output.remaining())} bytes are processed. Both buffer
   * positions advance by the number of bytes written. When both buffers have backing arrays, the
   * operation is performed on the arrays; otherwise, {@link Cipher#update(ByteBuffer, ByteBuffer)}
   * is used.
   *
   * @param input Source buffer containing plaintext.
   * @param output Destination buffer to receive ciphertext.
   * @throws IllegalStateException If {@code output} has insufficient remaining space.
   */
  public void encrypt(ByteBuffer input, ByteBuffer output) {
    if (input.hasArray() && output.hasArray()) {
      int moved = Math.min(input.remaining(), output.remaining());
      encrypt(
          input.array(),
          input.arrayOffset() + input.position(),
          moved,
          output.array(),
          output.arrayOffset() + output.position());
      input.position(input.position() + moved);
      output.position(output.position() + moved);
    } else {
      // Use ByteBuffer to ByteBuffer operations.
      try {
        int copy = Math.min(input.remaining(), output.remaining());
        int copied = encryptCipher.update(input, output);
        if (copied != copy) throw new IllegalStateException("Not a stream cipher???");
        encryptPos += copied;
      } catch (ShortBufferException e) {
        throw new IllegalStateException("Buffer too small for ByteBuffer update", e);
      }
    }
  }

  // BitSet-based helpers are not provided; prefer byte[]/ByteBuffer variants.

  /**
   * Decrypts a range from {@code input} into {@code output} without modifying {@code input}.
   *
   * @param input Source array containing ciphertext bytes.
   * @param offset Index of the first byte to decrypt in {@code input}.
   * @param len Number of bytes to decrypt.
   * @param output Destination array to receive plaintext.
   * @param outputOffset Index in {@code output} to place the first plaintext byte.
   * @throws IllegalArgumentException If the source range is invalid or if the destination is too
   *     small for the requested output.
   * @throws IllegalStateException If the underlying transformation does not behave like a stream
   *     (should not occur for supported types).
   */
  public void decrypt(byte[] input, int offset, int len, byte[] output, int outputOffset) {
    if (offset + len > input.length) throw new IllegalArgumentException();
    if (input == output && offset != outputOffset) {
      // Copy via temporary buffer when source and destination ranges may overlap.
      byte[] temp = Arrays.copyOfRange(input, offset, offset + len);
      decrypt(temp, 0, temp.length);
      System.arraycopy(temp, 0, output, outputOffset, len);
      return;
    }
    try {
      int copied = decryptCipher.update(input, offset, len, output, outputOffset);
      if (copied != len) throw new IllegalStateException("Not a stream cipher???");
      decryptPos += copied;
    } catch (ShortBufferException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Decrypts a range of {@code input} in place.
   *
   * @param input Array to modify with plaintext.
   * @param offset Index of the first byte to decrypt.
   * @param len Number of bytes to decrypt.
   * @throws IllegalArgumentException If the specified range is invalid.
   */
  public void decrypt(byte[] input, int offset, int len) {
    decrypt(input, offset, len, input, offset);
  }

  /**
   * Decrypts a slice of {@code input} and returns a newly allocated array containing the plaintext.
   *
   * @param input Bytes to decrypt. Contents are not modified.
   * @param offset Starting index in {@code input}.
   * @param len Number of bytes to decrypt.
   * @return Newly allocated plaintext array of length {@code len}.
   * @throws IllegalArgumentException If the specified range is invalid.
   */
  public byte[] decryptCopy(byte[] input, int offset, int len) {
    byte[] output = Arrays.copyOfRange(input, offset, offset + len);
    decrypt(input, offset, len, output, 0);
    return output;
  }

  /**
   * Decrypts all bytes from {@code input} and returns a new array.
   *
   * @param input Bytes to decrypt.
   * @return Newly allocated plaintext array.
   */
  public byte[] decryptCopy(byte[] input) {
    return decryptCopy(input, 0, input.length);
  }

  /**
   * Decrypts the readable portion of {@code input} and returns a new {@link ByteBuffer}.
   *
   * <p>Only bytes in the range {@code [position, limit)} are read. The returned buffer has a
   * backing array, position {@code 0}, and capacity equal to the number of bytes decrypted.
   *
   * @param input Buffer to decrypt.
   * @return Newly allocated buffer containing plaintext.
   */
  public ByteBuffer decryptCopy(ByteBuffer input) {
    if (input.hasArray())
      return ByteBuffer.wrap(
          decryptCopy(input.array(), input.arrayOffset() + input.position(), input.remaining()));
    else return ByteBuffer.wrap(decryptCopy(Fields.copyToArray(input)));
  }

  /**
   * Decrypts bytes from {@code input} into {@code output}.
   *
   * <p>At most {@code min(input.remaining(), output.remaining())} bytes are processed. Both buffer
   * positions advance by the number of bytes written. When both buffers have backing arrays, the
   * operation is performed on the arrays; otherwise, {@link Cipher#update(ByteBuffer, ByteBuffer)}
   * is used.
   *
   * @param input Source buffer containing ciphertext.
   * @param output Destination buffer to receive plaintext.
   * @throws IllegalStateException If {@code output} has insufficient remaining space.
   */
  public void decrypt(ByteBuffer input, ByteBuffer output) {
    if (input.hasArray() && output.hasArray()) {
      int moved = Math.min(input.remaining(), output.remaining());
      decrypt(
          input.array(),
          input.arrayOffset() + input.position(),
          moved,
          output.array(),
          output.arrayOffset() + output.position());
      input.position(input.position() + moved);
      output.position(output.position() + moved);
    } else {
      // Use ByteBuffer to ByteBuffer operations.
      try {
        int copy = Math.min(input.remaining(), output.remaining());
        int copied = decryptCipher.update(input, output);
        if (copied != copy) throw new IllegalStateException("Not a stream cipher???");
        decryptPos += copied;
      } catch (ShortBufferException e) {
        throw new IllegalStateException("Buffer too small for ByteBuffer update", e);
      }
    }
  }

  // BitSet-based helpers are not provided; prefer byte[]/ByteBuffer variants.

  /**
   * Sets a new IV and reinitializes the ciphers.
   *
   * <p>Resets the internal stream positions for both encrypt and decrypt paths to {@code 0}.
   *
   * @param iv New IV value.
   * @throws InvalidAlgorithmParameterException If the IV length is incorrect for the configured
   *     type.
   * @throws UnsupportedTypeException If the configured type does not use an IV.
   */
  public void setIV(IvParameterSpec iv) throws InvalidAlgorithmParameterException {
    if (!type.hasIV()) {
      throw new UnsupportedTypeException(type);
    }
    this.iv = iv;
    this.ivBytes = (iv == null ? null : Arrays.copyOf(iv.getIV(), iv.getIV().length));
    try {
      ensureCiphersInitialized();
      encryptCipher.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
      decryptCipher.init(Cipher.DECRYPT_MODE, this.key, this.iv);
      // Reset stream positions when IV changes.
      this.encryptPos = 0L;
      this.decryptPos = 0L;
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Generates a new IV and reinitializes the ciphers.
   *
   * <p>Resets the internal stream positions for both encrypt and decrypt paths to {@code 0}.
   *
   * @return The generated IV.
   * @throws UnsupportedTypeException If the configured type does not use an IV.
   */
  public IvParameterSpec genIV() {
    if (!type.hasIV()) {
      throw new UnsupportedTypeException(type);
    }
    this.iv = KeyGenUtils.genIV(type.ivSize);
    this.ivBytes = Arrays.copyOf(this.iv.getIV(), this.iv.getIV().length);
    try {
      ensureCiphersInitialized();
      encryptCipher.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
      decryptCipher.init(Cipher.DECRYPT_MODE, this.key, this.iv);
      // Reset stream positions when IV changes.
      this.encryptPos = 0L;
      this.decryptPos = 0L;
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException(e); // Definitely a bug ...
    }
    return iv;
  }

  /** Lazily create cipher instances when absent (e.g., after deserialization). */
  private void ensureCiphersInitialized() {
    if (encryptCipher == null || decryptCipher == null) {
      try {
        encryptCipher = Cipher.getInstance(this.type.algName);
        decryptCipher = Cipher.getInstance(this.type.algName);
      } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  /**
   * Returns the current IV.
   *
   * <p>Only valid for types that use an IV.
   *
   * @return The current IV.
   * @throws UnsupportedTypeException If the configured type does not use an IV.
   */
  public IvParameterSpec getIV() {
    if (!type.hasIV()) {
      throw new UnsupportedTypeException(type);
    }
    return iv;
  }

  /**
   * Custom deserialization: restore IV and rebuild cipher instances after transient fields are lost
   * during serialization.
   */
  @Serial
  private void readObject(java.io.ObjectInputStream in)
      throws java.io.IOException, ClassNotFoundException {
    in.defaultReadObject();
    try {
      // Recreate IV from serialized bytes when applicable
      if (type.hasIV()) {
        if (ivBytes == null || ivBytes.length != type.ivSize) {
          throw new java.io.InvalidObjectException("Missing or wrong-sized IV bytes");
        }
        this.iv = new IvParameterSpec(Arrays.copyOf(ivBytes, ivBytes.length));
      } else {
        this.iv = null;
      }

      // Recreate cipher instances and initialize them
      encryptCipher = Cipher.getInstance(this.type.algName);
      decryptCipher = Cipher.getInstance(this.type.algName);
      if (type.hasIV()) {
        encryptCipher.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
        decryptCipher.init(Cipher.DECRYPT_MODE, this.key, this.iv);
      } else {
        encryptCipher.init(Cipher.ENCRYPT_MODE, this.key);
        decryptCipher.init(Cipher.DECRYPT_MODE, this.key);
      }

      // Advance ciphers to their previous stream positions to preserve continuity.
      advanceCipher(encryptCipher, encryptPos);
      advanceCipher(decryptCipher, decryptPos);
    } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
      throw new java.io.InvalidObjectException("Cipher algorithm unavailable: " + e);
    } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
      throw new java.io.InvalidObjectException("Failed to init ciphers: " + e);
    }
  }

  /** Advance a stream cipher by 'bytes' by encrypting zero bytes and discarding output. */
  private static void advanceCipher(Cipher cipher, long bytes) {
    if (bytes <= 0) return;
    final int CHUNK = 8192;
    final byte[] zeros = new byte[CHUNK];
    final byte[] out = new byte[CHUNK];
    long remaining = bytes;
    try {
      while (remaining > 0) {
        int copy = (int) Math.min(remaining, CHUNK);
        int produced = cipher.update(zeros, 0, copy, out, 0);
        if (produced != copy)
          throw new IllegalStateException("Stream cipher did not produce expected bytes");
        remaining -= produced;
      }
    } catch (ShortBufferException e) {
      throw new IllegalStateException("Failed to advance cipher state", e);
    }
  }
}
