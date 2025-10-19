package network.crypta.crypt;

/**
 * Contract for symmetric block ciphers.
 *
 * <p>This interface abstracts a raw block cipher: initialization with a key, queries for key and
 * block sizes (in bits), and single-block encipher/decipher operations. It does not define padding
 * or modes of operation.
 */
public interface BlockCipher {

  /**
   * Initializes the cipher with the provided key.
   *
   * <p>Implementations typically perform any key-schedule work here (for example, computing subkeys
   * or lookup tables). The expected key length is algorithm-specific; callers should pass a
   * non-null array of the appropriate length (commonly {@code getKeySize()/8}).
   *
   * @param key raw secret key bytes; must be non-null and of a supported length.
   */
  void initialize(byte[] key);

  /**
   * Returns the key size in bits expected by this cipher.
   *
   * @return key size in bits.
   */
  int getKeySize();

  /**
   * Returns the block size in bits.
   *
   * @return block size in bits.
   */
  int getBlockSize();

  /**
   * Encrypts exactly one block.
   *
   * <p>The {@code block} array must contain {@code getBlockSize()/8} bytes starting at offset 0.
   * The {@code result} array must have at least {@code getBlockSize()/8} bytes available starting
   * at offset 0. The same array may be supplied for both parameters. Implementations may overwrite
   * the contents of {@code block} during processing.
   *
   * @param block input buffer containing one plaintext block.
   * @param result output buffer that receives one ciphertext block.
   */
  void encipher(byte[] block, byte[] result);

  /**
   * Decrypts exactly one block.
   *
   * <p>The {@code block} array must contain {@code getBlockSize()/8} bytes starting at offset 0.
   * The {@code result} array must have at least {@code getBlockSize()/8} bytes available starting
   * at offset 0. The same array may be supplied for both parameters. Implementations may overwrite
   * the contents of {@code block} during processing.
   *
   * @param block input buffer containing one ciphertext block.
   * @param result output buffer that receives one plaintext block.
   */
  void decipher(byte[] block, byte[] result);
}
