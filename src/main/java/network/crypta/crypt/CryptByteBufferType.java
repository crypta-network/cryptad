package network.crypta.crypt;

import java.io.Serializable;

/**
 * Keeps track of properties of different symmetric cipher algorithms available to Freenet including
 * key type, name of the algorithm, block size used, and iv length if required.
 *
 * @author unixninja92
 */
public enum CryptByteBufferType implements Serializable {
  AESCTR(16, 16, "AES/CTR/NOPADDING", KeyType.AES256),
  ChaCha128(32, 8, "CHACHA", KeyType.ChaCha128),
  ChaCha256(64, 8, "CHACHA", KeyType.ChaCha256);

  /** Bitmask for aggregation. */
  public final int bitmask;

  public final int blockSize;
  public final Integer ivSize; // in bytes
  public final String algName;
  public final String cipherName;
  public final KeyType keyType;
  public final boolean isStreamCipher;

  /**
   * Creates an enum value for block ciphers without an IV.
   *
   * @param bitmask Aggregation bitmask for the type
   * @param keyType The type of key the algorithm requires
   */
  CryptByteBufferType(int bitmask, KeyType keyType) {
    this.bitmask = bitmask;
    this.keyType = keyType;
    this.cipherName = keyType.alg;
    this.blockSize = keyType.keySize;
    this.ivSize = null;
    algName = name();
    isStreamCipher = false;
  }

  /**
   * Creates an enum value for block ciphers without an IV and a custom block size.
   *
   * @param bitmask Aggregation bitmask for the type
   * @param keyType The type of key the algorithm requires
   * @param blockSize The block size used by the algorithm
   */
  CryptByteBufferType(int bitmask, KeyType keyType, int blockSize) {
    this.bitmask = bitmask;
    this.ivSize = null;
    this.keyType = keyType;
    this.cipherName = keyType.alg;
    this.blockSize = blockSize;
    algName = name();
    isStreamCipher = false;
  }

  /**
   * Creates an enum value for stream/feedback modes with a fixed IV size.
   *
   * @param bitmask Aggregation bitmask for the type
   * @param ivSize Size of the IV in bytes
   * @param keyType The type of key the algorithm requires
   */
  CryptByteBufferType(int bitmask, int ivSize, KeyType keyType) {
    this.bitmask = bitmask;
    this.keyType = keyType;
    this.cipherName = keyType.alg;
    this.blockSize = keyType.keySize;
    this.ivSize = ivSize;
    algName = name();
    isStreamCipher = true;
  }

  /**
   * Creates an enum value for the specified algorithm, key type, and IV size. Also stores the
   * provider algorithm name recognized by the JCE.
   *
   * @param bitmask Aggregation bitmask for the type
   * @param ivSize Size of the IV in bytes
   * @param algName The JCE provider algorithm name
   * @param keyType The type of key the algorithm requires
   */
  CryptByteBufferType(int bitmask, int ivSize, String algName, KeyType keyType) {
    this.bitmask = bitmask;
    this.ivSize = ivSize;
    this.cipherName = keyType.alg;
    this.blockSize = keyType.keySize;
    this.algName = algName;
    this.keyType = keyType;
    isStreamCipher = true;
  }

  /** Returns true if the algorithm supports/requires an IV, otherwise returns false. */
  public boolean hasIV() {
    return ivSize != null;
  }
}
