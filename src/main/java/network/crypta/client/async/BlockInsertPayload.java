package network.crypta.client.async;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;

/**
 * Immutable bundle describing the data and encoding parameters for a single block insert.
 *
 * <p>This record groups the bucket payload with the key and encoding metadata required by
 * block-level inserters such as {@link SingleBlockInserter} and {@link USKInserter}. It performs no
 * validation or defensive copying; callers are responsible for supplying valid values and for
 * ensuring the referenced bucket remains readable for the duration of the insert.
 *
 * <p>The {@code cryptoKey} array is stored by reference and compared by content for equality. Avoid
 * mutating it after construction if you rely on stable equality or hash semantics.
 *
 * @param data source bucket containing the bytes to insert; must remain readable during encoding
 * @param uri target URI that determines the key type (e.g., CHK/SSK/USK)
 * @param compressionCodec compression codec identifier; {@code -1} lets the encoder decide
 * @param isMetadata whether the content should be encoded as metadata
 * @param sourceLength uncompressed source length in bytes, or {@code -1} if unknown
 * @param cryptoAlgorithm identifier for optional per-block cryptography; {@code 0} for none
 * @param cryptoKey raw key material for {@code cryptoAlgorithm}; may be {@code null} when unused
 */
@SuppressWarnings("ArrayRecordComponent")
public record BlockInsertPayload(
    Bucket data,
    FreenetURI uri,
    short compressionCodec,
    boolean isMetadata,
    int sourceLength,
    byte cryptoAlgorithm,
    byte[] cryptoKey) {

  /**
   * Compares this payload to another for structural equality, including array contents.
   *
   * @param o candidate object to compare with this payload; may be {@code null}
   * @return {@code true} when all fields match by value; otherwise {@code false}
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o
        instanceof
        BlockInsertPayload(
            Bucket otherData,
            FreenetURI otherUri,
            short otherCompressionCodec,
            boolean otherIsMetadata,
            int otherSourceLength,
            byte otherCryptoAlgorithm,
            byte[] otherCryptoKey))) return false;
    return compressionCodec == otherCompressionCodec
        && isMetadata == otherIsMetadata
        && sourceLength == otherSourceLength
        && cryptoAlgorithm == otherCryptoAlgorithm
        && Objects.equals(data, otherData)
        && Objects.equals(uri, otherUri)
        && Arrays.equals(cryptoKey, otherCryptoKey);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * @return hash code derived from all components, including crypto key contents
   */
  @Override
  public int hashCode() {
    int result =
        Objects.hash(data, uri, compressionCodec, isMetadata, sourceLength, cryptoAlgorithm);
    result = 31 * result + Arrays.hashCode(cryptoKey);
    return result;
  }

  /**
   * Returns a descriptive string including the crypto key contents.
   *
   * @return a non-null string representation of this payload
   */
  @Override
  public @NotNull String toString() {
    return "BlockInsertPayload["
        + "data="
        + data
        + ", uri="
        + uri
        + ", compressionCodec="
        + compressionCodec
        + ", isMetadata="
        + isMetadata
        + ", sourceLength="
        + sourceLength
        + ", cryptoAlgorithm="
        + cryptoAlgorithm
        + ", cryptoKey="
        + Arrays.toString(cryptoKey)
        + "]";
  }
}
