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
 * validation; callers are responsible for supplying valid values and for ensuring the referenced
 * bucket remains readable for the duration of the insert.
 *
 * <p>The {@code cryptoKey} array is defensively copied on construction and accessor read, and is
 * compared by content for equality.
 */
public final class BlockInsertPayload {
  private final Bucket data;
  private final FreenetURI uri;
  private final short compressionCodec;
  private final boolean isMetadata;
  private final int sourceLength;
  private final byte cryptoAlgorithm;
  private final byte[] cryptoKey;

  /**
   * Creates a bundle describing a single block insert payload.
   *
   * @param data source bucket containing the bytes to insert; must remain readable during encoding
   * @param uri target URI that determines the key type (e.g., CHK/SSK/USK)
   * @param compressionCodec compression codec identifier; {@code -1} lets the encoder decide
   * @param isMetadata whether the content should be encoded as metadata
   * @param sourceLength uncompressed source length in bytes, or {@code -1} if unknown
   * @param cryptoAlgorithm identifier for optional per-block cryptography; {@code 0} for none
   * @param cryptoKey raw key material for {@code cryptoAlgorithm}; copied when non-null
   */
  public BlockInsertPayload(
      Bucket data,
      FreenetURI uri,
      short compressionCodec,
      boolean isMetadata,
      int sourceLength,
      byte cryptoAlgorithm,
      byte[] cryptoKey) {
    this.data = data;
    this.uri = uri;
    this.compressionCodec = compressionCodec;
    this.isMetadata = isMetadata;
    this.sourceLength = sourceLength;
    this.cryptoAlgorithm = cryptoAlgorithm;
    this.cryptoKey = copyNullable(cryptoKey);
  }

  public Bucket data() {
    return data;
  }

  public FreenetURI uri() {
    return uri;
  }

  public short compressionCodec() {
    return compressionCodec;
  }

  public boolean isMetadata() {
    return isMetadata;
  }

  public int sourceLength() {
    return sourceLength;
  }

  public byte cryptoAlgorithm() {
    return cryptoAlgorithm;
  }

  public byte[] cryptoKey() {
    return copyNullable(cryptoKey);
  }

  private static byte[] copyNullable(byte[] input) {
    return input == null ? null : Arrays.copyOf(input, input.length);
  }

  /**
   * Compares this payload to another for structural equality, including array contents.
   *
   * @param o candidate object to compare with this payload; may be {@code null}
   * @return {@code true} when all fields match by value; otherwise {@code false}
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof BlockInsertPayload other)) return false;
    return compressionCodec == other.compressionCodec
        && isMetadata == other.isMetadata
        && sourceLength == other.sourceLength
        && cryptoAlgorithm == other.cryptoAlgorithm
        && Objects.equals(data, other.data)
        && Objects.equals(uri, other.uri)
        && Arrays.equals(cryptoKey, other.cryptoKey);
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
