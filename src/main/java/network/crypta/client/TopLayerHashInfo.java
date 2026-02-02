package network.crypta.client;

import java.util.Arrays;
import network.crypta.crypt.HashResult;
import org.jetbrains.annotations.NotNull;

/**
 * Groups hash data for the final content and optional layer-local hash.
 *
 * <p>This value object captures hash material used when serializing or interpreting the top layer
 * of metadata. It is typically assembled by callers that already computed hashes and want to pass
 * them through as-is alongside size and block-count information. The class does not validate hash
 * contents, compute digests, or enforce particular hash algorithms; it only preserves the arrays
 * supplied at construction time. This keeps construction lightweight and makes the type a simple
 * carrier for downstream serialization or diagnostics.
 *
 * <p>Instances are immutable, but the underlying arrays are not copied. Callers should treat the
 * arrays as stable for the lifetime of metadata construction and avoid mutating them after passing
 * this instance to {@link MetadataTopLayerInfo}. The class is thread-safe if the referenced arrays
 * are treated as immutable.
 *
 * <ul>
 *   <li>Stores hashes for final/original data when provided.
 *   <li>Optionally stores a layer-local hash for the current metadata layer.
 *   <li>Does not infer or validate hash algorithms or array lengths.
 * </ul>
 *
 * @see MetadataTopLayerInfo
 * @see TopLayerBlockInfo
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class TopLayerHashInfo {
  private final HashResult[] hashes;
  private final byte[] hashThisLayerOnly;

  /**
   * Creates a hash bundle for top-layer metadata.
   *
   * <p>This constructor stores the provided arrays directly without cloning or validation. It is
   * intended for callers that already computed hash values and want to provide them to metadata
   * serialization. Either array may be {@code null} to indicate absence of that hash material. The
   * constructor has no side effects and can be used repeatedly with the same inputs. Callers must
   * avoid mutating the arrays after construction if stable equality and hashing are required.
   *
   * @param hashes hashes of the final or original data; may be {@code null} or empty when hashes
   *     are not available.
   * @param hashThisLayerOnly hash of only this metadata layer; may be {@code null} when not
   *     provided or not required.
   */
  public TopLayerHashInfo(HashResult[] hashes, byte[] hashThisLayerOnly) {
    this.hashes = hashes;
    this.hashThisLayerOnly = hashThisLayerOnly;
  }

  /**
   * Returns the hashes of the final or original data, if provided.
   *
   * <p>The returned array is the same reference supplied at construction time and is not copied or
   * normalized. It may be {@code null} or empty, depending on whether hashes were available at the
   * call site. Because the array is shared, callers should treat it as immutable to keep {@link
   * #equals(Object)} and {@link #hashCode()} stable over time.
   *
   * @return the final-data hash array, or {@code null} when no hashes were supplied.
   */
  public HashResult[] hashes() {
    return hashes;
  }

  /**
   * Returns the optional hash for only this metadata layer, if provided.
   *
   * <p>The returned array is the same reference supplied at construction time and is not copied or
   * validated. It may be {@code null} when a layer-local hash is not available. Callers should not
   * mutate the array after construction if they depend on stable equality, hashing, or diagnostic
   * output. This accessor performs no allocation and has no side effects.
   *
   * @return the layer-local hash bytes, or {@code null} when not supplied.
   */
  public byte[] hashThisLayerOnly() {
    return hashThisLayerOnly;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof TopLayerHashInfo other)) {
      return false;
    }
    return Arrays.equals(hashes, other.hashes)
        && Arrays.equals(hashThisLayerOnly, other.hashThisLayerOnly);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(hashes);
    result = 31 * result + Arrays.hashCode(hashThisLayerOnly);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "TopLayerHashInfo[hashes="
        + Arrays.toString(hashes)
        + ", hashThisLayerOnly="
        + Arrays.toString(hashThisLayerOnly)
        + "]";
  }
}
