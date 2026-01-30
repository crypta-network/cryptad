package network.crypta.client.async;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.crypt.HashResult;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.jetbrains.annotations.NotNull;

/**
 * Immutable container for the outcome of a single compression attempt.
 *
 * <p>This record bundles three pieces of information that downstream callers typically need
 * together: a {@link RandomAccessBucket} holding the resulting bytes, the chosen compressor
 * (represented by {@link network.crypta.support.compress.Compressor.COMPRESSOR_TYPE}), and an
 * optional array of {@link HashResult} describing content hashes computed while producing the
 * output. The codec may be {@code null} to indicate that compression was not applied or did not
 * produce a smaller result; in that case the {@code data} contains the original bytes.
 *
 * <p>Instances are shallowly immutable: the reference to {@code data} and the {@code hashes} array
 * are stored as provided and are not defensively copied. Callers are expected to respect the
 * immutability contract and avoid mutating the referenced objects after construction when they are
 * shared.
 *
 * <ul>
 *   <li>Data: random-access storage for the produced payload, ready for reading or further
 *       processing.
 *   <li>Codec: the compressor that yielded the best result, or {@code null} when none was used.
 *   <li>Hashes: zero or more content digests computed during processing; may be {@code null}.
 * </ul>
 *
 * <p>Typical usage is to construct this as the return value of a compression routine and then hand
 * the bucket and metadata to subsequent persistence or transmission layers.
 *
 * <pre>{@code
 * // Example: pass compression output to a writer
 * var out = new CompressionOutput(bucket, codec, hashes);
 * writer.write(out.data());
 * }</pre>
 *
 * @param data the {@link RandomAccessBucket} containing the bytes produced by compression; never
 *     wrapped or copied, and may reference uncompressed data when no codec is selected
 * @param bestCodec the {@link network.crypta.support.compress.Compressor.COMPRESSOR_TYPE} selected
 *     as most effective for this content, or {@code null} when compression was not applied
 * @param hashes an optional array of {@link HashResult} values describing computed content digests;
 *     may be {@code null} or empty, and is stored without defensive copying
 */
record CompressionOutput(RandomAccessBucket data, COMPRESSOR_TYPE bestCodec, HashResult[] hashes) {

  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    return (o
            instanceof
            CompressionOutput(RandomAccessBucket od, COMPRESSOR_TYPE oc, HashResult[] oh))
        && Objects.equals(this.data, od)
        && this.bestCodec == oc
        && Arrays.equals(this.hashes, oh);
  }

  @Override
  public int hashCode() {
    int result = 1;
    result = 31 * result + Objects.hashCode(this.data);
    result = 31 * result + Objects.hashCode(this.bestCodec);
    result = 31 * result + Arrays.hashCode(this.hashes);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "CompressionOutput["
        + "data="
        + data
        + ", bestCodec="
        + bestCodec
        + ", hashes="
        + Arrays.toString(hashes)
        + "]";
  }
}
