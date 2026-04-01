package network.crypta.client;

import network.crypta.client.InsertContext.CompatibilityMode;

/**
 * Groups sizing, block-count, compression, and compatibility details for a metadata top layer.
 *
 * <p>This record is a compact carrier for the values that describe how the outermost metadata layer
 * is sized and how it should be interpreted during serialization. It is typically constructed by
 * callers that already know the top-layer byte sizes, the required and total block counts, and the
 * intended compatibility mode. The record does not validate or normalize values; it preserves them
 * as provided so that upstream code can decide on coherent ranges and relationships. It is often
 * paired with {@link TopLayerHashInfo} when building {@link MetadataTopLayerInfo} instances.
 *
 * <p>All numeric fields represent byte counts or block counts and are expected to be non-negative.
 * The record is immutable and safe to share across threads. The only trade-off is that no defensive
 * checks are performed, which keeps construction lightweight but places responsibility for
 * correctness on the caller.
 *
 * <ul>
 *   <li>Captures byte lengths for original and compressed top-layer data.
 *   <li>Stores required and total block counts used by serializers and progress reporting.
 *   <li>Records compression intent and compatibility mode without inference.
 * </ul>
 *
 * @param size original uncompressed size in bytes for the top layer; non-negative, {@code 0} when
 *     unknown.
 * @param compressedSize original compressed size in bytes; non-negative, {@code 0} when unknown or
 *     not applicable.
 * @param blocksRequired minimum number of blocks required to reconstruct the data; non-negative,
 *     {@code 0} when not supplied.
 * @param blocksTotal total number of blocks inserted for the data; non-negative and typically
 *     greater than or equal to {@code blocksRequired}.
 * @param dontCompress whether compression was intentionally disabled for the top layer; {@code
 *     true} records intent, not actual compression state.
 * @param compatMode declared compatibility mode for the top layer; never {@code null}, often {@link
 *     CompatibilityMode#COMPAT_UNKNOWN} when unspecified.
 * @see MetadataTopLayerInfo
 * @see TopLayerHashInfo
 */
public record TopLayerBlockInfo(
    long size,
    long compressedSize,
    int blocksRequired,
    int blocksTotal,
    boolean dontCompress,
    CompatibilityMode compatMode) {}
