package network.crypta.keys;

/**
 * Compression size limits and header layout hints.
 *
 * @param maxLengthBeforeCompression upper bound on {@code sourceData.size()} before compression is
 *     attempted
 * @param maxCompressedLengthLimit hard limit on the compressed byte array length
 * @param shortLength whether the precompressed-length header uses 2 bytes instead of 4
 */
public record CompressionLimits(
    long maxLengthBeforeCompression, int maxCompressedLengthLimit, boolean shortLength) {}
