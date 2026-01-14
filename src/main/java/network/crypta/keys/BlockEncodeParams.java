package network.crypta.keys;

import network.crypta.support.api.Bucket;

/**
 * Bundles common compression inputs for CHK/SSK encoding operations.
 *
 * @param sourceData bucket containing the input bytes
 * @param asMetadata whether the resulting key should be flagged as metadata
 * @param dontCompress whether compression should be skipped
 * @param alreadyCompressedCodec codec identifier if the input is already compressed
 * @param sourceLength expected number of bytes to read from the source
 * @param compressorDescriptor optional compressor selection/hint
 */
public record BlockEncodeParams(
    Bucket sourceData,
    boolean asMetadata,
    boolean dontCompress,
    short alreadyCompressedCodec,
    long sourceLength,
    String compressorDescriptor) {}
