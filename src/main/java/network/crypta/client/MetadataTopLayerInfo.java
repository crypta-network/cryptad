package network.crypta.client;

import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;

/**
 * Bundle of top-layer size, block counts, compatibility, and hash details used in metadata.
 *
 * <p>Lengths are in bytes and counts are non-negative. {@code hashes} refers to the final/original
 * data. {@code hashThisLayerOnly} refers to the current layer and may be {@code null}.
 */
public record MetadataTopLayerInfo(
    long origDataLength,
    long origCompressedDataLength,
    int requiredBlocks,
    int totalBlocks,
    boolean topDontCompress,
    CompatibilityMode topCompatibilityMode,
    HashResult[] hashes,
    byte[] hashThisLayerOnly) {

  /** Returns an instance representing the absence of any top-layer sizing or hash data. */
  public static MetadataTopLayerInfo none() {
    return new MetadataTopLayerInfo(
        0, 0, 0, 0, false, CompatibilityMode.COMPAT_UNKNOWN, null, null);
  }
}
