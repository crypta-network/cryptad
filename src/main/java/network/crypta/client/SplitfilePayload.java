package network.crypta.client;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/** Bundle describing the content represented by a splitfile metadata entry. */
public record SplitfilePayload(
    ClientMetadata clientMetadata,
    long dataLength,
    ARCHIVE_TYPE archiveType,
    COMPRESSOR_TYPE compressionCodec,
    long decompressedLength,
    boolean isMetadata) {}
