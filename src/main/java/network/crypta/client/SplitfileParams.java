package network.crypta.client;

import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.keys.ClientCHK;

/**
 * Bundle of splitfile keys, layout, and crypto settings used when building metadata.
 *
 * <p>Arrays are not copied; callers retain ownership.
 */
public record SplitfileParams(
    SplitfileAlgorithm splitfileAlgorithm,
    ClientCHK[] dataURIs,
    ClientCHK[] checkURIs,
    int segmentSize,
    int checkSegmentSize,
    int deductBlocksFromSegments,
    int crossSegmentBlocks,
    byte splitfileCryptoAlgorithm,
    byte[] splitfileCryptoKey,
    boolean specifySplitfileKey) {}
