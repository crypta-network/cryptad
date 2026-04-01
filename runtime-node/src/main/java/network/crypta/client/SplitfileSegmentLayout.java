package network.crypta.client;

/** Layout sizing and redundancy counts for a splitfile. */
public record SplitfileSegmentLayout(
    int segmentSize, int checkSegmentSize, int deductBlocksFromSegments, int crossSegmentBlocks) {}
