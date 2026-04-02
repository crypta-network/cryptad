package network.crypta.node;

/**
 * Captures the length and position metadata for a message fragment.
 *
 * <p>The record is an immutable carrier used when constructing {@link MessageFragment} instances.
 * It performs no validation; callers must supply consistent values.
 *
 * @param fragmentLength declared fragment length (may differ from {@code fragmentData.length})
 * @param messageLength total message length for first fragments; otherwise ignored
 * @param fragmentOffset byte offset of this fragment within the full message (0-based)
 */
record MessageFragmentSizes(int fragmentLength, int messageLength, int fragmentOffset) {}
