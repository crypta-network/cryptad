package network.crypta.node;

/**
 * Bundles the header flags and message identifier for a fragment.
 *
 * <p>The record is an immutable carrier used when constructing {@link MessageFragment} instances.
 * It performs no validation; callers must supply consistent values.
 *
 * @param shortMessage {@code true} when the message uses single-byte size fields
 * @param isFragmented {@code true} when the message is split across multiple fragments
 * @param firstFragment {@code true} when this is the first fragment of the message
 * @param messageID identifier of the logical message this fragment belongs to
 */
record MessageFragmentHeader(
    boolean shortMessage, boolean isFragmented, boolean firstFragment, int messageID) {}
