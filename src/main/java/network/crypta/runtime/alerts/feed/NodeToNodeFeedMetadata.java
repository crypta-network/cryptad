package network.crypta.runtime.alerts.feed;

/**
 * Immutable runtime-owned provenance metadata for node-to-node feed events.
 *
 * <p>This record carries the peer-facing source node name together with the timestamps that
 * describe when a node-to-node message was composed, sent, and received. Runtime alerts use it to
 * preserve the same timing and origin information that existing FCP feed messages already expose.
 * Keeping the metadata in a small standalone record lets runtime code describe provenance without
 * depending on any transport-specific container.
 *
 * <p>The timestamp values are passed through without interpretation. Callers may use sentinel
 * values such as {@code -1} when a particular time is unknown, and transport bridges remain
 * responsible for deciding how those sentinel values appear on the wire.
 *
 * @param sourceNodeName human-readable node name associated with the originating peer message
 * @param composed epoch milliseconds when the originating peer composed the message, if known
 * @param sent epoch milliseconds when the originating peer transmitted the message, if known
 * @param received epoch milliseconds when the local node received the message, if known
 */
public record NodeToNodeFeedMetadata(
    String sourceNodeName, long composed, long sent, long received) {}
