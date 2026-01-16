package network.crypta.node.useralerts;

import network.crypta.node.DarknetPeerNode;

/**
 * Bundles peer and timing metadata for node-to-node alert creation.
 *
 * <p>This record captures the minimal state required to build user alerts that represent
 * node-to-node feeds or messages. It keeps a reference to the originating {@link DarknetPeerNode},
 * the peer-local file number used for cleanup on dismissal, and the trio of timestamps supplied by
 * the sender and receiver. Callers typically create one context per incoming message and pass it to
 * alert constructors so the alert implementations can remain focused on presentation logic instead
 * of repetitive wiring.
 *
 * <p>The record is an immutable value carrier: it does not validate input, perform I/O, or adjust
 * timestamps. Consumers should treat the contained values as verbatim metadata. The peer reference
 * is expected to remain live while alerts are rendered, but no additional synchronization is
 * performed here. This type is therefore thread-safe for sharing across threads as long as the
 * referenced peer is managed safely elsewhere.
 *
 * <ul>
 *   <li>Groups message timing metadata with its source peer.
 *   <li>Provides a stable, reuse-oriented parameter set for alert constructors.
 *   <li>Leaves validation and lifecycle decisions to the alert implementations.
 * </ul>
 *
 * @param sourcePeerNode originating darknet peer for the alert; must be non-null and is expected to
 *     remain valid while the alert reads its name or reference
 * @param fileNumber peer-local identifier of extra data to delete on dismissal; non-negative values
 *     are typical and are treated as opaque by this record
 * @param composedTime sender-provided composition time in epoch milliseconds; use {@code -1} when
 *     the time is unknown or intentionally omitted
 * @param sentTime sender-provided transmission time in epoch milliseconds; use {@code -1} when
 *     unavailable or not meaningful for the feed
 * @param receivedTime local receipt time in epoch milliseconds; often used as the alert updated
 *     time and should reflect when the data arrived
 * @see BookmarkFeedUserAlert
 * @see DownloadFeedUserAlert
 * @see N2NTMUserAlert
 */
public record NodeToNodeAlertContext(
    DarknetPeerNode sourcePeerNode,
    int fileNumber,
    long composedTime,
    long sentTime,
    long receivedTime) {}
