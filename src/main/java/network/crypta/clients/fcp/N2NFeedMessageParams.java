package network.crypta.clients.fcp;

/**
 * Parameter bundle describing the shared metadata for node-to-node feed messages.
 *
 * <p>Instances capture the core feed text fields alongside the originating node name and the
 * timestamps that describe when the message was composed, sent, and received. The values are passed
 * through to {@link FeedMessage} and {@link N2NFeedMessage} without modification, preserving the
 * existing wire format and validation behavior.
 *
 * @param header short one-line title shown prominently to users; may be {@code null} if no distinct
 *     header is needed.
 * @param shortText secondary summary line; may be {@code null} when no short description is used.
 * @param text full feed body text that will be encoded as UTF-8 bytes; must be non-{@code null}.
 * @param priorityClass numeric priority hint used by the FCP infrastructure to order outgoing
 *     messages.
 * @param updatedTime timestamp in milliseconds since the epoch indicating when the entry was last
 *     updated.
 * @param sourceNodeName human-readable name of the node that originated the message; may be {@code
 *     null} or empty.
 * @param composed epoch milliseconds when the sender composed the message; use {@code -1} if
 *     unknown.
 * @param sent epoch milliseconds when the sender transmitted the message; use {@code -1} if
 *     unknown.
 * @param received epoch milliseconds when this node received the message; use {@code -1} if
 *     unknown.
 */
public record N2NFeedMessageParams(
    String header,
    String shortText,
    String text,
    short priorityClass,
    long updatedTime,
    String sourceNodeName,
    long composed,
    long sent,
    long received) {}
