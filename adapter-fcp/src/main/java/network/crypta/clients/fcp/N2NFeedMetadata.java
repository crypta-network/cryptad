package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Shared node-to-node metadata for feed messages.
 *
 * <p>This helper captures the origin node name alongside the three timestamps used to describe when
 * a feed entry was composed, sent, and received. Feed message classes use it as a lightweight value
 * object and delegate field emission to {@link #applyTo(SimpleFieldSet)} so that all node-to-node
 * messages share the same wire-level field behavior without repeating logic. Typical call sites
 * construct the metadata from {@link N2NFeedMessageParams} and immediately apply it when building
 * an outgoing {@link SimpleFieldSet} header.
 *
 * <p>The class is intentionally minimal: it stores immutable values, performs no validation, and
 * does not allocate additional resources beyond the provided {@link SimpleFieldSet}. Timestamp
 * values use {@code -1} as a sentinel for "unknown", which suppresses those fields in the header.
 * This keeps messages backward compatible for peers that do not provide timing data. Instances are
 * thread-safe for concurrent reads because they never mutate after construction.
 *
 * <ul>
 *   <li>Encapsulates source node identity and timing metadata.
 *   <li>Applies node-to-node header fields consistently for all feed messages.
 *   <li>Avoids stateful behavior so callers can reuse it safely.
 * </ul>
 */
final class N2NFeedMetadata {
  /**
   * Display-friendly name of the node that originated the message.
   *
   * <p>This value is written verbatim to the {@code SourceNodeName} field and is treated as
   * user-facing text rather than a stable identifier. It may be {@code null} or empty depending on
   * upstream data availability and is not interpreted by this class.
   */
  private final String sourceNodeName;

  /**
   * Epoch milliseconds when the sender composed the message.
   *
   * <p>A value of {@code -1} means the time is unknown and the {@code TimeComposed} field is
   * omitted from the header. Non-negative values are emitted as-is without range checking or
   * normalization.
   */
  private final long composed;

  /**
   * Epoch milliseconds when the sender transmitted the message.
   *
   * <p>A value of {@code -1} suppresses the {@code TimeSent} header entry. Non-negative values are
   * included verbatim and are assumed to be comparable with other epoch-millisecond timestamps.
   */
  private final long sent;

  /**
   * Epoch milliseconds when this node received the message.
   *
   * <p>A value of {@code -1} suppresses the {@code TimeReceived} header entry. Non-negative values
   * are emitted as provided and represent the node's best-known receipt time for the feed entry.
   */
  private final long received;

  /**
   * Create metadata describing the origin and timing of a node-to-node feed entry.
   *
   * <p>The constructor stores the supplied values without validation and assumes that callers
   * provide epoch-millisecond timestamps or {@code -1} for unknown values. Instances are immutable
   * and can be reused across multiple field-set builds for the same message. This constructor does
   * not allocate any I/O resources and performs no defensive copying.
   *
   * @param sourceNodeName display name of the originating node; may be {@code null} or empty
   *     depending on upstream metadata availability
   * @param composed epoch milliseconds when the message was composed, or {@code -1} if unknown
   * @param sent epoch milliseconds when the message was sent, or {@code -1} if unknown
   * @param received epoch milliseconds when the message was received, or {@code -1} if unknown
   */
  N2NFeedMetadata(String sourceNodeName, long composed, long sent, long received) {
    this.sourceNodeName = sourceNodeName;
    this.composed = composed;
    this.sent = sent;
    this.received = received;
  }

  /**
   * Append node metadata fields to the supplied field set.
   *
   * <p>This method mutates the provided {@link SimpleFieldSet} by appending the source node name
   * and any known timestamps. {@code SourceNodeName} is always written, while {@code TimeComposed},
   * {@code TimeSent}, and {@code TimeReceived} are included only when their values are
   * non-negative. The operation is idempotent with respect to the stored values; repeated calls
   * overwrite the same keys with the same values and do not allocate additional buckets.
   *
   * @param fs mutable field set to populate; must be non-null and is modified in place
   * @return the same field set instance for chaining or immediate serialization
   */
  SimpleFieldSet applyTo(SimpleFieldSet fs) {
    fs.putSingle("SourceNodeName", sourceNodeName);
    if (composed != -1) fs.put("TimeComposed", composed);
    if (sent != -1) fs.put("TimeSent", sent);
    if (received != -1) fs.put("TimeReceived", received);
    return fs;
  }
}
