package network.crypta.node;

/**
 * Describes a unit of work that a higher-level request can send.
 *
 * <p>A single {@code SendableRequest} may comprise multiple items. For fetch operations, an item is
 * often a small token such as an index or position indicating which key to retrieve. For insert
 * operations, an item may carry the data to insert or a handle that allows the sender to obtain the
 * data without direct database access.
 *
 * <p>Implementations should keep instances lightweight so they can be queued and tracked
 * efficiently. Use {@link #getKey()} to supply a compact identity suitable for hash-based
 * collections when deduplicating or checking membership.
 *
 * @author Matthew Toseland {@code <toad@amphibian.dyndns.org>} (0xE43DA450)
 */
public interface SendableRequestItem {

  /**
   * Releases resources when the associated request is abandoned.
   *
   * <p>Invocation timing is controlled by the sender; some senders may also call this after a
   * successful completion. Implementations should make this method safe to call at most once and
   * avoid throwing exceptions. Prefer freeing transient memory and closing any streams or handles
   * owned solely by this item.
   */
  void dump();

  /**
   * Returns a lightweight key that identifies the item in queues and sets.
   *
   * <p>This frequently returns {@code this}. If constructing the item is expensive or large, return
   * a dedicated {@link SendableRequestItemKey} implementation instead (commonly used for transient
   * inserts). The key should define stable {@link Object#equals(Object)} and {@link
   * Object#hashCode()} semantics that reflect the item's logical identity.
   *
   * @return a stable lightweight key that identifies this item in queue and membership tracking
   *     structures
   */
  SendableRequestItemKey getKey();
}
