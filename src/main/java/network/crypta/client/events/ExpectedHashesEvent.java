package network.crypta.client.events;

import network.crypta.crypt.HashResult;

/**
 * Event that conveys the set of content hashes a client expects to observe.
 *
 * <p>This value object is emitted by higher-level client operations when they can determine one or
 * more reference digests for the item being fetched, inserted, or verified. Listeners may log this
 * information, compare it with actual results, or surface the data to user interfaces. The event
 * carries only metadata; it does not perform any computation and has no side effects. Instances are
 * immutable with respect to the reference they expose, although the referenced array itself is not
 * defensively copied. Callers should therefore treat the {@link #hashes} field as read-only and
 * avoid mutating it after constructing the event.
 *
 * <p>Typical usages include:
 *
 * <ul>
 *   <li>Reporting digests calculated by a preparatory step so downstream components can validate
 *       retrieved data.
 *   <li>Attaching expected digests to progress logs to aid troubleshooting and correlation.
 *   <li>Providing a compact, serializable summary for audit or testing utilities.
 * </ul>
 *
 * <p>Thread-safety note: The class itself is effectively immutable once constructed, but because
 * the {@code hashes} array reference is stored as provided, external mutation of that array would
 * be observable by listeners. Prefer supplying a dedicated array instance that is not modified
 * after publication.
 *
 * @see ClientEvent
 * @see HashResult
 */
public class ExpectedHashesEvent implements ClientEvent {

  /**
   * The expected content digests associated with this event.
   *
   * <p>The array groups zero or more {@link HashResult} entries, typically one per algorithm. The
   * reference is stored as provided by the caller; no defensive copy is performed. The reference
   * may be {@code null} to indicate the absence of expected hashes. Consumers should treat the
   * array as read-only.
   */
  public final HashResult[] hashes;

  /**
   * Stable identifier for this event type.
   *
   * <p>The value is suitable for programmatic routing, filtering, or metric labeling. It remains
   * constant across releases for compatibility with downstream consumers.
   */
  public static final int CODE = 0x0E;

  /**
   * Creates a new event containing the provided expected digests.
   *
   * <p>No validation or de-duplication is performed here; producers should construct the array in
   * the desired order and with the desired uniqueness guarantees. The array reference is stored as
   * is and not copied.
   *
   * @param h array of expected {@link HashResult} values; may be {@code null} when no digests are
   *     available or applicable. The array is not defensively copied and should not be mutated
   *     after construction.
   */
  public ExpectedHashesEvent(HashResult[] h) {
    hashes = h;
  }

  /** {@inheritDoc} */
  @Override
  public int getCode() {
    return CODE;
  }

  /** {@inheritDoc} */
  @Override
  public String getDescription() {
    return "Expected hashes";
  }
}
