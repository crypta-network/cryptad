package network.crypta.node;

/**
 * A lightweight identifier for a {@code SendableRequestItem} that supports efficient equality and
 * hashing.
 *
 * <p>The key identifies a request without embedding large payloads (for example, the data to be
 * inserted). It is intended for fast lookups in maps/sets that track queued or running work, such
 * as registries of transient inserts.
 *
 * <p>Guidelines:
 *
 * <ul>
 *   <li>Implement {@link #equals(Object)} and {@link #hashCode()} so that keys representing the
 *       same logical request compare equal.
 *   <li>Ensure keys are globally unique across requests within a node; avoid simple counters or
 *       other values that can collide.
 *   <li>Keep the representation small and inexpensive to compute; do not include large or sensitive
 *       data.
 *   <li>When {@link SendableRequestItem#getKey()} returns the request object itself, the default
 *       {@code equals} and {@code hashCode} may be sufficient. If a separate key object is used for
 *       quick membership checks, provide robust implementations.
 * </ul>
 *
 * @see SendableRequestItem#getKey()
 */
public interface SendableRequestItemKey {

  /**
   * Compares this key to another object for logical equality.
   *
   * @param o the object to compare; may be {@code null}
   * @return {@code true} if {@code o} denotes the same request identity as this instance; {@code
   *     false} otherwise
   */
  @Override
  boolean equals(Object o);

  /**
   * Returns a hash code consistent with {@link #equals(Object)} for use in hash-based collections.
   *
   * @return an integer hash code representing this key's logical identity
   */
  @Override
  int hashCode();
}
