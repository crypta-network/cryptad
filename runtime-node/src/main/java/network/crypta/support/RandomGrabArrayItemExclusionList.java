package network.crypta.support;

import network.crypta.client.async.ClientContext;

/**
 * Strategy interface that decides temporary exclusion for a {@link RandomGrabArrayItem}.
 *
 * <p>Implementations provide scheduler-level cooldown or backoff decisions used by selection
 * structures such as {@link RandomGrabArray}. The decision is expressed as a timestamp in epoch
 * milliseconds indicating when the item may next become eligible. A return value of {@code 0} means
 * the item is eligible now.
 *
 * <p>Thread-safety: Callers typically invoke this method while holding the selection tree's root
 * lock (see {@code ClientRequestSelector}). Implementations should make this check quick and avoid
 * blocking operations.
 */
public interface RandomGrabArrayItemExclusionList {

  /**
   * Returns the earliest time this item may be selected, or {@code 0} if it is eligible now.
   *
   * <p>Return values:
   *
   * <ul>
   *   <li>{@code 0}: Do not exclude; the item may be returned immediately.
   *   <li>{@code > 0}: Absolute time (milliseconds since the epoch) when the item may become
   *       eligible. Until then, the item is considered excluded by the scheduler.
   * </ul>
   *
   * <p>Preconditions: {@code item} must be non-{@code null}. Implementations should be side-effect
   * free or limit themselves to inexpensive internal accounting needed to compute the decision.
   *
   * @param item the candidate item being considered; never {@code null}
   * @param context client execution context
   * @param now current time in milliseconds since the epoch
   * @return {@code 0} if eligible now; otherwise an absolute wakeup time in epoch milliseconds
   */
  long exclude(RandomGrabArrayItem item, ClientContext context, long now);
}
