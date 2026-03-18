package network.crypta.runtime.spi;

/**
 * Legacy completion states returned after creating a new persistent queue insert.
 *
 * <p>The queue insert SPI keeps a few legacy daemon completion states on the normal return path
 * instead of turning them into exceptions. That preserves the queue page's established redirect and
 * completion behavior after insert construction moved behind the runtime boundary.
 *
 * <p>These values therefore describe what happened while attempting to register the insert, not
 * whether the eventual network insert will succeed later.
 */
public enum QueueInsertOutcome {
  /**
   * The insert request was registered with the persistent queue and started successfully.
   *
   * <p>Callers normally follow this outcome with the existing queue-page redirect.
   */
  STARTED,

  /**
   * The chosen identifier was already in use.
   *
   * <p>This matches the older queue behavior where identifier collisions were treated as a normal
   * redirect-only outcome instead of a user-visible hard failure.
   */
  IDENTIFIER_COLLISION,

  /**
   * Redirect metadata could not be resolved while constructing the insert.
   *
   * <p>The queue UI historically handled this case the same way it handled successful enqueueing
   * for redirect purposes, so the SPI preserves that distinction.
   */
  METADATA_UNRESOLVED
}
