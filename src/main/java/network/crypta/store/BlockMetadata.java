package network.crypta.store;

/**
 * Mutable metadata describing properties of a datastore block.
 *
 * <p>Instances accompany blocks read from the store and influence higher-level caching and
 * advertising decisions. This type is a simple value holder and performs no validation or
 * synchronization; callers are responsible for any required thread-safety when sharing instances
 * across threads.
 */
public final class BlockMetadata {

  /**
   * Flag indicating that the block originates from legacy or opportunistic caching.
   *
   * <p>When {@code true}, the block was either persisted before build 1224 or cached because a low
   * physical security level caused all traffic to be written to the datastore. In such cases we
   * cannot assert that it should be cached or advertised to peers; other nodes should learn about
   * it only when we actively transmit the data.
   */
  private boolean oldBlock;

  /**
   * Clear all metadata and restore default values.
   *
   * <p>Postcondition: {@link #isOldBlock()} returns {@code false}.
   */
  public void reset() {
    oldBlock = false;
  }

  /**
   * Report whether the block should be treated as "old" and therefore not proactively cached or
   * advertised.
   *
   * @return {@code true} if the block predates build 1224 or was cached only due to global
   *     write-to-store settings (e.g., low physical security level); {@code false} otherwise.
   */
  public boolean isOldBlock() {
    return oldBlock;
  }

  /**
   * Mark the block as originating from legacy or opportunistic caching.
   *
   * <p>Postcondition: {@link #isOldBlock()} returns {@code true}.
   */
  public void setOldBlock() {
    oldBlock = true;
  }
}
