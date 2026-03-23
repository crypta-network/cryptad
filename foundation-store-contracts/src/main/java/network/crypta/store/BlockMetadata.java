package network.crypta.store;

/**
 * Mutable metadata describing properties of a stored block.
 *
 * <p>This type is a simple value holder. It performs no validation or synchronization.
 */
public final class BlockMetadata {

  /**
   * Indicates that the block came from an older or opportunistic cache path.
   *
   * <p>Callers may use this to avoid treating the block as a normal promotable datastore entry.
   */
  private boolean oldBlock;

  /** Clears all metadata and restores default values. */
  public void reset() {
    oldBlock = false;
  }

  /**
   * Reports whether the block should be treated as old.
   *
   * @return {@code true} when the caller marked the block as old; otherwise {@code false}
   */
  public boolean isOldBlock() {
    return oldBlock;
  }

  /** Marks the block as old. */
  public void setOldBlock() {
    oldBlock = true;
  }
}
