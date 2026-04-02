package network.crypta.support;

/**
 * Null-object implementation of {@link BloomFilter}.
 *
 * <p>This variant represents a zero-length filter that always reports positive membership and
 * ignores all updates. It contains no backing storage and performs no hashing. The {@link
 * BloomFilter#createFilter(int, int, boolean)} and {@link BloomFilter#createFilter(java.io.File,
 * int, int, boolean)} factories return an instance of this class when the requested length is
 * {@code 0}.
 *
 * <h2>Behavior</h2>
 *
 * <ul>
 *   <li>{@link #checkFilter(byte[])} always returns {@code true} and accepts {@code null} keys.
 *   <li>{@link #addKey(byte[])} and {@link #removeKey(byte[])} are no-ops and accept {@code null}
 *       keys.
 *   <li>{@link #getBit(int)} always returns {@code true}; {@link #setBit(int)} and {@link
 *       #unsetBit(int)} are no-ops.
 *   <li>{@link #fork(int)}, {@link #discard()}, and {@link #merge()} are intentional no-ops because
 *       there is no forkable state.
 * </ul>
 *
 * <h2>Threading</h2>
 *
 * <p>All operations are side effect free and constant time; no synchronization is required beyond
 * what the base type may perform. There are no observable state transitions.
 *
 * @author sdiz
 */
public class NullBloomFilter extends BloomFilter {
  /**
   * Constructs a null filter.
   *
   * <p>The {@link BloomFilter} base class coerces {@code k} to {@code 0} when {@code length == 0},
   * ensuring there is no hashing or index generation.
   *
   * @param length requested length in bits; callers typically pass {@code 0}
   * @param k number of hash functions; ignored and coerced to {@code 0} by the base constructor
   */
  protected NullBloomFilter(int length, int k) {
    super(length, k);
  }

  /**
   * Returns {@code true} for any key.
   *
   * <p>This method accepts {@code null} and keys of any length. It performs no hashing and has no
   * side effects.
   *
   * @param key key material; may be {@code null}
   * @return always {@code true}
   */
  @Override
  public boolean checkFilter(byte[] key) {
    return true;
  }

  /**
   * No-op. Accepts any input, including {@code null}.
   *
   * <p>The null filter has no backing storage to update.
   *
   * @param key key material; ignored
   */
  @Override
  public void addKey(byte[] key) {
    // No-op: null filter does not store state.
  }

  /**
   * No-op. Accepts any input, including {@code null}.
   *
   * <p>There is no stored state to remove from.
   *
   * @param key key material; ignored
   */
  @Override
  public void removeKey(byte[] key) {
    // No-op: nothing to remove in a null filter.
  }

  /**
   * Reports {@code true} for any position.
   *
   * <p>Since the filter has no storage, membership checks conceptually observe all positions as
   * set.
   *
   * @param offset ignored position index
   * @return always {@code true}
   */
  @Override
  protected boolean getBit(int offset) {
    // Intentional: null filter behaves as if every bit were set.
    return true;
  }

  /**
   * No-op. There is no underlying buffer to modify.
   *
   * @param offset ignored position index
   */
  @Override
  protected void setBit(int offset) {
    // No-op.
  }

  /**
   * No-op. There is no underlying buffer to modify.
   *
   * @param offset ignored position index
   */
  @Override
  protected void unsetBit(int offset) {
    // No-op.
  }

  /**
   * No-op. Starts no fork because this filter has no state.
   *
   * @param k requested hash count for the (non-existent) fork; ignored
   */
  @Override
  public void fork(int k) {
    // Intentionally no-op: the null filter has no backing state to fork.
  }

  /** No-op. There is no forked state to discard. */
  @Override
  public void discard() {
    // Intentionally no-op: there is no forked state to discard for the null filter.
  }

  /** No-op. There is no forked state to merge. */
  @Override
  public void merge() {
    // Intentionally no-op: merging is meaningless without forked state.
  }
}
