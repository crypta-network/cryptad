package network.crypta.config;

/**
 * No-op {@link LongCallback} that implements the null-object pattern.
 *
 * <p>This implementation provides a safe, do-nothing callback for long-valued configuration
 * settings. {@link #get()} always returns {@code 0L}. Calls to {@link #set(Long)} are accepted and
 * ignored, producing no state changes or side effects. Use when a setting is optional or
 * intentionally read-only to avoid {@code null} checks and special cases.
 *
 * <p>Threading: instances are stateless and safe to share across threads.
 *
 * <p>Side effects: none.
 */
public class NullLongCallback extends LongCallback {

  /**
   * Returns a constant {@code 0L} value.
   *
   * @return {@code 0L} in all cases.
   */
  @Override
  public Long get() {
    return 0L;
  }

  /**
   * Ignores the requested value; no state changes occur.
   *
   * <p>This implementation never throws but declares {@link InvalidConfigValueException} to satisfy
   * the callback contract.
   *
   * @param val the requested new value; ignored. May be {@code null}.
   * @throws InvalidConfigValueException never thrown by this implementation.
   */
  @Override
  public void set(Long val) throws InvalidConfigValueException {
    // No-op setter: writes are intentionally ignored.
  }
}
