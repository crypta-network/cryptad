package network.crypta.config;

/**
 * No-op {@link ShortCallback} implementing the null-object pattern.
 *
 * <p>This implementation provides a safe, do-nothing callback for short-valued configuration
 * settings. {@link #get()} always returns {@code 0}. Calls to {@link #set(Short)} are accepted and
 * ignored, producing no state changes or side effects. Use when a setting is optional or
 * intentionally read-only to avoid {@code null} checks and special-case handling.
 *
 * <p>Threading: instances are stateless and safe to share across threads.
 *
 * <p>Side effects: none.
 */
public class NullShortCallback extends ShortCallback {

  /**
   * Returns a constant {@code 0} value.
   *
   * @return {@code 0} in all cases.
   */
  @Override
  public Short get() {
    return 0;
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
  public void set(Short val) throws InvalidConfigValueException {
    // No-op setter: writes are intentionally ignored.
  }
}
