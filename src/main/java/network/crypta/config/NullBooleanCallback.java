package network.crypta.config;

import network.crypta.support.api.BooleanCallback;

/**
 * No-op {@link BooleanCallback} following the null-object pattern.
 *
 * <p>This implementation provides a safe, do-nothing callback for boolean configuration values.
 * {@link #get()} always returns {@code false}. Calls to {@link #set(Boolean)} are accepted and
 * ignored, producing no state changes or side effects. Using this class allows callers to avoid
 * {@code null} checks when a setting is optional or intentionally read-only.
 *
 * <p>Threading: instances are stateless and safe to share across threads.
 *
 * <p>Side effects: none.
 */
public class NullBooleanCallback extends BooleanCallback {

  /**
   * Returns a constant {@code false} value.
   *
   * @return {@code false} in all cases.
   */
  @Override
  public Boolean get() {
    return false;
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
  public void set(Boolean val) throws InvalidConfigValueException {
    // No-op setter: writes are intentionally ignored.
  }
}
