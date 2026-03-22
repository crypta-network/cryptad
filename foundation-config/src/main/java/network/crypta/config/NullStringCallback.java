package network.crypta.config;

/**
 * No-op {@link StringCallback} implementing the null-object pattern.
 *
 * <p>This implementation provides a safe, do-nothing callback for string-valued configuration
 * settings. {@link #get()} always returns the empty string ({@code ""}). Calls to {@link
 * #set(String)} are accepted and ignored, producing no state changes or side effects. Use this when
 * a setting is optional or intentionally read-only to avoid {@code null} checks and special-case
 * handling.
 *
 * <p>Threading: instances are stateless and safe to share across threads.
 *
 * <p>Side effects: none.
 */
public class NullStringCallback extends StringCallback {

  /**
   * Returns a constant empty string.
   *
   * @return {@code ""} in all cases.
   */
  @Override
  public String get() {
    return "";
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
  public void set(String val) throws InvalidConfigValueException {
    // No-op setter: writes are intentionally ignored.
  }
}
