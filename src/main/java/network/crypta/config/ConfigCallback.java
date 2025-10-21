package network.crypta.config;

/**
 * Base callback abstraction for reading and writing a configuration value.
 *
 * <p>Implementations encapsulate access and validation logic for a single setting. Callers use
 * {@link #get()} to obtain the current effective value and {@link #set(Object)} to request a
 * change. Concrete implementations may persist values, perform validation, and—where
 * applicable—signal that a restart is required before the new value takes effect.
 *
 * <p>Threading: this type defines no synchronization; thread-safety depends on the implementation.
 *
 * <p>Nullability: whether {@link #get()} can return {@code null} and whether {@link #set(Object)}
 * accepts {@code null} depends on the specific setting and implementation.
 *
 * @param <T> the value type of the configuration setting.
 */
public abstract class ConfigCallback<T> {

  /**
   * Returns the current effective value of the setting.
   *
   * <p>The value may reflect defaults, persisted configuration, or computed state. It may be {@code
   * null} if the setting is optional and unset, depending on the implementation.
   *
   * @return the current value; may be {@code null}.
   */
  public abstract T get();

  /**
   * Applies a new value to the setting.
   *
   * <p>Implementations may validate and persist the value. Some settings become effective only
   * after a restart; in such cases, implementations may throw {@link NodeNeedRestartException} to
   * indicate that the value is accepted but not yet active.
   *
   * @param val the requested new value; may be {@code null} if allowed by the implementation.
   * @throws InvalidConfigValueException if the value is rejected as invalid.
   * @throws NodeNeedRestartException if the change is accepted but requires a node restart to take
   *     effect.
   */
  public abstract void set(T val) throws InvalidConfigValueException, NodeNeedRestartException;

  /**
   * Indicates whether this callback permits writes.
   *
   * <p>The base implementation returns {@code false}. Implementations may override to return {@code
   * true} for read-only settings.
   *
   * @return {@code true} if writes are not supported by this instance.
   */
  public boolean isReadOnly() {
    return false;
  }
}
