package network.crypta.config;

/**
 * Functional contract for applying a configuration value with validation.
 *
 * <p>This interface is analogous to {@code java.util.function.Consumer} but tailored for the
 * configuration domain where setters may reject values or accept them while requiring a restart.
 * Implementations typically persist the new value and/or update in-memory state.
 *
 * <p>Threading: no synchronization is defined by this type; thread-safety depends on the
 * implementation.
 *
 * <p>Nullability: whether {@link #accept(Object)} permits {@code null} depends on the specific
 * setting and implementation.
 *
 * @param <T> the type of the configuration value to apply.
 */
public interface ConfigConsumer<T> {

  /**
   * Applies the provided configuration value.
   *
   * <p>Implementations may validate and persist the value. If the change cannot be accepted, they
   * throw {@link InvalidConfigValueException}. If the value is accepted but will only take effect
   * after a node restart, they throw {@link NodeNeedRestartException}. Callers should treat a
   * normal return as immediate acceptance.
   *
   * @param value the requested new value; may be {@code null} if allowed by the implementation.
   * @throws InvalidConfigValueException if the value is rejected as invalid (e.g., malformed or out
   *     of range relative to constraints for the setting).
   * @throws NodeNeedRestartException if the value is accepted but requires a node restart before it
   *     becomes effective; implementors should ensure persistence in this case.
   */
  void accept(T value) throws InvalidConfigValueException, NodeNeedRestartException;
}
