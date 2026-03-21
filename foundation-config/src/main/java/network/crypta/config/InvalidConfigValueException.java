package network.crypta.config;

/**
 * Indicates that a configuration value is rejected as invalid.
 *
 * <p>This exception is thrown by configuration setters such as {@link ConfigCallback#set(Object)}
 * or {@link ConfigConsumer#accept(Object)} when a supplied value fails validation (for example,
 * wrong format, out of range, or otherwise prohibited). The absence of this exception does not
 * guarantee overall correctness; it only means no immediately detectable problem was found during
 * validation.
 */
public class InvalidConfigValueException extends ConfigException {
  /**
   * Creates a new exception with the provided detail message.
   *
   * @param msg human-readable explanation of why the value is considered invalid.
   */
  public InvalidConfigValueException(String msg) {
    super(msg);
  }

  /**
   * Creates a new exception wrapping the given cause.
   *
   * @param cause underlying cause; may be {@code null}.
   */
  public InvalidConfigValueException(Throwable cause) {
    super(cause);
  }
}
