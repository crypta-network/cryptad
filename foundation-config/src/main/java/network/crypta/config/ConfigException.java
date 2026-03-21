package network.crypta.config;

import java.io.Serial;

/**
 * Base class for exceptions thrown by the configuration subsystem.
 *
 * <p>This abstraction lets callers catch a single type to handle all configuration-related
 * failures. Concrete subclasses include {@link InvalidConfigValueException} for invalid input and
 * {@link NodeNeedRestartException} for changes that require a restart.
 */
public abstract class ConfigException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates a new exception with the specified detail message.
   *
   * @param msg human-readable detail describing the configuration failure.
   */
  protected ConfigException(String msg) {
    super(msg);
  }

  /**
   * Creates a new exception that wraps the given cause.
   *
   * @param cause the underlying cause; may be {@code null}.
   */
  protected ConfigException(Throwable cause) {
    super(cause);
  }
}
