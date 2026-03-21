package network.crypta.config;

import java.io.Serial;

/**
 * Signals that a configuration value cannot be parsed into the required type.
 *
 * <p>This exception is typically thrown while reading or validating options when a textual
 * representation cannot be converted to a target type such as a number, boolean, enum, or a
 * structured value. Catchers can use it to surface a clear error to the user and request a
 * corrected value.
 *
 * <p>See also {@link InvalidConfigValueException} for other value-related failures.
 */
public class OptionFormatException extends InvalidConfigValueException {
  // Serialization ID for binary compatibility across versions of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates a new instance with a human-readable detail message.
   *
   * @param msg detail message describing the option and the value that failed to parse; forwarded
   *     to the superclass
   */
  public OptionFormatException(String msg) {
    super(msg);
  }
}
