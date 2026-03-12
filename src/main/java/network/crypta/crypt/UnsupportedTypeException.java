package network.crypta.crypt;

import java.io.Serial;

/**
 * Indicates that an unsupported enum constant was provided to a cryptographic API.
 *
 * <p>This exception is a specialized {@link IllegalArgumentException}. It is thrown when a caller
 * supplies an {@link Enum} value (e.g., an algorithm, mode, or type selector) that the receiving
 * method does not support. The exception message includes the enum's declaring class and constant
 * name to aid diagnosis.
 *
 * @author unixninja92
 */
public class UnsupportedTypeException extends IllegalArgumentException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception describing the unsupported enum value.
   *
   * @param type the unsupported enum constant; its declaring class and name are reported in the
   *     message.
   * @param s additional context appended to the message (may be empty).
   */
  public UnsupportedTypeException(Enum<?> type, String s) {
    super("Unsupported " + type.getDeclaringClass().getName() + " " + type.name() + " used. " + s);
  }

  /**
   * Creates an exception describing the unsupported enum value with no additional context.
   *
   * @param type the unsupported enum constant.
   */
  public UnsupportedTypeException(Enum<?> type) {
    this(type, "");
  }
}
