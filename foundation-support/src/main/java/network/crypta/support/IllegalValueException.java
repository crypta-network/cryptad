package network.crypta.support;

/**
 * Signals that an input value is invalid for the current context.
 *
 * <p>This checked exception is used to indicate that a supplied value violates domain constraints,
 * format expectations, or other validation rules enforced by the caller. It is typically thrown by
 * parsing and validation utilities to provide a precise, user-facing error message.
 */
public class IllegalValueException extends Exception {

  /**
   * Creates a new exception describing why the value is considered invalid.
   *
   * @param message human-readable detail used by {@link #getMessage()}
   */
  public IllegalValueException(String message) {
    super(message);
  }
}
