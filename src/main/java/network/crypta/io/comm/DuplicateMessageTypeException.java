package network.crypta.io.comm;

/**
 * Signals an attempt to register a {@link MessageType} whose registry identifier already exists.
 *
 * <p>The identifier is derived from the type's name via {@link String#hashCode()}. If another type
 * with the same key is already present in the registry, the registering code throws this unchecked
 * exception to prevent ambiguous decoding and inconsistent schemas.
 *
 * <p>Typical source: constructing a new {@link MessageType} with a name that collides with an
 * existing type.
 */
public class DuplicateMessageTypeException extends RuntimeException {
  /**
   * Creates the exception with a detail message.
   *
   * @param message detail text; often includes the conflicting type name
   */
  public DuplicateMessageTypeException(String message) {
    super(message);
  }
}
