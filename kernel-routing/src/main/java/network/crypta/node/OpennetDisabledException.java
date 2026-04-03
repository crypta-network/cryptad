package network.crypta.node;

import java.io.Serial;

/**
 * Signals that an operation requires the opennet subsystem, but it is disabled for this node.
 *
 * <p>This is a checked exception used by node-facing runtime code to indicate that a caller
 * attempted to perform an opennet action when opennet is not enabled in the current runtime
 * configuration. The class is immutable and therefore thread-safe.
 */
public class OpennetDisabledException extends Exception {
  // Fixed UID to preserve serialization compatibility across releases.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an instance with an optional underlying cause.
   *
   * @param e the cause of this exception; may be {@code null} when no lower-level exception is
   *     available.
   */
  @SuppressWarnings("unused")
  public OpennetDisabledException(Exception e) {
    super(e);
  }

  /**
   * Creates an instance with a human-readable detail message.
   *
   * @param msg detail message describing the context of the failure; may be {@code null}.
   */
  public OpennetDisabledException(String msg) {
    super(msg);
  }
}
