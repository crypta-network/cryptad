package network.crypta.io.comm;

import java.io.Serial;

/**
 * Indicates that a textual or structured peer description could not be parsed.
 *
 * <p>Thrown by code that converts external representations (for example, node references or address
 * strings) into {@link Peer} instances when the input is syntactically invalid or missing required
 * fields.
 *
 * @author amphibian
 */
public class PeerParseException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Constructs an instance that wraps a lower-level cause.
   *
   * @param e the underlying parsing failure; may be {@code null}.
   */
  public PeerParseException(Exception e) {
    super(e);
  }

  /** Constructs an instance with no detail message. */
  public PeerParseException() {
    super();
  }

  /**
   * Constructs an instance with a detail message.
   *
   * @param string human-readable detail; may be {@code null}.
   */
  public PeerParseException(String string) {
    super(string);
  }
}
