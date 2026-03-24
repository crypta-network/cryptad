package network.crypta.io.comm;

import java.io.Serial;
import network.crypta.support.LightweightException;

/**
 * Indicates that an operation requiring an active peer connection was attempted when no connection
 * existed.
 *
 * <p>This exception commonly occurs when sending a message to a peer that is not currently
 * connected. It is distinct from {@link DisconnectedException}, which signals that a previously
 * established connection dropped during a blocking wait. As a {@link LightweightException}, stack
 * traces may be omitted by default to keep the exception inexpensive in frequent control-flow
 * paths.
 *
 * @author amphibian
 * @see DisconnectedException
 * @see PeerRestartedException
 */
public class NotConnectedException extends LightweightException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Constructs an instance with a detail message.
   *
   * @param string human-readable detail; may be {@code null}.
   */
  public NotConnectedException(String string) {
    super(string);
  }

  /** Constructs an instance with no detail message. */
  public NotConnectedException() {
    super();
  }

  /**
   * Constructs an instance derived from a {@link DisconnectedException}.
   *
   * <p>The message is taken from {@code e.toString()}, and this exception's cause is initialized to
   * {@code e}. Useful when translating a mid-wait disconnect into a "not connected" condition for
   * higher layers.
   *
   * @param e the disconnection to wrap as the cause; must not be {@code null}.
   */
  public NotConnectedException(DisconnectedException e) {
    super(e.toString());
    initCause(e);
  }
}
