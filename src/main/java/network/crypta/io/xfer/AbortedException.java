package network.crypta.io.xfer;

import java.io.Serial;

/**
 * Exception indicating that an I/O transfer was intentionally aborted.
 *
 * <p>Thrown by transfer components to signal that the current operation must cease immediately.
 * Callers should not continue using the associated transfer or its resources after this exception
 * is thrown, as doing so can cause races or inconsistent state. This exception represents a
 * cooperative cancellation condition rather than a programming error.
 */
public class AbortedException extends Exception {
  // Explicit ID to keep serialization stable across versions.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Constructs a new {@code AbortedException} with the specified detail message.
   *
   * @param msg human‑readable reason describing why the transfer was aborted
   */
  public AbortedException(String msg) {
    super(msg);
  }
}
