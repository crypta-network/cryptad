package network.crypta.node;

import java.io.Serial;

/**
 * Signals that an operation remained blocked longer than the permitted duration.
 *
 * <p>The amount by which the allowed block duration was exceeded is exposed via {@link #delta}. The
 * time unit is defined by the code that throws this exception.
 */
public class BlockedTooLongException extends Exception {
  @Serial private static final long serialVersionUID = 1L;

  /** Amount by which the permitted block duration was exceeded; unit defined by the caller. */
  public final long delta;

  /**
   * Creates a new exception with the given excess blocking amount.
   *
   * @param delta amount by which the permitted block duration was exceeded; unit defined by the
   *     caller
   */
  public BlockedTooLongException(long delta) {
    this.delta = delta;
  }
}
