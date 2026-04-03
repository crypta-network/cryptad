package network.crypta.node;

import java.io.Serial;
import network.crypta.keys.KeyBlock;

/**
 * Exception representing a failure during a low-level PUT operation in the node.
 *
 * <p>The {@link #code} field carries a stable integer reason that callers can use for retry,
 * overload handling, or collision-specific behavior. For collision cases, {@link
 * #getCollidedBlock()} exposes the conflicting block when one is available. Instances are
 * effectively immutable and safe to share across threads.
 */
public class LowLevelPutException extends Exception {
  @Serial private static final long serialVersionUID = 1L;

  /** An internal error occurred */
  public static final int INTERNAL_ERROR = 1;

  /** The request could not go enough hops to store the data properly. */
  public static final int ROUTE_NOT_FOUND = 2;

  /**
   * A downstream node is overloaded, and rejected the insert. We should reduce our rate of sending
   * inserts.
   */
  public static final int REJECTED_OVERLOAD = 3;

  /** Insert could not get off the node at all */
  public static final int ROUTE_REALLY_NOT_FOUND = 4;

  /** Insert collided with pre-existing, different content. Can only happen with KSKs and SSKs. */
  public static final int COLLISION = 5;

  /** Failure code */
  public final int code;

  private final transient KeyBlock collidedBlock;

  static String getMessage(int reason) {
    return switch (reason) {
      case INTERNAL_ERROR -> "Internal error - probably a bug";
      case ROUTE_NOT_FOUND -> "Could not store the data on enough nodes";
      case REJECTED_OVERLOAD -> "A node downstream either timed out or was overloaded (retry)";
      case ROUTE_REALLY_NOT_FOUND -> "The insert could not get off the node at all";
      case COLLISION ->
          "The insert collided with different data of the same key already on the network";
      default -> "Unknown error code: " + reason;
    };
  }

  /**
   * Constructs an instance with an explicit message and cause.
   *
   * @param code failure reason (one of the defined constants)
   * @param message detail message; not {@code null}
   * @param t optional cause; may be {@code null}
   */
  public LowLevelPutException(int code, String message, Throwable t) {
    super(message, t);
    this.code = code;
    this.collidedBlock = null;
  }

  /**
   * Constructs an instance using the default description for {@code reason}.
   *
   * @param reason failure reason (one of the defined constants)
   */
  public LowLevelPutException(int reason) {
    super(getMessage(reason));
    this.code = reason;
    this.collidedBlock = null;
  }

  /**
   * Constructs a collision instance carrying the conflicting block.
   *
   * @param collided conflicting block returned by the datastore or peer handling path
   */
  public LowLevelPutException(KeyBlock collided) {
    super(getMessage(COLLISION));
    this.code = COLLISION;
    this.collidedBlock = collided;
  }

  /**
   * Returns the conflicting block when the failure reason is {@link #COLLISION}.
   *
   * @return the collided block for collision failures, or {@code null} for other failure reasons
   */
  public KeyBlock getCollidedBlock() {
    return collidedBlock;
  }
}
