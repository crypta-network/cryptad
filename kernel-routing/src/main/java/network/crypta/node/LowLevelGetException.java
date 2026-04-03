package network.crypta.node;

import java.io.Serial;
import network.crypta.support.LightweightException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exception representing a failure during a low-level GET operation in the node.
 *
 * <p>The {@link #code} field carries a stable integer reason that callers can use for programmatic
 * handling (for example, deciding whether to retry or abort). Use {@link #getMessage(int)} to
 * obtain a concise, human-readable description for logs or operator messages; do not branch on the
 * returned text.
 *
 * <p>To limit allocation cost on hot paths, this exception omits the stack trace unless debug
 * logging is enabled or the reason suggests a potential defect; see {@link
 * #shouldFillInStackTrace()}.
 *
 * <p>Thread-safety: instances are effectively immutable and may be shared across threads.
 */
public class LowLevelGetException extends LightweightException {
  private static final Logger LOG = LoggerFactory.getLogger(LowLevelGetException.class);

  @Serial private static final long serialVersionUID = 1L;

  /** Decode of retrieved data fails; the payload is invalid or corrupt. */
  public static final int DECODE_FAILED = 1;

  /** Data is absent from the local store and the request is local-only. */
  public static final int DATA_NOT_FOUND_IN_STORE = 2;

  /** An internal error occurs (unexpected state or bug). */
  public static final int INTERNAL_ERROR = 3;

  /** Maximum search effort reached without finding the data; it may not exist. */
  public static final int DATA_NOT_FOUND = 4;

  /** Not enough viable nodes are available to continue routing toward the target. */
  public static final int ROUTE_NOT_FOUND = 5;

  /** A downstream node is overloaded and rejects the request; callers typically back off. */
  public static final int REJECTED_OVERLOAD = 6;

  /** Data transfer starts but does not complete successfully. */
  public static final int TRANSFER_FAILED = 7;

  /** Data is received but fails node-key validation (prior to higher-level decode). */
  public static final int VERIFY_FAILED = 8;

  /** Request is cancelled by the caller. */
  public static final int CANCELLED = 9;

  /** Blocked by the local failure table due to a recent downstream failure. */
  public static final int RECENTLY_FAILED = 10;

  /**
   * Returns a concise description for a failure {@code reason} code.
   *
   * <p>The returned text is intended for logs and operator output. Prefer branching on the integer
   * code instead of this text.
   *
   * @param reason one of this class's public constants
   * @return a short, human-readable description
   */
  public static String getMessage(int reason) {
    return switch (reason) {
      case DECODE_FAILED -> "Decode of data failed, probably was bogus at source";
      case DATA_NOT_FOUND_IN_STORE -> "Data was not in store and request was local-only";
      case INTERNAL_ERROR -> "Internal error - probably a bug";
      case DATA_NOT_FOUND -> "Could not find the data";
      case ROUTE_NOT_FOUND ->
          "Could not find enough nodes to be sure that the data is not out there somewhere";
      case REJECTED_OVERLOAD -> "A node downstream either timed out or was overloaded (retry)";
      case TRANSFER_FAILED -> "Started to transfer data, then failed (should be rare)";
      case VERIFY_FAILED -> "Node sent us invalid data";
      case CANCELLED -> "Request cancelled";
      case RECENTLY_FAILED ->
          "Request killed by failure table due to recently DNFing on a downstream node";
      default -> "Unknown error code: " + reason;
    };
  }

  /** Failure reason code for this instance; see the public constants for possible values. */
  public final int code;

  /**
   * Constructs an instance with an explicit message and cause.
   *
   * @param code failure reason (one of the defined constants)
   * @param message detail message; not {@code null}
   * @param t optional cause; may be {@code null}
   */
  public LowLevelGetException(int code, String message, Throwable t) {
    super(message, t);
    this.code = code;
  }

  /**
   * Constructs an instance with an explicit message and no cause.
   *
   * @param code failure reason (one of the defined constants)
   * @param message detail message; not {@code null}
   */
  public LowLevelGetException(int code, String message) {
    super(message);
    this.code = code;
  }

  /**
   * Constructs an instance using the default description for {@code reason}.
   *
   * @param reason failure reason (one of the defined constants)
   */
  public LowLevelGetException(int reason) {
    super(getMessage(reason));
    this.code = reason;
  }

  /**
   * Constructs an instance using the default description for {@code reason} and attaches a cause.
   *
   * @param reason failure reason (one of the defined constants)
   * @param t optional cause; may be {@code null}
   */
  public LowLevelGetException(int reason, Throwable t) {
    super(getMessage(reason), t);
    this.code = reason;
  }

  /** Returns the base exception string followed by the reason description. */
  @Override
  public String toString() {
    return super.toString() + ':' + getMessage(code);
  }

  /**
   * Indicates whether to capture a stack trace for this instance.
   *
   * <p>Returns {@code true} when debug logging is enabled or when the reason suggests a potential
   * defect ({@link #INTERNAL_ERROR}, {@link #DECODE_FAILED}, or {@link #VERIFY_FAILED}); otherwise
   * returns {@code false} to reduce allocation overhead.
   */
  @Override
  protected boolean shouldFillInStackTrace() {
    return LOG.isDebugEnabled()
        || code == INTERNAL_ERROR
        || code == DECODE_FAILED
        || code == VERIFY_FAILED;
  }
}
