package network.crypta.io.comm;

import java.io.Serial;
import network.crypta.support.LightweightException;

/**
 * Exception indicating that a block or related data could not be retrieved over the I/O
 * communication layer.
 *
 * <p>The reason for the failure is encoded as an integer {@linkplain #getReason() reason code}.
 * Human-readable forms are provided by {@link #getErrString()} and {@link #getErrString(int)}. The
 * {@link #toString()} and {@link #getMessage()} methods include both the canonical reason string
 * and an optional detail message.
 *
 * <p>This class extends {@link LightweightException}; consult that type for behavior differences
 * from {@link Exception} (e.g., message formatting or stack handling).
 *
 * @author ian
 */
public class RetrievalException extends LightweightException {
  @Serial private static final long serialVersionUID = 3257565105301500723L;

  /** Unspecified failure reason. */
  public static final int UNKNOWN = 0;

  /** Premature end of input while reading a block or message. */
  public static final int PREMATURE_EOF = 2;

  /** Underlying I/O error occurred during transfer. */
  public static final int IO_ERROR = 3;

  /** Sender terminated unexpectedly during the transfer. */
  public static final int SENDER_DIED = 5;

  /** Operation exceeded the allowed time. */
  public static final int TIMED_OUT = 4;

  /** The requested block already exists locally; retrieval not performed. */
  public static final int ALREADY_CACHED = 6;

  /** Sender disconnected before completion. */
  public static final int SENDER_DISCONNECTED = 7;

  /** Data insert is unavailable or not permitted for this operation. */
  public static final int NO_DATAINSERT = 8;

  /** Transfer was canceled by the receiver. */
  public static final int CANCELLED_BY_RECEIVER = 9;

  /** Receiver terminated unexpectedly during the transfer. */
  public static final int RECEIVER_DIED = 11;

  /** Could not send a block within the configured timeout. */
  public static final int UNABLE_TO_SEND_BLOCK_WITHIN_TIMEOUT = 12;

  /** Transfer aborted because the peer switched to turtle mode. */
  public static final int GONE_TO_TURTLE_MODE = 13;

  /** Transfer aborted because the turtle job/session was terminated. */
  public static final int TURTLE_KILLED = 14;

  // Numeric reason code; one of the public constants above.
  final int reason;
  // Optional human-readable detail for diagnostics (may be empty).
  final String cause;

  /**
   * Creates an instance with the given reason code.
   *
   * @param reason one of the public reason code constants defined in this class
   */
  public RetrievalException(int reason) {
    this.reason = reason;
    this.cause = getErrString(reason);
  }

  /**
   * Creates an instance with the given reason code and a detail message.
   *
   * <p>If {@code cause} is {@code null}, empty, or the literal {@code "null"}, the canonical reason
   * string from {@link #getErrString(int)} is used instead.
   *
   * @param reason one of the public reason code constants defined in this class
   * @param cause optional detail message for logging or diagnostics
   */
  public RetrievalException(int reason, String cause) {
    this.reason = reason;
    this.cause =
        cause == null || cause.isEmpty() || cause.equals("null") ? getErrString(reason) : cause;
  }

  /**
   * Returns the numeric reason code associated with this failure.
   *
   * @return one of the public reason code constants defined in this class
   */
  public int getReason() {
    return reason;
  }

  /**
   * Returns a concise description in the form {@code REASON:detail}. The reason token contains no
   * spaces, which simplifies parsing in logs and diagnostics.
   */
  @Override
  public String toString() {
    return getErrString(reason) + ":" + cause;
  }

  /**
   * Returns the canonical reason token for this instance.
   *
   * <p>The token contains no spaces to remain stable in logs and machine parsing.
   *
   * @return a non-null, no-space canonical token for the reason code
   */
  public String getErrString() {
    return getErrString(reason);
  }

  /**
   * Maps a reason code to its canonical token.
   *
   * @param reason a numeric reason code
   * @return a non-null, no-space canonical token describing the reason code; {@code "UNKNOWN (n)"}
   *     for unrecognized values
   */
  public static String getErrString(int reason) {
    return switch (reason) {
      case PREMATURE_EOF -> "PREMATURE_EOF";
      case IO_ERROR -> "IO_ERROR";
      case SENDER_DIED -> "SENDER_DIED";
      case TIMED_OUT -> "TIMED_OUT";
      case ALREADY_CACHED -> "ALREADY_CACHED";
      case SENDER_DISCONNECTED -> "SENDER_DISCONNECTED";
      case NO_DATAINSERT -> "NO_DATAINSERT";
      case CANCELLED_BY_RECEIVER -> "CANCELLED_BY_RECEIVER";
      case UNKNOWN -> "UNKNOWN";
      case UNABLE_TO_SEND_BLOCK_WITHIN_TIMEOUT -> "UNABLE_TO_SEND_BLOCK_WITHIN_TIMEOUT";
      case GONE_TO_TURTLE_MODE -> "GONE_TO_TURTLE_MODE";
      case TURTLE_KILLED -> "TURTLE_KILLED";
      default -> "UNKNOWN (" + reason + ")";
    };
  }

  /** Returns the detail message. Equivalent to {@link #toString()}. */
  @Override
  public String getMessage() {
    return toString();
  }
}
