package network.crypta.clients.fcp;

import java.io.Serial;

/**
 * Signals that an FCP client attempted a file transfer that violates the node's configured
 * permissions.
 *
 * <p>This exception is raised when an upload targets a location the client is not permitted to read
 * from or when a download writes to a destination the client may not modify. It encapsulates the
 * access-control outcome rather than the underlying I/O failure so callers can distinguish between
 * authorization problems and transient transport or storage errors. Typical call chains surface it
 * from request validation layers before any bytes are transmitted, allowing the caller to log or
 * inform the user without retrying the same operation.
 *
 * <p>The class is immutable and thread-safe; instances hold no mutable state and are safe to reuse
 * across threads when bubbling through asynchronous handlers. Application code usually catches this
 * type alongside other {@link java.lang.SecurityException}-style failures to enforce sandboxing or
 * policy boundaries in higher-level workflows.
 *
 * <ul>
 *   <li>Identifies access-control violations in FCP file exchanges.
 *   <li>Distinguishes policy failures from transport or formatting errors.
 *   <li>Safe to propagate across threads and layers without additional synchronization.
 * </ul>
 *
 * @see java.lang.SecurityException
 */
public class NotAllowedException extends Exception {

  /**
   * Creates the exception for a disallowed transfer attempt while leaving the message unset.
   *
   * <p>The default constructor is useful when the calling layer chooses to attach context-specific
   * messages at higher levels, for example when bundling user-facing error responses that include
   * the attempted path or operation type. The resulting exception is idempotent and can be reused
   * in tests or helper utilities that simulate authorization failures without tying the instance to
   * a particular request. Callers may wrap it in broader fault containers if they need to attach
   * retry or remediation guidance.
   */
  public NotAllowedException() {
    // Default constructor intentionally leaves the message unset so callers can attach context
    // later.
  }

  @Serial private static final long serialVersionUID = 1L;
}
