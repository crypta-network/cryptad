package network.crypta.client.filter;

import java.io.Serial;

/**
 * Exception indicating that a client-side content filtering operation failed in a way that
 * generated explanatory text intended for presentation to a human consumer.
 *
 * <p>This exception is raised by filters when they detect input that cannot be safely or
 * meaningfully transformed according to the active filtering rules. In addition to signaling
 * failure, the exception message typically carries a short, human-readable explanation that the
 * caller may render to a log, UI, or diagnostics channel. The message is deliberately kept as raw
 * text: it is <em>not</em> HTML- or XML-encoded, and it may include characters derived from the
 * analyzed content. Callers are responsible for choosing an appropriate output channel and
 * performing any necessary escaping or localization before display.
 *
 * <p>Typical usage is to catch this exception at an integration boundary (for example, a request
 * handler, pipeline controller, or UI adapter), record the failure for observability, and present a
 * concise, user-facing explanation. The type is immutable and conveys no retry semantics by itself;
 * retry policies, if any, should be decided by the caller based on broader context.
 *
 * <ul>
 *   <li>The message may be data-dependent and must be sanitized before presentation.
 *   <li>Intended for control-flow and user guidance, not for low-level I/O errors.
 *   <li>Thread-safe to share after construction; instances are immutable.
 * </ul>
 */
public class CommentException extends Exception {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Creates a new exception with an explanatory message suitable for presentation to a human
   * reader.
   *
   * <p>The supplied message is treated as raw, unencoded text and may contain characters derived
   * from the analyzed content. The caller is responsible for escaping or otherwise preparing it for
   * the output medium (for example, HTML, JSON, or plain logs) and for ensuring that sensitive data
   * is not disclosed. Instances created by this constructor are immutable and thread-safe to share
   * between threads for reporting purposes.
   *
   * @param msg Human-oriented explanation of the filtering failure. Provide concise, actionable
   *     text suitable for logs or UI; must be sanitized and encoded by the caller before display.
   */
  public CommentException(String msg) {
    super(msg);
  }
}
