package network.crypta.clients.http;

import java.io.Serial;

/**
 * Exception indicating that a {@link ToadletContext} was closed before an operation such as writing
 * reply headers or response data could complete.
 *
 * <p>Handlers receive this checked exception when the underlying connection has been terminated by
 * the client or deliberately closed by server logic to protect protocol integrity. It allows
 * callers to abort processing cleanly without conflating the condition with generic I/O failures.
 * Typical usage is inside toadlet handlers that send headers or body content; if the context is
 * closed, the handler can skip further work or log and return. Instances are lightweight and carry
 * no additional state beyond the message chain.
 *
 * <p><strong>Notable behaviors</strong>
 *
 * <ul>
 *   <li>Signals a terminal state for the current request; retrying the same write is not expected
 *       to succeed.
 *   <li>Propagation is intentional to keep calling code aware of partial responses.
 * </ul>
 *
 * @see ToadletContext
 */
public class ToadletContextClosedException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Create a new exception with no detail message. Use when the caller only needs to indicate
   * closure without extra context.
   */
  public ToadletContextClosedException() {}

  /**
   * Create a new exception with a human-readable description of the closure scenario.
   *
   * @param message Detail message describing how or why the context was closed; may be {@code null}
   *     when no additional information is available.
   */
  public ToadletContextClosedException(String message) {
    super(message);
  }

  /**
   * Create a new exception with both a detail message and an underlying cause to preserve the
   * original failure context.
   *
   * @param message Text describing the closure condition; may be {@code null}.
   * @param cause Root cause such as an {@link java.io.IOException}; may be {@code null} when none
   *     is available.
   */
  public ToadletContextClosedException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Create a new exception that wraps a lower-level cause without adding a separate message.
   *
   * @param cause Triggering cause for the closure; may be {@code null}.
   */
  public ToadletContextClosedException(Throwable cause) {
    super(cause);
  }
}
