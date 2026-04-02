package network.crypta.clients.fcp;

import java.io.Serial;

/**
 * Signals that a client-supplied identifier conflicts with one already registered in the FCP
 * session or broader node context. The exception travels on the client-facing surface of the
 * protocol layer so callers can distinguish collision failures from transport issues or generic
 * validation errors. It carries no mutable state beyond the inherited message/cause chain, keeping
 * instances lightweight and safe to propagate across threads, log, or retry pipelines without
 * additional guarding. Typical usage is to throw this exception from code that rejects the
 * conflicting identifier immediately and then map it to an {@code IdentifierCollision} reply for
 * wire transmission.
 *
 * <p>Callers may choose whether to attach a human-readable message; a null message remains valid
 * and preserves symmetry with the zero-argument constructor. Because this type extends {@link
 * Exception}, it is a checked signal and encourages explicit handling at boundaries where
 * user-supplied identifiers are parsed or reserved. It intentionally avoids automatic fallback
 * behavior so the application can present clearer guidance to the user about selecting a unique
 * identifier.
 *
 * <ul>
 *   <li>Used when an identifier cannot be accepted due to duplication.
 *   <li>Intended for immediate propagation to client-visible error mapping.
 *   <li>Immutable and thread-safe; contains only the standard exception payload.
 * </ul>
 *
 * @see IdentifierCollisionMessage
 * @see FCPMessage
 */
public class IdentifierCollisionException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates a new collision exception with no detail message so callers may add context later or
   * rely on higher-level error mapping to produce user-facing text. The cause remains unset, which
   * keeps the instance lightweight when constructed on hot paths where collisions are expected and
   * not indicative of infrastructure failure.
   */
  public IdentifierCollisionException() {
    // Intentionally empty: state lives in the base Exception and defaults suffice for collision
    // signalling without extra payload.
  }
}
