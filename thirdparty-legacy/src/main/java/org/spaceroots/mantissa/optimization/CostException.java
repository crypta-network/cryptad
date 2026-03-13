package org.spaceroots.mantissa.optimization;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Signals a failure while evaluating a cost function during an optimization pass.
 *
 * <p>This exception wraps problems that occur inside user-supplied cost computations, including
 * numerical issues, invalid arguments, or domain-specific precondition breaches. Optimizers can
 * propagate it unchanged to callers so they can distinguish cost-evaluation failures from broader
 * algorithmic errors. The class is intentionally lightweight and mostly carries context through its
 * message and cause chains; it does not attempt to normalize error states. Instances are typically
 * created close to the failing computation and rethrown up the stack without modification.
 *
 * <p>Design considerations:
 *
 * <ul>
 *   <li>Immutable state suitable for reuse in multithreaded solver workflows.
 *   <li>Preserves the original cause to aid post-mortem diagnostics.
 *   <li>Intended for deterministic, synchronous evaluation phases rather than asynchronous tasks.
 * </ul>
 *
 * @version $Id: CostException.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public class CostException extends MantissaException {

  /**
   * Builds an exception with a generic message for unspecified cost failures.
   *
   * <p>Use this when the caller has little contextual information yet still needs to signal that a
   * cost computation aborted. The default text keeps logs readable without leaking sensitive
   * inputs. The instance is fully initialized on construction and can be safely rethrown across
   * threads if the calling pattern requires it.
   */
  @SuppressWarnings("unused")
  public CostException() {
    super("cost exception");
  }

  /**
   * Builds an exception with a caller-supplied message describing the failure.
   *
   * <p>This overload is preferred when the cost computation can supply a concise, user-facing error
   * detail such as a parameter range violation or an unexpected data shape. The message is stored
   * as provided; callers remain responsible for omitting sensitive identifiers.
   *
   * @param message human-readable explanation of the evaluation failure; never null
   */
  @SuppressWarnings("unused")
  public CostException(String message) {
    super(message);
  }

  /**
   * Builds an exception that primarily wraps another throwable cause.
   *
   * <p>Use this overload when the cost function encounters a lower-level exception (for example,
   * arithmetic overflows, I/O during data retrieval, or domain-specific validation errors). The
   * wrapper preserves the causal chain for diagnostics while clearly signaling that the cost phase
   * failed.
   *
   * @param cause underlying failure that triggered cost computation abort
   */
  @SuppressWarnings("unused")
  public CostException(Throwable cause) {
    super(cause);
  }

  /**
   * Builds an exception with both a custom message and a preserved cause.
   *
   * <p>This constructor is useful when callers need to enrich a lower-level exception with
   * additional context while keeping the original stack trace intact. The combination of message
   * and cause allows downstream handlers to present actionable diagnostics and still recover or
   * retry the optimization if appropriate.
   *
   * @param message descriptive text clarifying why evaluation could not proceed
   * @param cause underlying failure that led to the cost exception being raised
   */
  @SuppressWarnings("unused")
  public CostException(String message, Throwable cause) {
    super(message, cause);
  }

  @Serial private static final long serialVersionUID = -6099968585593678071L;
}
