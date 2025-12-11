package org.spaceroots.mantissa.random;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Exception indicating that a matrix expected to be positive definite is not.
 *
 * <p>This exception is raised by components that rely on positive definite covariance or
 * correlation matrices, most notably {@link CorrelatedRandomVectorGenerator}. A matrix fails this
 * requirement when a Cholesky decomposition cannot be computed or when at least one eigenvalue is
 * non-positive, which prevents generation of stable multivariate samples. Callers typically see
 * this error during parameter validation before any random vectors are produced, so no partial
 * output is emitted. The instance is immutable and therefore thread-safe to share across threads
 * when propagating diagnostics.
 *
 * <ul>
 *   <li>Signals invalid covariance input for correlated random vector generation.
 *   <li>Encourages callers to sanitize and recondition matrices before invocation.
 *   <li>Captures a human-readable detail message to aid logging and troubleshooting.
 * </ul>
 *
 * @version $Id: NotPositiveDefiniteMatrixException.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 * @see CorrelatedRandomVectorGenerator
 */
public class NotPositiveDefiniteMatrixException extends MantissaException {

  /**
   * Create an exception with a default diagnostic message.
   *
   * <p>The default text, {@code "not positive definite matrix"}, mirrors the most common failure
   * condition encountered when preparing covariance data. Use this constructor when no additional
   * context is needed or when the exception is immediately wrapped by a higher-level handler. The
   * resulting object is immutable and may be safely reused or logged without further protection.
   */
  public NotPositiveDefiniteMatrixException() {
    super("not positive definite matrix");
  }

  /**
   * Create an exception with the specified diagnostic message.
   *
   * <p>This variant allows the caller to embed matrix dimensions, conditioning metrics, or
   * algorithm-specific hints so downstream handlers can present actionable guidance. The supplied
   * message is stored verbatim; callers should avoid including sensitive data because exception
   * text may be surfaced in logs.
   *
   * @param message detail text describing the positive-definiteness failure, never {@code null} in
   *     typical use even though not enforced by the constructor
   */
  @SuppressWarnings("unused")
  public NotPositiveDefiniteMatrixException(String message) {
    super(message);
  }

  @Serial private static final long serialVersionUID = -6801349873804445905L;
}
