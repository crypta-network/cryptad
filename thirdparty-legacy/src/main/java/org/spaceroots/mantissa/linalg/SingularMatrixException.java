package org.spaceroots.mantissa.linalg;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Exception thrown when an operation detects that a matrix is singular.
 *
 * <p>The exception signals that the algorithm could not proceed because the input matrix lacks a
 * full rank (for example, a zero determinant or linearly dependent rows), making results like
 * inversion, back-substitution, or stable factorization impossible. It is typically raised by
 * linear solvers, decompositions, or determinant computations when pivoting fails or when a zero
 * pivot is encountered. As an immutable exception type, it is safe to share across threads, but it
 * usually remains confined to the failing call site. Callers should catch it to either switch to a
 * regularization strategy, report a user-level validation error, or fall back to a pseudo-inverse
 * where appropriate.
 *
 * <ul>
 *   <li>Indicates the matrix cannot support the requested operation because it is rank deficient.
 *   <li>Conveys only the condition; it does not attempt recovery or store intermediate state.
 *   <li>Works alongside {@link MantissaException} to integrate with the broader Mantissa error
 *       model.
 * </ul>
 *
 * @version $Id: SingularMatrixException.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 * @see MantissaException
 */
public class SingularMatrixException extends MantissaException {

  /**
   * Creates a singular-matrix exception with the default diagnostic message.
   *
   * <p>The constructor always supplies the message {@code "singular matrix"}, which keeps error
   * handling deterministic and concise when downstream code does not need per-operation detail.
   * Because no additional context is stored, callers that need more nuance should wrap this
   * instance or provide supplementary logging at the detection site. Instantiation is inexpensive,
   * side-effect free, and does not perform any matrix inspection on its own.
   *
   * <pre>{@code
   * try {
   *   solver.solve(rhs);
   * } catch (SingularMatrixException ex) {
   *   // Trigger an alternate path such as regularization or user feedback.
   * }
   * }</pre>
   */
  public SingularMatrixException() {
    super("singular matrix");
  }

  @Serial private static final long serialVersionUID = 7531357987468317564L;
}
