package org.spaceroots.mantissa.estimation;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Exception type signaled when an estimation process cannot continue.
 *
 * <p>This domain-specific subclass of {@link MantissaException} is raised by estimation solvers
 * when they encounter conditions that prevent producing a reliable result. Typical triggers include
 * inconsistent problem definitions, divergence detected by the optimizer, or numerical issues such
 * as ill-conditioned matrices. Library callers are expected to catch this exception to surface
 * actionable feedback to users or to retry with adjusted parameters rather than masking the failure
 * as a generic {@link RuntimeException}.
 *
 * <p>Instances are effectively immutable after construction; no mutable state beyond the captured
 * message and cause is retained. They are therefore safe to share across threads once created, even
 * though creation is usually scoped to a single failing computation. The superclass provides the
 * localization and formatting support, so messages can be prepared in a user-facing language while
 * still conveying the original technical context.
 *
 * <ul>
 *   <li>Responsibility: represent estimation-related failures with optional localization support.
 *   <li>Typical flow: created inside solvers, propagated to clients, logged or displayed with full
 *       context.
 *   <li>Thread-safety: immutable contents permit safe reporting from background worker threads.
 * </ul>
 *
 * @version $Id: EstimationException.java 1681 2005-12-16 11:13:28Z luc $
 * @author L. Maisonobe
 */
public class EstimationException extends MantissaException {

  /**
   * Creates an exception with a plain, already translated message.
   *
   * <p>Use this constructor when the caller already holds a user-facing description of the problem
   * and no additional formatting is required. The message is forwarded to the base class, which may
   * apply any configured localization or resource-bundle lookup while preserving the supplied text.
   * The resulting exception can be thrown directly or wrapped inside higher-level error handling
   * that performs retries or user notifications. Because the message is captured verbatim, prefer
   * concise wording that identifies the failing operation and any relevant input values.
   *
   * @param message human-readable explanation describing estimation failure scenario
   */
  public EstimationException(String message) {
    super(message);
  }

  /**
   * Creates an exception whose message is built from a specifier and parts.
   *
   * <p>This variant supports parameterized, potentially localized messages handled by {@link
   * MantissaException}. The {@code specifier} is looked up and translated by the underlying message
   * infrastructure, and the provided {@code parts} are inserted without translation. This is useful
   * when solver errors need to include dynamic values such as iteration counts or residual norms
   * while keeping the outer template managed centrally. Ensure that the parts array matches the
   * placeholders expected by the specifier to avoid malformed output.
   *
   * <pre>{@code
   * // Example: combine a translated template with dynamic values
   * throw new EstimationException("estimation.residual.too.large",
   *     new String[] {String.valueOf(residual)});
   * }</pre>
   *
   * @param specifier format specifier translated by the Mantissa message framework
   * @param parts ordered insertion values, kept as literals without translation
   */
  public EstimationException(String specifier, String[] parts) {
    super(specifier, parts);
  }

  /**
   * Creates an exception that wraps an underlying cause.
   *
   * <p>Choose this constructor when another exception triggered the estimation failure and that
   * original context must be preserved. The cause is attached using standard exception chaining so
   * stack traces remain intact. Callers may add a localized message later using higher-level error
   * handlers, or they can rethrow this instance directly to signal that the solver aborted due to a
   * downstream error such as I/O, invalid input preparation, or arithmetic overflow. The cause must
   * be non-null to retain a meaningful diagnostic chain.
   *
   * @param cause originating exception that forced the estimation process to abort
   */
  public EstimationException(Throwable cause) {
    super(cause);
  }

  @Serial private static final long serialVersionUID = 1613719630569355278L;
}
