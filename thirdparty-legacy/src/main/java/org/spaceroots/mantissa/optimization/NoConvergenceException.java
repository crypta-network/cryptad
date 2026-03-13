package org.spaceroots.mantissa.optimization;

import org.spaceroots.mantissa.MantissaException;

/**
 * Signals that an iterative optimization process stopped without satisfying its convergence
 * criteria.
 *
 * <p>Instances of this exception are raised by optimization routines when they exhaust their
 * allowed iterations, diverge from the search domain, or otherwise fail to meet the configured
 * termination thresholds. Library callers typically catch this type to surface a user-facing
 * message, adjust tolerances, or restart the search with a different initial guess. The class is
 * immutable and therefore thread-safe; it contains only the translated message components supplied
 * at construction time. Typical usage flows include propagating the exception directly from a
 * solver, translating the message for UI display, or logging the failure alongside the iteration
 * count and residual norm.
 *
 * <ul>
 *   <li>Represents non-fatal termination of optimization algorithms.
 *   <li>Conveys formatted, localized details about the convergence failure.
 *   <li>Intended to be handled by callers that can retry or relax constraints.
 * </ul>
 *
 * @version $Id: NoConvergenceException.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 * @see MantissaException
 */
public class NoConvergenceException extends MantissaException {

  /**
   * Builds the exception with a translated, formatted message describing the convergence failure.
   *
   * <p>The {@code specifier} is looked up in the localization bundles managed by {@link
   * MantissaException} and combined with the provided message {@code parts}. Callers should supply
   * placeholders that describe the algorithm, stopping criterion, or iteration counts so downstream
   * consumers can act on the details. This constructor performs no computation and is side-effect
   * free, making it safe to create eagerly before the point where the optimization is aborted.
   *
   * @param specifier message template key to translate into the current locale; must not be {@code
   *     null}
   * @param parts arguments inserted into the localized template in declaration order; entries may
   *     be {@code null} if the format accepts them
   */
  public NoConvergenceException(String specifier, String[] parts) {
    super(specifier, parts);
  }

  @SuppressWarnings("MissingSerialAnnotation")
  private static final long serialVersionUID = 4854864422540042859L;
}
