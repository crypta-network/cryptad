package org.spaceroots.mantissa.algebra;

import java.io.Serial;

/**
 * Implements the classical (alpha&nbsp;=&nbsp;0) Laguerre orthogonal polynomials.
 *
 * <p>The Laguerre family forms an orthogonal basis on the half-line with weight function {@code
 * exp(-x)}, and it often appears in numerical quadrature, spectral methods for diffusion problems,
 * and the radial part of solutions to the hydrogen atom Schrödinger equation. Instances of this
 * class represent a single polynomial of a chosen degree; coefficients are generated through the
 * shared {@link CoefficientsGenerator} and cached by the {@link OrthogonalPolynomial} base class,
 * so constructed objects are immutable and safe to reuse across threads as long as the shared
 * generator is not mutated concurrently. Typical usage is to build one or more instances to
 * evaluate their values or derivatives over non-negative arguments, or to combine them in weighted
 * sums when forming approximations over semi-infinite domains. Construction does not precompute
 * function values—only the exact rational coefficients—keeping memory usage modest while enabling
 * deterministic evaluation regardless of floating-point rounding. The implementation adheres to the
 * standard three-term recurrence below, which maintains numerical stability for moderate degrees
 * when paired with rational arithmetic inside the generator.
 *
 * <pre>{@code
 * L_0(X)             = 1
 * L_1(X)             = 1 - X
 * (k + 1) L_{k+1}(X) = (2k + 1 - X) L_k(X) - k L_{k-1}(X)
 * }</pre>
 *
 * <ul>
 *   <li>Produces immutable coefficients for each requested degree.
 *   <li>Shares a thread-safe generator to amortize recurrence computation.
 *   <li>Suited to algorithms on [0,&nbsp;∞) that rely on orthogonal polynomial bases.
 * </ul>
 *
 * @see OrthogonalPolynomial
 * @see CoefficientsGenerator
 * @version $Id: Laguerre.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class Laguerre extends OrthogonalPolynomial {

  /** Generator for the Laguerre polynomials. */
  private static final CoefficientsGenerator generator =
      new CoefficientsGenerator(
          new RationalNumber(1L), new RationalNumber(1L), new RationalNumber(-1L)) {
        public void setRecurrenceCoefficients(int k) {
          // the recurrence relation is
          // (k+1) Lk+1(X) = (2k + 1 - X) Lk(X) - k Lk-1(X)
          long kP1 = k + 1L;
          long twoKPlusOne = 2L * k + 1L;
          setRecurrenceCoefficients(
              new RationalNumber(twoKPlusOne, kP1),
              new RationalNumber(-1L, kP1),
              new RationalNumber(k, kP1));
        }
      };

  /**
   * Creates the degree-0 Laguerre polynomial {@code L_0(x) = 1}.
   *
   * <p>The constructor delegates to the shared generator to obtain the cached coefficient array for
   * the constant term and wraps it in an immutable {@link OrthogonalPolynomial} instance. Because
   * only coefficients are stored, the resulting object is lightweight and can be passed freely
   * across threads in numerical routines that evaluate or combine basis polynomials without further
   * synchronization. Use this overload when you need only the base polynomial—for example, as the
   * starting element of a recurrence-based evaluation scheme or as a fallback when a higher-degree
   * instance is unavailable.
   *
   * <pre>{@code
   * Laguerre l0 = new Laguerre();
   * // Coefficients now represent the constant polynomial 1
   * }</pre>
   */
  public Laguerre() {
    super(0, generator);
  }

  /**
   * Creates a Laguerre polynomial of the specified non-negative degree.
   *
   * <p>The supplied {@code degree} is forwarded to the shared generator, which computes and caches
   * the exact rational coefficients needed for that order before handing them to the immutable base
   * class. Callers should provide a zero or positive degree consistent with the classical Laguerre
   * sequence; negative values are not meaningful and may be rejected by lower-level validation in
   * the generator. The constructed instance is thread-safe to reuse in evaluators, integrators, or
   * basis expansions because it contains only immutable coefficient data after initialization.
   *
   * @param degree zero or positive order in the Laguerre sequence whose coefficients should be
   *     materialized and cached for subsequent evaluations
   */
  public Laguerre(int degree) {
    super(degree, generator);
  }

  @Serial private static final long serialVersionUID = 3213856667479179710L;
}
