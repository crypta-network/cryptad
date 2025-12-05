package org.spaceroots.mantissa.algebra;

import java.io.Serial;

/**
 * Implements the classical family of Legendre polynomials.
 *
 * <p>Legendre polynomials form an orthogonal basis on {@code [-1, 1]} with respect to the unit
 * weight function and appear widely in numerical integration, spectral methods, and solutions of
 * boundary-value problems. Each instance of this class represents one polynomial of the sequence
 * and delegates coefficient generation to a shared {@link CoefficientsGenerator}, which applies the
 * canonical three-term recurrence
 *
 * <pre>{@code
 * P_0(x)              = 1
 * P_1(x)              = x
 * (k + 1) P_{k+1}(x)  = (2k + 1) x P_k(x) - k P_{k-1}(x)
 * }</pre>
 *
 * <p>The constructed polynomial stores an immutable array of {@link RationalNumber} coefficients
 * produced by the generator; subsequent evaluations therefore incur no additional allocation. The
 * generator synchronizes its internal cache, so creating Legendre polynomials from multiple threads
 * is safe provided callers avoid mutating the returned coefficient arrays. Instances themselves are
 * immutable after construction, making them suitable for reuse in quadrature rule assembly or
 * orthogonal expansions where many evaluations of the same degree occur.
 *
 * <ul>
 *   <li>Encapsulates the standard Legendre recurrence with degree-zero and degree-one seeds.
 *   <li>Shares a synchronized generator to avoid recomputing coefficients across instances.
 *   <li>Provides serializable polynomial objects that can be cached or transmitted when needed.
 * </ul>
 *
 * @see OrthogonalPolynomial
 * @see Laguerre
 * @see Hermite
 * @see Chebyshev
 * @version $Id: Legendre.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class Legendre extends OrthogonalPolynomial {

  /** Generator for the Legendre polynomials. */
  private static final CoefficientsGenerator generator =
      new CoefficientsGenerator(
          new RationalNumber(1L), new RationalNumber(0L), new RationalNumber(1L)) {
        public void setRecurrenceCoefficients(int k) {
          // the recurrence relation is
          // (k+1) Pk+1(X) = (2k+1) X Pk(X) - k Pk-1(X)
          long kP1 = k + 1L;
          setRecurrenceCoefficients(
              new RationalNumber(0L),
              new RationalNumber(2L * k + 1, kP1),
              new RationalNumber(k, kP1));
        }
      };

  /**
   * Creates the degree-zero Legendre polynomial {@code P_0(x) = 1}.
   *
   * <p>The constructor requests the cached coefficients for degree zero from the shared generator,
   * yielding an immutable polynomial that evaluates to {@code 1} for every input. Construction is
   * idempotent and side-effect free beyond generator caching, so repeated instantiation incurs
   * negligible overhead and can be used freely in quadrature or normalization pipelines where the
   * constant polynomial is required as a baseline term.
   *
   * <pre>{@code
   * // Example: evaluate the constant polynomial
   * Legendre p0 = new Legendre();
   * double value = p0.value(0.3); // always 1.0
   * }</pre>
   */
  public Legendre() {
    super(0, generator);
  }

  /**
   * Creates a Legendre polynomial of the requested degree.
   *
   * <p>The generator expands its cache up to {@code degree} using the standard recurrence and
   * returns a read-only coefficient array that this instance reuses for all subsequent evaluations.
   * Callers should supply a zero or positive degree; negative values lead to undefined generator
   * behavior. Instances produced by this constructor are immutable and can be shared safely between
   * threads, though the underlying generator serializes concurrent expansions to guarantee coherent
   * coefficient sequences.
   *
   * <pre>{@code
   * // Example: build and evaluate P_3(x)
   * Legendre p3 = new Legendre(3);
   * double y = p3.value(0.25);
   * }</pre>
   *
   * @param degree zero or positive order within the Legendre family; negative values are invalid
   */
  public Legendre(int degree) {
    super(degree, generator);
  }

  @Serial private static final long serialVersionUID = 4014485393845978429L;
}
