package org.spaceroots.mantissa.algebra;

import java.io.Serial;

/**
 * Family of orthogonal Hermite polynomials generated from a three-term recurrence.
 *
 * <p>Instances of this class represent a single Hermite polynomial of a chosen degree while sharing
 * a static {@link CoefficientsGenerator} that lazily computes and caches coefficient sequences for
 * all degrees on demand. The family follows the physicists' normalization where the seed
 * polynomials are {@code H0(X) = 1} and {@code H1(X) = 2X}, and higher orders satisfy the
 * recurrence {@code H_{k+1}(X) = 2X H_k(X) - 2k H_{k-1}(X)}. Construction copies the cached
 * coefficients into the immutable array maintained by {@link Polynomial.Rational}, so subsequent
 * calls to {@link #valueAt(double)} or algebraic operations inherited from the base class do not
 * trigger further computation. The generator itself is synchronized during expansion, making read
 * access thread-safe as long as callers do not mutate the shared {@link RationalNumber} instances.
 *
 * <p>Use this type when analytic Hermite polynomials are needed for interpolation kernels, Gaussian
 * quadrature, or probabilistic Hermite expansions. Typical usage constructs the desired degree once
 * and evaluates it repeatedly at various points. Performance is dominated by a one-time coefficient
 * generation step per degree, after which evaluations run in {@code O(n)} time where {@code n} is
 * the polynomial degree. Because the class is immutable and side-effect free after generation,
 * instances can be cached or reused across threads without additional locking. The implementation
 * does not attempt any rescaling or probabilists' variant; callers needing those forms should wrap
 * or post-process the coefficients accordingly.
 *
 * <ul>
 *   <li>Physicists' Hermite definition with leading term {@code 2^n X^n}.
 *   <li>Coefficient storage is immutable per instance; generator expansion is synchronized.
 *   <li>Suitable for deterministic evaluation, differentiation, and polynomial algebra operations.
 * </ul>
 *
 * @see OrthogonalPolynomial
 * @see CoefficientsGenerator
 * @version $Id: Hermite.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class Hermite extends OrthogonalPolynomial {

  /** Generator for the Hermite polynomials. */
  private static final CoefficientsGenerator generator =
      new CoefficientsGenerator(
          new RationalNumber(1L), new RationalNumber(0L), new RationalNumber(2L)) {
        @Override
        public void setRecurrenceCoefficients(int k) {
          // the recurrence relation is
          // Hk+1(X) = 2X Hk(X) - 2k Hk-1(X)
          setRecurrenceCoefficients(
              new RationalNumber(0L), new RationalNumber(2L), new RationalNumber(k * 2L));
        }
      };

  /**
   * Creates the constant Hermite polynomial {@code H0}.
   *
   * <p>This constructor binds the instance to the shared Hermite coefficients generator and selects
   * degree {@code 0}. The resulting polynomial evaluates to {@code 1} for every input and serves as
   * the seed for higher-order Hermite polynomials. Use this overload when the degree is known to be
   * zero or when you need a canonical constant polynomial that participates correctly in the
   * recurrence relation without additional setup.
   */
  public Hermite() {
    super(0, generator);
  }

  /**
   * Creates a Hermite polynomial of the specified degree using the shared generator.
   *
   * <p>The constructor requests the coefficient sequence for {@code degree} from the static
   * generator, triggering lazy expansion if that degree has not been built previously. Degrees must
   * be zero or positive; negative values will propagate to generator logic and typically result in
   * an {@link ArrayIndexOutOfBoundsException}. Constructed instances are immutable and can be
   * evaluated or combined with other {@link Polynomial.Rational} objects without further
   * allocations. Generation cost grows linearly with {@code degree}, whereas subsequent evaluations
   * and derivative computations remain {@code O(degree)}.
   *
   * @param degree non-negative order of the Hermite polynomial to build; {@code 0} yields {@code
   *     H0}, {@code 1} yields {@code H1}, and larger values follow the standard physicists'
   *     sequence.
   */
  public Hermite(int degree) {
    super(degree, generator);
  }

  @Serial private static final long serialVersionUID = 7910082423686662133L;
}
