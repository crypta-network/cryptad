package org.spaceroots.mantissa.algebra;

import java.io.Serial;

/**
 * Family of Chebyshev polynomials of the first kind backed by the generic {@link
 * OrthogonalPolynomial} infrastructure.
 *
 * <p>Instances model a single polynomial {@code T_n(x)} with exact rational coefficients computed
 * from the standard three-term recurrence. The family is generated lazily by an internal {@link
 * CoefficientsGenerator}; once created, an instance is immutable and thread-safe as long as the
 * shared generator is not mutated concurrently (the provided generator performs synchronized
 * caching). Use this type when you need numerically stable orthogonal bases for approximation,
 * quadrature, or filter design while retaining exact coefficient arithmetic rather than floating
 * point rounding.
 *
 * <p><strong>Construction and recurrence</strong>
 *
 * <ul>
 *   <li>{@code T_0(x) = 1}
 *   <li>{@code T_1(x) = x}
 *   <li>{@code T_{k+1}(x) = 2x T_k(x) - T_{k-1}(x)}
 * </ul>
 *
 * Typical usage is to instantiate the required degree and immediately evaluate it via {@link
 * Polynomial#valueAt(double)} or derive related forms (for example, computing {@link
 * Polynomial#getDerivative() derivatives}). Coefficients are exposed through the inherited {@code
 * getCoefficients()} method in low-to-high degree order. The class does not normalize inputs; call
 * sites are expected to keep {@code |x| ≤ 1} when exploiting the cosine identity {@code
 * T_n(x)=cos(n arccos x)}.
 *
 * @version $Id: Chebyshev.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class Chebyshev extends OrthogonalPolynomial {

  /** Generator for the Chebyshev polynomials. */
  private static final CoefficientsGenerator generator =
      new CoefficientsGenerator(
          new RationalNumber(1L), new RationalNumber(0L), new RationalNumber(1L)) {
        public void setRecurrenceCoefficients(int k) {
          // the recurrence relation is
          // Tk+1(X) = 2X Tk(X) - Tk-1(X)
          setRecurrenceCoefficients(
              new RationalNumber(0L), new RationalNumber(2L), new RationalNumber(1L));
        }
      };

  /**
   * Create the constant Chebyshev polynomial {@code T_0(x) = 1}.
   *
   * <p>The resulting instance has degree 0, evaluates to {@code 1} for any input, and serves as the
   * seed element of the family. Construction triggers the generator only for the base term, so it
   * is inexpensive and side-effect free beyond cached coefficient storage.
   */
  public Chebyshev() {
    super(0, generator);
  }

  /**
   * Create the Chebyshev polynomial of the specified degree.
   *
   * <p>The degree must be zero or positive; negative values will propagate to the underlying
   * generator and typically yield an {@link IndexOutOfBoundsException}. Coefficients are computed
   * exactly using the canonical recurrence and cached for reuse. The returned polynomial is
   * immutable and may be evaluated multiple times without additional allocations.
   *
   * @param degree non-negative degree of the polynomial to construct within the Chebyshev family
   */
  public Chebyshev(int degree) {
    super(degree, generator);
  }

  @Serial private static final long serialVersionUID = -893367988717182601L;
}
