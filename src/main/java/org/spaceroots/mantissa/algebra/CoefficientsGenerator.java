package org.spaceroots.mantissa.algebra;

import java.util.ArrayList;
import java.util.List;

/**
 * Generates polynomial coefficient sequences from a three-term recurrence definition.
 *
 * <p>This abstract helper stores successive polynomial coefficients in a compact triangular layout
 * and expands the sequence lazily as callers request higher degrees. Subclasses supply the per-step
 * recurrence ratios so the same infrastructure can build orthogonal or custom polynomial families
 * without duplicating accumulation logic. The generator begins with two seed polynomials provided
 * at construction time, keeps all computed coefficients in order, and avoids recomputation when
 * previously generated degrees are requested again.
 *
 * <p>Thread-safety is limited to synchronized expansion in {@link #getCoefficients(int)}; the
 * returned arrays reference the shared {@link RationalNumber} instances and should be treated as
 * read-only by callers. Subclasses remain responsible for supplying numerically stable recurrence
 * parameters and any desired normalization because this class does not rescale or adjust
 * coefficients after they are stored.
 *
 * <ul>
 *   <li>Initial state: degree 0 and degree 1 polynomials are supplied via the constructor.
 *   <li>Growth: higher degrees are generated when {@link #getCoefficients(int)} demands them and
 *       {@link #setRecurrenceCoefficients(int)} provides per-step ratios.
 *   <li>Storage: coefficients for all degrees share a single list using contiguous triangular
 *       indexing for constant-time lookups.
 * </ul>
 */
public abstract class CoefficientsGenerator {

  /**
   * Seeds the generator with the two initial polynomials used by the recurrence.
   *
   * <p>The first polynomial must be the constant {@code P0(X) = a00}. The second must be the degree
   * one polynomial {@code P1(X) = a01 + a11 * X}. These values are stored immediately and reused
   * verbatim when higher-order polynomials are derived from the recurrence relation. Callers are
   * expected to supply non-null {@link RationalNumber} instances that already express any desired
   * normalization or scaling for the polynomial family being generated.
   *
   * @param a00 constant term for the degree 0 polynomial, non-null rational value
   * @param a01 constant term for the degree 1 polynomial, defining {@code P1(0)}
   * @param a11 coefficient of {@code X} in the degree 1 polynomial, controls slope
   */
  protected CoefficientsGenerator(RationalNumber a00, RationalNumber a01, RationalNumber a11) {
    l = new ArrayList<>();
    l.add(a00);
    l.add(a01);
    l.add(a11);
    maxDegree = 1;
  }

  /**
   * Set the recurrence coefficients.
   *
   * <p>This helper stores the pre-normalized recurrence ratios used by {@link
   * #computeUpToDegree(int)} for the current step. It expects the caller (typically an overriding
   * {@link #setRecurrenceCoefficients(int)} implementation) to pass values that already incorporate
   * any division by {@code a1k}. The numbers are kept as-is; no validation, copying, or
   * normalization is performed, so callers should supply stable, non-null inputs suitable for
   * repeated arithmetic.
   *
   * @param b2k coefficient ratio {@code a2k / a1k}, applied to the constant component of the step
   * @param b3k coefficient ratio {@code a3k / a1k}, scaling the {@code X}-dependent contribution
   * @param b4k coefficient ratio {@code a4k / a1k}, multiplying the prior polynomial {@code
   *     O_{k-1}}
   */
  protected void setRecurrenceCoefficients(
      RationalNumber b2k, RationalNumber b3k, RationalNumber b4k) {
    this.b2k = b2k;
    this.b3k = b3k;
    this.b4k = b4k;
  }

  /**
   * Computes and installs recurrence ratios for the specified step.
   *
   * <p>Subclasses implement this hook to evaluate their recurrence model at index {@code k}, then
   * invoke {@link #setRecurrenceCoefficients(RationalNumber, RationalNumber, RationalNumber)} with
   * the derived {@code b2k}, {@code b3k}, and {@code b4k} values. The underlying relation follows
   * {@code a1k * O_{k+1}(X) = (a2k + a3k * X) * O_k(X) - a4k * O_{k-1}(X)}, so the provided ratios
   * should already reflect any division by {@code a1k}. Implementations should keep computations
   * lightweight because this method executes once for each degree added during expansion.
   *
   * @param k zero-based index of the polynomial currently being expanded in the sequence
   */
  protected abstract void setRecurrenceCoefficients(int k);

  /**
   * Compute all the polynomial coefficients up to a given degree.
   *
   * @param degree maximal degree
   */
  private void computeUpToDegree(int degree) {

    int startK = (maxDegree - 1) * maxDegree / 2;
    for (int k = maxDegree; k < degree; ++k) {

      // start indices of two previous polynomials Ok(X) and Ok-1(X)
      int startKm1 = startK;
      startK += k;

      // a1k Ok+1(X) = (a2k + a3k X) Ok(X) - a4k Ok-1(X)
      // we use bik = aik/a1k
      setRecurrenceCoefficients(k);

      RationalNumber ckPrev;
      RationalNumber ck = l.get(startK);
      RationalNumber ckm1 = l.get(startKm1);

      // degree 0 coefficient
      l.add(ck.multiply(b2k).subtract(ckm1.multiply(b4k)));

      // degree 1 to degree k-1 coefficients
      for (int i = 1; i < k; ++i) {
        ckPrev = ck;
        ck = l.get(startK + i);
        ckm1 = l.get(startKm1 + i);
        l.add(ck.multiply(b2k).add(ckPrev.multiply(b3k)).subtract(ckm1.multiply(b4k)));
      }

      // degree k coefficient
      ckPrev = ck;
      ck = l.get(startK + k);
      l.add(ck.multiply(b2k).add(ckPrev.multiply(b3k)));

      // degree k+1 coefficient
      l.add(ck.multiply(b3k));
    }

    maxDegree = degree;
  }

  /**
   * Get the coefficients array for a given degree.
   *
   * <p>The method lazily computes missing polynomials up to {@code degree} using the recurrence
   * supplied by the subclass. Expansion is synchronized on the generator instance, so concurrent
   * callers will not interleave writes to the shared coefficient list. When the requested degree
   * has already been generated, the existing values are reused without recomputation. The returned
   * array contains references to the internally stored {@link RationalNumber} objects; callers
   * should not mutate those instances if other threads may observe the same data.
   *
   * @param degree non-negative degree of the polynomial to retrieve from the sequence
   * @return array of coefficients from degree 0 through {@code degree}, sharing internal instances
   */
  public RationalNumber[] getCoefficients(int degree) {

    synchronized (this) {
      if (degree > maxDegree) {
        computeUpToDegree(degree);
      }
    }

    // coefficient  for polynomial 0 is  l [0]
    // coefficients for polynomial 1 are l [1] ... l [2] (degrees 0 ... 1)
    // coefficients for polynomial 2 are l [3] ... l [5] (degrees 0 ... 2)
    // coefficients for polynomial 3 are l [6] ... l [9] (degrees 0 ... 3)
    // coefficients for polynomial 4 are l[10] ... l[14] (degrees 0 ... 4)
    // coefficients for polynomial 5 are l[15] ... l[20] (degrees 0 ... 5)
    // coefficients for polynomial 6 are l[21] ... l[27] (degrees 0 ... 6)
    // ...
    int start = degree * (degree + 1) / 2;

    RationalNumber[] a = new RationalNumber[degree + 1];
    for (int i = 0; i <= degree; ++i) {
      a[i] = l.get(start + i);
    }

    return a;
  }

  /** List holding the coefficients of the polynomials computed so far. */
  private final List<RationalNumber> l;

  /** Maximal degree of the polynomials computed so far. */
  private int maxDegree;

  /**
   * b<sub>2,k</sub> coefficient to initialize (b<sub>2,k</sub> = a<sub>2,k</sub> /
   * a<sub>1,k</sub>).
   */
  private RationalNumber b2k;

  /**
   * b<sub>3,k</sub> coefficient to initialize (b<sub>3,k</sub> = a<sub>3,k</sub> /
   * a<sub>1,k</sub>).
   */
  private RationalNumber b3k;

  /**
   * b<sub>4,k</sub> coefficient to initialize (b<sub>4,k</sub> = a<sub>4,k</sub> /
   * a<sub>1,k</sub>).
   */
  private RationalNumber b4k;
}
