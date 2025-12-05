package org.spaceroots.mantissa.algebra;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;

/**
 * Represents an immutable fraction of univariate polynomials with rational coefficients.
 *
 * <p>Instances encapsulate a numerator and denominator polynomial whose coefficients are rational
 * numbers and are normalized so the denominator has a positive leading coefficient. Fractions are
 * simplified during construction by removing common polynomial factors and absorbing constant
 * denominators into the numerator so {@code getDenominator()} is either monic or degree zero with
 * value one. All arithmetic operations create new instances and never mutate the existing ones,
 * which makes the type thread-safe when {@link Polynomial.Rational} values are treated as
 * immutable.
 *
 * <p>Typical call flows build fractions from integers, {@link RationalNumber} values, or existing
 * {@link Polynomial.Rational} objects and then compose them with {@link #add(PolynomialFraction)},
 * {@link #multiply(PolynomialFraction)}, or {@link #invert()} to form rational functions used in
 * algebraic algorithms such as interpolation, simplification, or symbolic manipulation. The class
 * keeps signs consistent so denominators always expose a non-negative leading term.
 *
 * <ul>
 *   <li>Denominator leading term is normalized to a non-negative coefficient.
 *   <li>All returned fractions are simplified before being exposed.
 *   <li>Arithmetic raises {@link ArithmeticException} when encountering zero denominators.
 * </ul>
 *
 * @version $Id: PolynomialFraction.java 1711 2006-12-13 21:27:51Z luc $
 * @author L. Maisonobe
 * @see Polynomial.Rational
 * @see RationalNumber
 */
public class PolynomialFraction implements Serializable {

  /**
   * Creates the zero polynomial fraction {@code 0/1}.
   *
   * <p>The constructor initializes the numerator to zero and the denominator to one, then applies
   * the internal simplification routine to guarantee canonical sign normalization. This overload is
   * useful for initializing accumulators or placeholders before performing arithmetic operations
   * such as {@link #add(PolynomialFraction)} or {@link #multiply(PolynomialFraction)}.
   */
  public PolynomialFraction() {
    this(new Polynomial.Rational(0L), new Polynomial.Rational(1L));
  }

  /**
   * Creates a fraction whose numerator and denominator are integer values.
   *
   * <p>The supplied numbers are wrapped into degree-zero {@link Polynomial.Rational} instances and
   * simplified so the denominator sign is normalized. The resulting fraction is immutable; repeated
   * calls with the same arguments yield equivalent objects although no caching occurs.
   *
   * @param numerator integer numerator value stored as a constant polynomial term
   * @param denominator integer denominator value that must not be zero
   * @exception ArithmeticException if the denominator is zero at construction time
   */
  public PolynomialFraction(long numerator, long denominator) {
    this(new Polynomial.Rational(numerator), new Polynomial.Rational(denominator));
  }

  /**
   * Creates a fraction from arbitrary-precision integer values.
   *
   * <p>Both arguments become degree-zero polynomials with rational coefficients backed by {@link
   * BigInteger}. The instance is simplified immediately, and the denominator sign is flipped when
   * needed so its leading coefficient is non-negative. The created fraction remains immutable and
   * thread-safe to share between computations.
   *
   * @param numerator big integer numerator promoted to a constant polynomial
   * @param denominator big integer denominator that must be non-zero
   * @exception ArithmeticException if the denominator is zero during instantiation
   */
  public PolynomialFraction(BigInteger numerator, BigInteger denominator) {
    this(
        new Polynomial.Rational(new RationalNumber(numerator)),
        new Polynomial.Rational(new RationalNumber(denominator)));
  }

  /**
   * Creates a fraction from two {@link RationalNumber} instances.
   *
   * <p>Both arguments are converted into constant {@link Polynomial.Rational} objects before
   * canonical simplification. Sign normalization ensures the denominator leading coefficient is
   * positive. This overload is convenient when upstream computations already operate on rational
   * scalars rather than primitive integers.
   *
   * @param numerator rational numerator value expressed as a constant polynomial term
   * @param denominator rational denominator value that must not be zero
   * @exception ArithmeticException if the denominator equals zero when constructing the fraction
   */
  @SuppressWarnings("unused")
  public PolynomialFraction(RationalNumber numerator, RationalNumber denominator) {
    this(new Polynomial.Rational(numerator), new Polynomial.Rational(denominator));
  }

  /**
   * Creates a fraction from polynomial numerator and denominator values.
   *
   * <p>This is the most general constructor and accepts arbitrarily high-degree polynomials with
   * rational coefficients. The fraction is simplified by removing common polynomial factors and
   * absorbing constant denominators into the numerator. The denominator sign is normalized so the
   * highest-degree coefficient is never negative, which stabilizes comparison and formatting.
   *
   * @param numerator polynomial numerator that may contain rational coefficients
   * @param denominator polynomial denominator whose leading coefficient will become non-negative
   * @exception ArithmeticException if the denominator polynomial evaluates to zero
   */
  public PolynomialFraction(Polynomial.Rational numerator, Polynomial.Rational denominator) {

    if (denominator.isZero()) {
      throw new ArithmeticException("null denominator");
    }

    p = numerator;
    q = denominator;

    RationalNumber[] a = q.getCoefficients();
    if (a[a.length - 1].isNegative()) {
      p = (Polynomial.Rational) p.negate();
      q = (Polynomial.Rational) q.negate();
    }

    simplify();
  }

  /**
   * Creates a constant fraction from a single integer value.
   *
   * <p>The integer is wrapped as a degree-zero polynomial numerator, while the denominator is set
   * to one. Simplification and sign normalization still run so the resulting instance is fully
   * canonical and ready for arithmetic composition.
   *
   * @param l integer value representing the numerator of the resulting fraction
   */
  public PolynomialFraction(long l) {
    this(l, 1L);
  }

  /**
   * Creates a constant fraction from a {@link BigInteger} value.
   *
   * <p>The provided value becomes the numerator, the denominator is set to one, and simplification
   * ensures the fraction follows the class invariants. This overload is suited for callers that
   * already compute with arbitrary-precision integers.
   *
   * @param i big integer value used as the numerator of the resulting fraction
   */
  @SuppressWarnings("unused")
  public PolynomialFraction(BigInteger i) {
    this(i, BigInteger.ONE);
  }

  /**
   * Creates a constant fraction from a {@link RationalNumber} value.
   *
   * <p>The rational argument is decomposed into numerator and denominator components to preserve
   * exactness. After construction, the fraction is simplified to maintain the positive-denominator
   * invariant and can be safely reused across computations without additional normalization steps.
   *
   * @param r rational value expressed as a numerator/denominator pair
   */
  @SuppressWarnings("unused")
  public PolynomialFraction(RationalNumber r) {
    this(r.getNumerator(), r.getDenominator());
  }

  /**
   * Creates a fraction from a polynomial numerator with unit denominator.
   *
   * <p>The supplied polynomial remains unchanged, while the denominator is initialized to one and
   * the fraction is simplified to enforce the positive leading coefficient rule. This constructor
   * is useful when a polynomial must be treated as a fraction without altering its structure.
   *
   * @param p polynomial numerator placed over a denominator equal to one
   */
  @SuppressWarnings("unused")
  public PolynomialFraction(Polynomial.Rational p) {
    this(p, new Polynomial.Rational(1L));
  }

  /**
   * Returns the additive inverse of this fraction.
   *
   * <p>The numerator sign is flipped while the denominator remains unchanged, and the result is
   * simplified to preserve the positive-denominator invariant. The current instance is not mutated,
   * allowing callers to safely reuse it across threads or repeated calculations. This helper is
   * useful when building symmetric expressions or computing additive inverses inside algorithms.
   *
   * @return new simplified fraction whose numerator is the negated value of this one
   */
  public PolynomialFraction negate() {
    return new PolynomialFraction((Polynomial.Rational) p.negate(), q);
  }

  /**
   * Returns a fraction equal to the sum of this fraction and the supplied one.
   *
   * <p>The method cross-multiplies numerators and denominators to preserve exactness, then
   * simplifies the result to eliminate common factors and normalize the denominator sign. Neither
   * operand is modified; both can be safely reused after the operation completes. Results inherit
   * the same normalization guarantees as fractions produced directly by the constructors.
   *
   * @param f other fraction to add; must be non-null and immutable
   * @return new fraction representing the simplified sum of both operands
   */
  public PolynomialFraction add(PolynomialFraction f) {
    return new PolynomialFraction(p.multiply(f.q).add(f.p.multiply(q)), q.multiply(f.q));
  }

  /**
   * Returns a fraction representing this fraction minus the supplied one.
   *
   * <p>The operation performs cross-multiplication to avoid loss of precision, followed by full
   * simplification to remove shared polynomial factors and enforce denominator sign conventions.
   * The original operands remain unchanged, supporting safe reuse in subsequent calculations. The
   * returned fraction is fully simplified, so repeated subtraction chains do not accumulate drift.
   *
   * @param f fraction to subtract; must represent a valid, non-null rational function
   * @return simplified fraction capturing the arithmetic difference of the operands
   */
  public PolynomialFraction subtract(PolynomialFraction f) {
    return new PolynomialFraction(p.multiply(f.q).subtract(f.p.multiply(q)), q.multiply(f.q));
  }

  /**
   * Returns the product of this fraction and the supplied fraction.
   *
   * <p>Both numerators and denominators are multiplied independently, and the resulting fraction is
   * simplified to remove common factors and normalize its denominator sign. Because the operation
   * is purely functional, callers can chain multiplications without defensive copying. The returned
   * instance respects the positive-denominator rule even when both operands originally violated it.
   *
   * @param f fraction multiplier; must be a valid, non-null polynomial fraction
   * @return simplified fraction representing the product of both operands
   */
  public PolynomialFraction multiply(PolynomialFraction f) {
    PolynomialFraction product = new PolynomialFraction(p.multiply(f.p), q.multiply(f.q));
    product.simplify();
    return product;
  }

  /**
   * Returns the quotient of this fraction divided by the supplied fraction.
   *
   * <p>The method multiplies this numerator by the other denominator and this denominator by the
   * other numerator, then simplifies the resulting fraction. A zero numerator in the supplied
   * fraction triggers an {@link ArithmeticException} to prevent division by zero. The simplified
   * quotient preserves sign normalization and can safely participate in further arithmetic chains.
   *
   * @param f divisor fraction; must have a non-zero numerator and be non-null
   * @return simplified fraction representing the exact division result
   * @exception ArithmeticException if the supplied fraction has a zero numerator
   */
  public PolynomialFraction divide(PolynomialFraction f) {

    if (f.p.isZero()) {
      throw new ArithmeticException("divide by zero");
    }

    Polynomial.Rational newP = p.multiply(f.q);
    Polynomial.Rational newQ = q.multiply(f.p);

    RationalNumber[] a = newQ.getCoefficients();
    if (a[a.length - 1].isNegative()) {
      newP = (Polynomial.Rational) newP.negate();
      newQ = (Polynomial.Rational) newQ.negate();
    }

    PolynomialFraction result = new PolynomialFraction(newP, newQ);
    result.simplify();
    return result;
  }

  /**
   * Returns the multiplicative inverse of this fraction.
   *
   * <p>The numerator and denominator are swapped, and the sign is adjusted so the denominator keeps
   * a positive leading coefficient. If this fraction equals zero, the method raises an {@link
   * ArithmeticException}. The returned instance is simplified and independent of the original. Use
   * this to switch between reciprocal forms when evaluating rational functions.
   *
   * @return simplified inverse fraction whose product with this one equals one
   * @exception ArithmeticException if this fraction has a zero numerator
   */
  public PolynomialFraction invert() {

    if (p.isZero()) {
      throw new ArithmeticException("divide by zero");
    }

    RationalNumber[] a = p.getCoefficients();
    PolynomialFraction inverse =
        (a[a.length - 1].isNegative())
            ? new PolynomialFraction(
                (Polynomial.Rational) q.negate(), (Polynomial.Rational) p.negate())
            : new PolynomialFraction(q, p);
    inverse.simplify();
    return inverse;
  }

  /**
   * Simplify a fraction. If the denominator polynom is a constant polynom, then simplification
   * involves merging this constant in the rational coefficients of the numerator in order to
   * replace the denominator by the constant 1. If the degree of the denominator is non-null, then
   * simplification involves both removing common polynomial factors (by euclidian division) and
   * replacing rational coefficients by integer coefficients (multiplying both numerator and
   * denominator by the proper value). The signs of both the numerator and the denominator are
   * adjusted in order to have a positive leeding degree term in the denominator.
   */
  private void simplify() {

    Polynomial.Rational a = p;
    Polynomial.Rational b = q;
    if (a.getDegree() < b.getDegree()) {
      Polynomial.Rational tmp = a;
      a = b;
      b = tmp;
    }

    Polynomial.DivisionResult res = Polynomial.Rational.euclidianDivision(a, b);
    while (res.remainder().getDegree() != 0) {
      a = b;
      b = res.remainder();
      res = Polynomial.Rational.euclidianDivision(a, b);
    }

    if (res.remainder().isZero()) {
      // there is a common factor we can remove
      p = Polynomial.Rational.euclidianDivision(p, b).quotient();
      q = Polynomial.Rational.euclidianDivision(q, b).quotient();
    }

    if (q.getDegree() == 0) {
      if (!q.isOne()) {
        p = (Polynomial.Rational) p.divide(q.getCoefficients()[0]);
        q = new Polynomial.Rational(1L);
      }
    } else {

      BigInteger lcm = p.getDenominatorsLCM();
      if (lcm.compareTo(BigInteger.ONE) != 0) {
        p = (Polynomial.Rational) p.multiply(lcm);
        q = (Polynomial.Rational) q.multiply(lcm);
      }

      lcm = q.getDenominatorsLCM();
      if (lcm.compareTo(BigInteger.ONE) != 0) {
        p = (Polynomial.Rational) p.multiply(lcm);
        q = (Polynomial.Rational) q.multiply(lcm);
      }
    }

    if (q.getCoefficients()[q.getDegree()].isNegative()) {
      p = (Polynomial.Rational) p.negate();
      q = (Polynomial.Rational) q.negate();
    }
  }

  /**
   * Returns the normalized numerator polynomial.
   *
   * <p>The returned reference shares the internal immutable representation. Its coefficients are
   * guaranteed to reflect any simplification performed during construction or arithmetic so callers
   * can rely on consistent sign conventions when inspecting leading terms. No defensive copy is
   * created, which keeps access inexpensive for performance-critical paths.
   *
   * @return numerator polynomial reference; callers should treat it as immutable
   */
  public Polynomial.Rational getNumerator() {
    return p;
  }

  /**
   * Returns the normalized denominator polynomial.
   *
   * <p>The denominator always exposes a non-negative leading coefficient and is simplified to
   * remove common factors shared with the numerator. When the degree is zero, the value equals one
   * so constant fractions are represented without redundant scaling. The returned reference can be
   * shared safely when callers adhere to the immutability expectation of {@link
   * Polynomial.Rational}.
   *
   * @return denominator polynomial whose leading coefficient is always non-negative
   */
  public Polynomial.Rational getDenominator() {
    return q;
  }

  /**
   * Formats the fraction using infix notation suitable for debugging and logs.
   *
   * <p>Returns {@code "0"} when the numerator is zero, otherwise prints {@code numerator} or {@code
   * numerator/denominator}. Parentheses are added around polynomials containing spaces to preserve
   * readability when complex terms appear in either component. This representation is stable and
   * aims to mirror human-readable algebraic notation for quick inspection.
   *
   * @return string representation with parentheses added when either part contains spaces
   */
  public String toString() {
    if (p.isZero()) {
      return "0";
    } else if (q.isOne()) {
      return p.toString();
    } else {

      StringBuilder s = new StringBuilder();

      String pString = p.toString();
      if (pString.indexOf(' ') >= 0) {
        s.append('(');
        s.append(pString);
        s.append(')');
      } else {
        s.append(pString);
      }

      s.append('/');

      String qString = q.toString();
      if (qString.indexOf(' ') >= 0) {
        s.append('(');
        s.append(qString);
        s.append(')');
      } else {
        s.append(qString);
      }

      return s.toString();
    }
  }

  /** Numerator. */
  private Polynomial.Rational p;

  /** Denominator. */
  private Polynomial.Rational q;

  @Serial private static final long serialVersionUID = 6033909492898954748L;
}
