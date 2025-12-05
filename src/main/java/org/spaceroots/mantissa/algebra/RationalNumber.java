package org.spaceroots.mantissa.algebra;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;

/**
 * Immutable fraction expressed as a reduced numerator and denominator.
 *
 * <p>This type models exact rational arithmetic on top of {@link java.math.BigInteger}. Each
 * instance is normalized during construction so that the denominator is strictly positive and the
 * pair {@code (p, q)} is reduced to the lowest terms. Clients can therefore compare instances with
 * {@link #equals(Object)} or {@link #hashCode()} without worrying about representation artifacts
 * such as {@code 2/4} versus {@code 1/2}. The class is lightweight and side-effect free; every
 * arithmetic method returns a new instance while leaving the source operands unchanged.
 *
 * <p>Typical usage involves building values from primitive {@code long} or {@link BigInteger}
 * numbers, chaining arithmetic operations, and finally converting to a primitive using {@link
 * #doubleValue()} or inspecting numerator/denominator components. As the objects are immutable and
 * thread-safe, they can be freely shared between threads without synchronization.
 *
 * <ul>
 *   <li>Normalization: denominators are always positive and common factors are removed.
 *   <li>Error handling: divisions by zero throw {@link ArithmeticException}.
 *   <li>Performance: relies on {@link BigInteger} arithmetic; cost grows with operand size but no
 *       rounding occurs.
 * </ul>
 *
 * @version $Id: RationalNumber.java 1711 2006-12-13 21:27:51Z luc $
 * @author L. Maisonobe
 * @see java.math.BigInteger
 */
public class RationalNumber implements Serializable {

  /**
   * Canonical representation of zero.
   *
   * <p>The numerator is {@link BigInteger#ZERO} and the denominator is {@link BigInteger#ONE}. The
   * instance is immutable and may be shared across the application in place of creating new zero
   * values.
   */
  public static final RationalNumber ZERO = new RationalNumber(0L);

  /**
   * Canonical representation of one.
   *
   * <p>The numerator is {@link BigInteger#ONE} and the denominator is {@link BigInteger#ONE}. Use
   * this constant when a neutral multiplicative element is needed to avoid extra allocations.
   */
  public static final RationalNumber ONE = new RationalNumber(1L);

  /**
   * Build a zero rational number.
   *
   * <p>The created instance has numerator {@code 0} and denominator {@code 1}. It is equivalent to
   * {@link #ZERO} but does not reuse the shared instance.
   */
  public RationalNumber() {
    p = BigInteger.ZERO;
    q = BigInteger.ONE;
  }

  /**
   * Build a rational number from primitive components.
   *
   * <p>The value is normalized so the denominator becomes positive and any greatest common divisor
   * is removed. Callers can pass negative numerators or denominators; the sign is carried by the
   * numerator in the normalized form to keep the denominator positive.
   *
   * @param numerator signed value representing the numerator to store in the fraction.
   * @param denominator signed value representing the denominator; must not be zero after
   *     conversion.
   * @throws ArithmeticException if {@code denominator} equals zero, preventing fraction creation.
   */
  public RationalNumber(long numerator, long denominator) {

    if (denominator == 0L) {
      throw new ArithmeticException("divide by zero");
    }

    p = BigInteger.valueOf(numerator);
    q = BigInteger.valueOf(denominator);

    if (q.signum() < 0) {
      p = p.negate();
      q = q.negate();
    }

    simplify();
  }

  /**
   * Build a rational number from {@link BigInteger} components.
   *
   * <p>The fraction is reduced immediately so there is no common factor between numerator and
   * denominator. A negative denominator is flipped to the numerator to keep the denominator
   * positive. The supplied objects are not stored directly if sign adjustments are needed.
   *
   * @param numerator signed {@link BigInteger} used as the numerator; may be any finite value.
   * @param denominator signed {@link BigInteger} used as the denominator; must be non-zero.
   * @throws ArithmeticException if {@code denominator} is zero, matching arithmetic division rules.
   */
  public RationalNumber(BigInteger numerator, BigInteger denominator) {

    if (denominator.signum() == 0) {
      throw new ArithmeticException("divide by zero");
    }

    p = numerator;
    q = denominator;

    if (q.signum() < 0) {
      p = p.negate();
      q = q.negate();
    }

    simplify();
  }

  /**
   * Build a rational number from a primitive integer.
   *
   * <p>The created value has denominator {@code 1} and therefore represents an exact integer.
   *
   * @param l signed integer value to store as the numerator with denominator {@code 1}.
   */
  public RationalNumber(long l) {
    p = BigInteger.valueOf(l);
    q = BigInteger.ONE;
  }

  /**
   * Build a rational number from a {@link BigInteger} integer.
   *
   * <p>The denominator is set to {@code 1}, preserving the full precision of the supplied value.
   *
   * @param i signed {@link BigInteger} to use as numerator while fixing denominator to {@code 1}.
   */
  public RationalNumber(BigInteger i) {
    p = i;
    q = BigInteger.ONE;
  }

  /**
   * Return the additive inverse of this rational number.
   *
   * <p>The numerator sign is flipped while the denominator is preserved, and the result is reduced
   * to the lowest terms. The current instance remains unchanged because the class is immutable.
   *
   * @return new {@code RationalNumber} representing {@code -this}, sharing no mutable state.
   */
  public RationalNumber negate() {
    return new RationalNumber(p.negate(), q);
  }

  /**
   * Add an integer to this rational number.
   *
   * <p>The operation is exact and yields a normalized fraction. The denominator remains unchanged
   * because the integer is scaled by the existing denominator before addition.
   *
   * @param l signed integer value to add; any {@code long} value is accepted.
   * @return normalized sum of this value and {@code l}, as a new rational instance.
   */
  public RationalNumber add(long l) {
    return add(BigInteger.valueOf(l));
  }

  /**
   * Add a {@link BigInteger} integer to this rational number.
   *
   * <p>The integer is first scaled by the current denominator to align denominators, then added to
   * the numerator. The resulting fraction is reduced, leaving the original object untouched.
   *
   * @param l integer value to add; may be negative or zero and is treated as an exact quantity.
   * @return new rational equal to {@code this + l}, normalized with a positive denominator.
   */
  public RationalNumber add(BigInteger l) {
    return new RationalNumber(p.add(q.multiply(l)), q);
  }

  /**
   * Add another rational number to this one.
   *
   * <p>The method computes a common denominator by multiplying the two denominators and sums the
   * appropriately scaled numerators. The result is immediately reduced. Neither operand is
   * modified, ensuring safe reuse across threads.
   *
   * @param r other rational value to add; must be non-null and already normalized by construction.
   * @return normalized sum {@code this + r} with denominator greater than zero.
   */
  public RationalNumber add(RationalNumber r) {
    return new RationalNumber(p.multiply(r.q).add(r.p.multiply(q)), q.multiply(r.q));
  }

  /**
   * Subtract an integer from this rational number.
   *
   * <p>The integer is scaled by the denominator before subtraction so the denominator is preserved.
   * The resulting fraction is reduced and returned as a new instance.
   *
   * @param l integer value to subtract; any {@code long} is permitted, including negatives.
   * @return normalized difference {@code this - l} with denominator unchanged and positive.
   */
  public RationalNumber subtract(long l) {
    return subtract(BigInteger.valueOf(l));
  }

  /**
   * Subtract a {@link BigInteger} integer from this rational number.
   *
   * <p>The numerator is decreased by {@code l * denominator}. The output is a reduced fraction and
   * does not alter the current object.
   *
   * @param l integer value to subtract; may be positive, negative, or zero.
   * @return new rational equal to {@code this - l}, reduced with a positive denominator.
   */
  public RationalNumber subtract(BigInteger l) {
    return new RationalNumber(p.subtract(q.multiply(l)), q);
  }

  /**
   * Subtract another rational number from this one.
   *
   * <p>The computation aligns denominators by multiplication, subtracts the scaled numerators, and
   * reduces the result. Inputs are left untouched, supporting safe reuse across method chains.
   *
   * @param r rational value to subtract; must not be {@code null} and should be in reduced form.
   * @return normalized difference {@code this - r} with denominator strictly positive.
   */
  public RationalNumber subtract(RationalNumber r) {
    return new RationalNumber(p.multiply(r.q).subtract(r.p.multiply(q)), q.multiply(r.q));
  }

  /**
   * Multiply this rational number by an integer.
   *
   * <p>The numerator is scaled by the supplied integer while the denominator is preserved. The
   * result is reduced to the lowest terms and returned as a fresh object.
   *
   * @param l integer factor; any {@code long} value, including zero, is accepted.
   * @return product {@code this * l} in normalized form with a positive denominator.
   */
  public RationalNumber multiply(long l) {
    return multiply(BigInteger.valueOf(l));
  }

  /**
   * Multiply this rational number by a {@link BigInteger} integer.
   *
   * <p>The multiplication is exact; no rounding occurs. The denominator is unchanged and the result
   * is simplified before being returned.
   *
   * @param l integer factor to apply to the numerator; may be negative, positive, or zero.
   * @return new rational representing {@code this * l}, reduced with denominator greater than zero.
   */
  public RationalNumber multiply(BigInteger l) {
    return new RationalNumber(p.multiply(l), q);
  }

  /**
   * Multiply this rational number by another rational number.
   *
   * <p>Both numerators and denominators are multiplied, then the result is reduced. Neither operand
   * is mutated, enabling fluent arithmetic pipelines.
   *
   * @param r rational factor to multiply with; must not be {@code null}.
   * @return normalized product {@code this * r} with positive denominator.
   */
  public RationalNumber multiply(RationalNumber r) {
    return new RationalNumber(p.multiply(r.p), q.multiply(r.q));
  }

  /**
   * Divide this rational number by an integer.
   *
   * <p>The denominator is multiplied by the integer, respecting sign. Division by zero propagates
   * an {@link ArithmeticException}. The result is reduced and returned as a new instance.
   *
   * @param l integer divisor; if negative, the sign is transferred to the numerator.
   * @return normalized quotient {@code this / l} with denominator kept positive.
   * @throws ArithmeticException if {@code l} is zero, mirroring integer division rules.
   */
  public RationalNumber divide(long l) {
    return divide(BigInteger.valueOf(l));
  }

  /**
   * Divide this rational number by a {@link BigInteger} integer.
   *
   * <p>Handles negative divisors by flipping the sign to the numerator, ensuring the denominator
   * remains positive. Throws {@link ArithmeticException} on a zero divisor. The result is reduced
   * before being returned.
   *
   * @param l integer divisor as {@link BigInteger}; zero triggers an exception.
   * @return rational representing {@code this / l}, normalized to the lowest terms.
   * @throws ArithmeticException if {@code l} has a zero signum, preventing division.
   */
  public RationalNumber divide(BigInteger l) {

    if (l.signum() == 0) {
      throw new ArithmeticException("divide by zero");
    }

    if (l.signum() > 0) {
      return new RationalNumber(p, q.multiply(l));
    }

    return new RationalNumber(p.negate(), q.multiply(l.negate()));
  }

  /**
   * Divide this rational number by another rational number.
   *
   * <p>The division multiplies by the reciprocal of the provided rational. If the divisor has a
   * zero numerator, an {@link ArithmeticException} is thrown. The result is normalized with a
   * positive denominator and returned as a new object.
   *
   * @param r rational divisor; must not have a zero numerator to avoid divide-by-zero.
   * @return quotient {@code this / r} in reduced form with positive denominator.
   * @throws ArithmeticException if {@code r} represents zero, because inversion is undefined.
   */
  public RationalNumber divide(RationalNumber r) {

    if (r.p.signum() == 0) {
      throw new ArithmeticException("divide by zero");
    }

    BigInteger newP = p.multiply(r.q);
    BigInteger newQ = q.multiply(r.p);

    return (newQ.signum() < 0)
        ? new RationalNumber(newP.negate(), newQ.negate())
        : new RationalNumber(newP, newQ);
  }

  /**
   * Compute the multiplicative inverse of this rational number.
   *
   * <p>The numerator and denominator are swapped, with sign adjusted to keep the denominator
   * positive. Attempting to invert zero triggers {@link ArithmeticException}. The original instance
   * is left unchanged.
   *
   * @return new rational equal to {@code 1 / this}, reduced with a positive denominator.
   * @throws ArithmeticException if this value is zero, making inversion undefined.
   */
  public RationalNumber invert() {

    if (p.signum() == 0) {
      throw new ArithmeticException("divide by zero");
    }

    return (q.signum() < 0) ? new RationalNumber(q.negate(), p.negate()) : new RationalNumber(q, p);
  }

  /** Simplify a rational number by removing common factors. */
  private void simplify() {
    if (p.signum() == 0) {
      q = BigInteger.ONE;
    } else {
      BigInteger gcd = p.gcd(q);
      p = p.divide(gcd);
      q = q.divide(gcd);
    }
  }

  /**
   * Get the numerator component.
   *
   * <p>The numerator may be negative, zero, or positive. It is always in reduced form relative to
   * the denominator returned by {@link #getDenominator()}.
   *
   * @return signed {@link BigInteger} numerator representing this value in reduced form.
   */
  public BigInteger getNumerator() {
    return p;
  }

  /**
   * Get the denominator component.
   *
   * <p>The denominator is always strictly positive because sign is carried by the numerator during
   * normalization. It is coprime with the numerator.
   *
   * @return positive {@link BigInteger} denominator coprime with the numerator.
   */
  public BigInteger getDenominator() {
    return q;
  }

  /**
   * Test whether this rational number equals zero.
   *
   * <p>Because the fraction is normalized, zero is represented with numerator {@code 0} and
   * denominator {@code 1}.
   *
   * @return {@code true} when the numerator signum is zero; {@code false} otherwise.
   */
  public boolean isZero() {
    return p.signum() == 0;
  }

  /**
   * Test whether this rational number equals one.
   *
   * <p>The check compares against the canonical reduced representation {@code 1/1}.
   *
   * @return {@code true} if numerator and denominator both equal {@link BigInteger#ONE}.
   */
  public boolean isOne() {
    return (p.compareTo(BigInteger.ONE) == 0) && (q.compareTo(BigInteger.ONE) == 0);
  }

  /**
   * Test whether this rational number is an integer.
   *
   * <p>An integer is represented by a denominator of {@code 1} in reduced form.
   *
   * @return {@code true} when {@link #getDenominator()} equals {@link BigInteger#ONE}.
   */
  public boolean isInteger() {
    return q.compareTo(BigInteger.ONE) == 0;
  }

  /**
   * Test whether this rational number is strictly negative.
   *
   * <p>The sign is determined solely by the numerator because the denominator is always positive.
   *
   * @return {@code true} when the numerator signum is less than zero.
   */
  public boolean isNegative() {
    return p.signum() < 0;
  }

  /**
   * Compute the absolute value of a rational number.
   *
   * <p>The denominator remains unchanged while the numerator becomes non-negative. The supplied
   * argument is not modified; a new instance is created even if the input is already non-negative.
   *
   * @param r rational whose magnitude should be taken; must not be {@code null}.
   * @return rational with the same denominator as {@code r} and a non-negative numerator.
   */
  public static RationalNumber abs(RationalNumber r) {
    return new RationalNumber(r.p.abs(), r.q);
  }

  /**
   * Convert this value to a {@code double}.
   *
   * <p>The conversion performs an exact integer division to obtain the integral part and then adds
   * the fractional remainder divided by the denominator using double precision. Overflow or loss of
   * precision may occur for very large numerators or denominators, matching standard {@link
   * BigInteger#doubleValue()} semantics.
   *
   * @return {@code double} approximation of this rational, potentially rounded for large
   *     magnitudes.
   */
  public double doubleValue() {
    BigInteger[] result = p.divideAndRemainder(q);
    return result[0].doubleValue() + (result[1].doubleValue() / q.doubleValue());
  }

  /**
   * Compare this instance with another object for value equality.
   *
   * <p>Equality is based on the reduced numerator and denominator. Because all instances are
   * normalized, equivalent fractions always compare equal even if originally constructed with
   * different components.
   *
   * @param o object to compare; equality is considered only for other {@code RationalNumber}
   *     instances.
   * @return {@code true} when {@code o} is a {@code RationalNumber} with identical numerator and
   *     denominator; {@code false} otherwise.
   */
  public boolean equals(Object o) {
    if (o instanceof RationalNumber r) {
      return (p.compareTo(r.p) == 0) && (q.compareTo(r.q) == 0);
    }
    return false;
  }

  /**
   * Compute a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash is derived from the reduced numerator and denominator, guaranteeing that equal
   * rational numbers produce identical hash codes. This makes the class safe for use as keys in
   * hash-based collections.
   *
   * @return integer hash computed from the canonical numerator and denominator.
   */
  public int hashCode() {
    return p.hashCode() ^ q.hashCode();
  }

  /**
   * Render this rational number as a string.
   *
   * <p>The output uses the reduced representation. When the denominator equals {@code 1}, only the
   * numerator is shown; otherwise the format is {@code numerator/denominator} with the sign on the
   * numerator.
   *
   * @return human-readable string reflecting the normalized numerator and denominator.
   */
  public String toString() {
    return p + ((q.compareTo(BigInteger.ONE) == 0) ? "" : ("/" + q));
  }

  /** Numerator. */
  private BigInteger p;

  /** Denominator. */
  private BigInteger q;

  @Serial private static final long serialVersionUID = -324954393137577531L;
}
