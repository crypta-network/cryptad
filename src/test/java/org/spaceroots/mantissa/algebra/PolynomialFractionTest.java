package org.spaceroots.mantissa.algebra;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class PolynomialFractionTest {

  @Test
  void constructor_withZeroDenominator_throwsArithmeticException() {
    assertThrows(ArithmeticException.class, () -> new PolynomialFraction(1L, 0L));
  }

  @Test
  void constructor_withNegativeDenominator_normalizesSignAndSimplifiesConstant() {
    PolynomialFraction fraction =
        new PolynomialFraction(new Polynomial.Rational(1L), new Polynomial.Rational(-2L));

    RationalNumber[] numeratorCoefficients = fraction.getNumerator().getCoefficients();
    assertArrayEquals(
        new RationalNumber[] {new RationalNumber(BigInteger.valueOf(-1L), BigInteger.valueOf(2L))},
        numeratorCoefficients);
    assertTrue(fraction.getDenominator().isOne());
  }

  @Test
  void add_whenDifferentDenominators_returnsSimplifiedSum() {
    PolynomialFraction first = new PolynomialFraction(1L, 2L);
    PolynomialFraction second = new PolynomialFraction(1L, 3L);

    PolynomialFraction result = first.add(second);

    assertArrayEquals(
        new RationalNumber[] {new RationalNumber(5L, 6L)}, result.getNumerator().getCoefficients());
    assertTrue(result.getDenominator().isOne());
  }

  @Test
  void subtract_whenResultNegative_returnsSimplifiedDifference() {
    PolynomialFraction minuend = new PolynomialFraction(1L, 3L);
    PolynomialFraction subtrahend = new PolynomialFraction(1L, 2L);

    PolynomialFraction result = minuend.subtract(subtrahend);

    assertArrayEquals(
        new RationalNumber[] {new RationalNumber(-1L, 6L)},
        result.getNumerator().getCoefficients());
    assertTrue(result.getDenominator().isOne());
  }

  @Test
  void multiply_whenCommonFactorsPresent_simplifiesProduct() {
    PolynomialFraction fraction = new PolynomialFraction(2L, 3L);
    PolynomialFraction other = new PolynomialFraction(3L, 4L);

    PolynomialFraction product = fraction.multiply(other);

    assertArrayEquals(
        new RationalNumber[] {new RationalNumber(1L, 2L)},
        product.getNumerator().getCoefficients());
    assertTrue(product.getDenominator().isOne());
  }

  @Test
  void divide_whenDividingByZeroNumerator_throwsArithmeticException() {
    PolynomialFraction dividend = new PolynomialFraction(1L, 2L);
    PolynomialFraction divisor = new PolynomialFraction(0L);

    assertThrows(ArithmeticException.class, () -> dividend.divide(divisor));
  }

  @Test
  void invert_whenNegativeNumerator_normalizesSign() {
    PolynomialFraction fraction = new PolynomialFraction(-1L, 2L);

    PolynomialFraction inverted = fraction.invert();

    assertArrayEquals(
        new RationalNumber[] {new RationalNumber(-2L)}, inverted.getNumerator().getCoefficients());
    assertTrue(inverted.getDenominator().isOne());
  }

  @Test
  void simplify_whenCommonPolynomialFactorExists_reducesFractionToLowestTerms() {
    Polynomial.Rational common = new Polynomial.Rational(RationalNumber.ONE, RationalNumber.ONE);
    Polynomial.Rational other =
        new Polynomial.Rational(RationalNumber.ONE, new RationalNumber(2L)); // x + 2
    Polynomial.Rational numerator = common.multiply(other); // (x + 1)(x + 2)

    PolynomialFraction fraction = new PolynomialFraction(numerator, common);

    assertArrayEquals(
        new RationalNumber[] {new RationalNumber(2L), RationalNumber.ONE},
        fraction.getNumerator().getCoefficients());
    assertTrue(fraction.getDenominator().isOne());
  }

  @Test
  void simplify_withNonConstantDenominator_scalesCoefficientsToIntegers() {
    Polynomial.Rational numerator =
        new Polynomial.Rational(new RationalNumber(1L, 2L), RationalNumber.ONE); // (1/2)x + 1
    Polynomial.Rational denominator =
        new Polynomial.Rational(new RationalNumber(1L, 3L), RationalNumber.ONE); // (1/3)x + 1

    PolynomialFraction fraction = new PolynomialFraction(numerator, denominator);

    assertTrue(
        areAllCoefficientsIntegers(fraction.getNumerator().getCoefficients()),
        "Numerator coefficients should be integers after scaling");
    assertTrue(
        areAllCoefficientsIntegers(fraction.getDenominator().getCoefficients()),
        "Denominator coefficients should be integers after scaling");

    double expectedValue = 1.2; // (0.5*2 + 1) / (0.333...*2 + 1)
    double actualValue =
        fraction.getNumerator().valueAt(2.0) / fraction.getDenominator().valueAt(2.0);
    assertEquals(expectedValue, actualValue, 1e-12);
  }

  @Test
  void toString_whenPolynomialHasSpaces_wrapsWithParentheses() {
    PolynomialFraction fraction =
        new PolynomialFraction(
            new Polynomial.Rational(new RationalNumber(-1L), RationalNumber.ONE), // 1 - x
            new Polynomial.Rational(RationalNumber.ONE, RationalNumber.ONE)); // 1 + x

    assertEquals("(1 - x)/(1 + x)", fraction.toString());
  }

  @Test
  void toString_whenZeroNumerator_returnsZero() {
    PolynomialFraction fraction = new PolynomialFraction();

    assertEquals("0", fraction.toString());
  }

  private boolean areAllCoefficientsIntegers(RationalNumber[] coefficients) {
    for (RationalNumber coefficient : coefficients) {
      if (!coefficient.isInteger()) {
        return false;
      }
    }
    return true;
  }
}
