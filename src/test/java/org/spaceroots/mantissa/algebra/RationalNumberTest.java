package org.spaceroots.mantissa.algebra;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class RationalNumberTest {

  @Test
  @DisplayName("Constructor rejects zero denominator for long")
  void constructor_whenDenominatorZeroLong_throwsArithmeticException() {
    assertThrows(ArithmeticException.class, () -> new RationalNumber(1L, 0L));
  }

  @Test
  @DisplayName("Constructor rejects zero denominator for BigInteger")
  void constructor_whenDenominatorZeroBigInteger_throwsArithmeticException() {
    assertThrows(
        ArithmeticException.class, () -> new RationalNumber(BigInteger.ONE, BigInteger.ZERO));
  }

  @Test
  @DisplayName("Constructor normalizes sign to denominator being positive")
  void constructor_whenDenominatorNegative_normalizesSign() {
    RationalNumber result = new RationalNumber(1L, -2L);

    assertEquals(BigInteger.valueOf(-1), result.getNumerator());
    assertEquals(BigInteger.valueOf(2), result.getDenominator());
    assertTrue(result.isNegative());
  }

  @Test
  @DisplayName("Constructor reduces fraction by greatest common divisor")
  void constructor_whenFractionReducible_reducesToLowestTerms() {
    RationalNumber result = new RationalNumber(8L, 12L);

    assertEquals(BigInteger.valueOf(2), result.getNumerator());
    assertEquals(BigInteger.valueOf(3), result.getDenominator());
  }

  @Test
  @DisplayName("Zero numerator always yields denominator equal to one")
  void constructor_whenNumeratorZero_setsUnitDenominator() {
    RationalNumber result = new RationalNumber(0L, -5L);

    assertEquals(BigInteger.ZERO, result.getNumerator());
    assertEquals(BigInteger.ONE, result.getDenominator());
    assertTrue(result.isZero());
  }

  @Test
  @DisplayName("Add, subtract, multiply, divide with reduction and mixed signs")
  void arithmeticOperations_coverMixedSignsAndReduction() {
    RationalNumber a = new RationalNumber(1L, 3L);
    RationalNumber b = new RationalNumber(-1L, 6L);

    RationalNumber sum = a.add(b); // 1/3 + (-1/6) = 1/6
    RationalNumber difference = a.subtract(b); // 1/3 - (-1/6) = 1/2
    RationalNumber product = a.multiply(b); // 1/3 * (-1/6) = -1/18
    RationalNumber quotient = a.divide(b); // (1/3) / (-1/6) = -2

    assertEquals(new RationalNumber(1L, 6L), sum);
    assertEquals(new RationalNumber(1L, 2L), difference);
    assertEquals(new RationalNumber(-1L, 18L), product);
    assertEquals(new RationalNumber(-2L), quotient);
  }

  @Test
  @DisplayName("Division by zero RationalNumber throws")
  void divide_whenDividingByZeroRational_throwsArithmeticException() {
    RationalNumber dividend = new RationalNumber(3L, 5L);
    RationalNumber zero = new RationalNumber(0L);

    assertThrows(ArithmeticException.class, () -> dividend.divide(zero));
  }

  @Test
  @DisplayName("Division by negative integer normalizes sign")
  void divide_whenDividingByNegativeInteger_returnsNegativeQuotient() {
    RationalNumber result = new RationalNumber(1L, 4L).divide(-2L);

    assertEquals(new RationalNumber(-1L, 8L), result);
  }

  @Test
  @DisplayName("Invert rejects zero and keeps sign on numerator")
  void invert_whenZero_throwsAndWhenNegative_keepsSignOnNumerator() {
    RationalNumber negative = new RationalNumber(-2L, 3L);
    RationalNumber zero = new RationalNumber(0L);

    assertThrows(ArithmeticException.class, zero::invert);
    assertEquals(new RationalNumber(-3L, 2L), negative.invert());
  }

  @Test
  @DisplayName("Predicates correctly detect one, integer, zero, negative")
  void predicates_returnExpectedValues() {
    RationalNumber one = RationalNumber.ONE;
    RationalNumber integer = new RationalNumber(5L);
    RationalNumber fraction = new RationalNumber(-2L, 7L);

    assertTrue(one.isOne());
    assertTrue(integer.isInteger());
    assertTrue(fraction.isNegative());
    assertFalse(fraction.isZero());
  }

  @Test
  @DisplayName("Absolute value returns positive numerator and keeps denominator")
  void abs_whenNegative_returnsPositiveValue() {
    RationalNumber negative = new RationalNumber(-4L, 9L);

    RationalNumber absolute = RationalNumber.abs(negative);

    assertEquals(new RationalNumber(4L, 9L), absolute);
  }

  @Test
  @DisplayName("doubleValue computes accurate division result")
  void doubleValue_returnsExpectedDouble() {
    RationalNumber half = new RationalNumber(1L, 2L);

    assertEquals(0.5d, half.doubleValue(), 1.0e-12);
  }

  @Test
  @DisplayName("equals and hashCode use reduced representation")
  void equalsAndHashCode_whenDifferentRepresentations_areEqual() {
    RationalNumber twoFourths = new RationalNumber(2L, 4L);
    RationalNumber oneHalf = new RationalNumber(1L, 2L);

    assertEquals(oneHalf, twoFourths);
    assertEquals(oneHalf.hashCode(), twoFourths.hashCode());
    //noinspection AssertBetweenInconvertibleTypes
    assertNotEquals("1/2", oneHalf);
  }

  @Test
  @DisplayName("toString omits denominator for integers and shows slash otherwise")
  void toString_formatsCorrectly() {
    RationalNumber integer = new RationalNumber(3L);
    RationalNumber fraction = new RationalNumber(-2L, 5L);

    assertEquals("3", integer.toString());
    assertEquals("-2/5", fraction.toString());
  }
}
