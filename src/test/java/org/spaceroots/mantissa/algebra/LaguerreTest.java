package org.spaceroots.mantissa.algebra;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.spaceroots.mantissa.algebra.Polynomial.Rational;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LaguerreTest {

  @Test
  void constructor_withoutDegree_buildsConstantOnePolynomial() {
    Laguerre polynomial = new Laguerre();

    RationalNumber[] coefficients = polynomial.getCoefficients();

    assertEquals(0, polynomial.getDegree());
    assertTrue(polynomial.isOne());
    assertArrayEquals(new RationalNumber[] {RationalNumber.ONE}, coefficients);
  }

  @Test
  void constructor_withDegreeOne_buildsExpectedLinearPolynomial() {
    Laguerre polynomial = new Laguerre(1);

    RationalNumber[] coefficients = polynomial.getCoefficients();

    assertEquals(1, polynomial.getDegree());
    assertArrayEquals(
        new RationalNumber[] {RationalNumber.ONE, new RationalNumber(-1L)}, coefficients);
  }

  @Test
  void constructor_withDegreeThree_matchesClosedFormCoefficients() {
    Laguerre polynomial = new Laguerre(3);

    RationalNumber[] coefficients = polynomial.getCoefficients();

    assertEquals(3, polynomial.getDegree());
    assertArrayEquals(
        new RationalNumber[] {
          RationalNumber.ONE,
          new RationalNumber(-3L),
          new RationalNumber(3L, 2L),
          new RationalNumber(-1L, 6L)
        },
        coefficients);
  }

  @ParameterizedTest
  @MethodSource("recurrenceSamples")
  void valueAt_satisfiesThreeTermRecurrence(int degree, double x) {
    Laguerre lkPlus1 = new Laguerre(degree + 1);
    Laguerre lk = new Laguerre(degree);
    Laguerre lkMinus1 = new Laguerre(degree - 1);

    double left = (degree + 1) * lkPlus1.valueAt(x);
    double right = (2 * degree + 1 - x) * lk.valueAt(x) - degree * lkMinus1.valueAt(x);

    assertEquals(right, left, 1.0e-12);
  }

  private static Stream<Arguments> recurrenceSamples() {
    return Stream.of(
        Arguments.of(1, -0.5), Arguments.of(2, 0.0), Arguments.of(3, 0.75), Arguments.of(5, 2.4));
  }

  @ParameterizedTest
  @MethodSource("valueSamples")
  void valueAt_whenComparedToIterativeReference_matchesExpected(int degree, double x) {
    Laguerre polynomial = new Laguerre(degree);

    double actual = polynomial.valueAt(x);
    double expected = referenceLaguerre(degree, x);

    assertEquals(expected, actual, 1.0e-12);
  }

  private static Stream<Arguments> valueSamples() {
    return Stream.of(
        Arguments.of(0, 0.0),
        Arguments.of(1, 1.0),
        Arguments.of(2, 1.3),
        Arguments.of(3, -0.8),
        Arguments.of(4, 0.5),
        Arguments.of(5, 2.0));
  }

  @Test
  void derivative_whenAppliedToDegreeThree_matchesSymbolicDerivative() {
    Laguerre polynomial = new Laguerre(3);

    Polynomial derivative = polynomial.getDerivative();

    assertEquals(2, derivative.getDegree());
    assertArrayEquals(
        new RationalNumber[] {
          new RationalNumber(-3L), new RationalNumber(3L), new RationalNumber(-1L, 2L)
        },
        ((Rational) derivative).getCoefficients());
  }

  @ParameterizedTest
  @MethodSource("degreeSamples")
  void valueAt_zero_returnsOneForAnyDegree(int degree) {
    Laguerre polynomial = new Laguerre(degree);

    double value = polynomial.valueAt(0.0);

    assertEquals(1.0, value, 0.0);
  }

  private static Stream<Integer> degreeSamples() {
    return Stream.of(0, 1, 2, 3, 4, 5, 6);
  }

  private static double referenceLaguerre(int degree, double x) {
    if (degree == 0) {
      return 1.0;
    }
    if (degree == 1) {
      return 1.0 - x;
    }
    double lkm1 = 1.0;
    double lk = 1.0 - x;
    for (int k = 1; k < degree; ++k) {
      double lkPlus1 = ((2.0 * k + 1.0 - x) * lk - k * lkm1) / (k + 1.0);
      lkm1 = lk;
      lk = lkPlus1;
    }
    return lk;
  }
}
