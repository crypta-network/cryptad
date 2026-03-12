// New test file for Hermite polynomials
package org.spaceroots.mantissa.algebra;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class HermiteTest {

  @Test
  void constructor_withoutDegree_buildsDegreeZeroPolynomial() {
    Hermite h0 = new Hermite();

    RationalNumber[] coefficients = h0.getCoefficients();

    assertEquals(0, h0.getDegree());
    assertArrayEquals(new RationalNumber[] {new RationalNumber(1)}, coefficients);
  }

  @Test
  void constructor_withDegreeOne_buildsExpectedLinearPolynomial() {
    Hermite h1 = new Hermite(1);

    RationalNumber[] coefficients = h1.getCoefficients();

    assertEquals(1, h1.getDegree());
    assertArrayEquals(
        new RationalNumber[] {new RationalNumber(0), new RationalNumber(2)}, coefficients);
  }

  @Test
  void constructor_withDegreeFour_matchesClosedFormCoefficients() {
    Hermite h4 = new Hermite(4);

    RationalNumber[] coefficients = h4.getCoefficients();

    assertEquals(4, h4.getDegree());
    assertArrayEquals(
        new RationalNumber[] {
          new RationalNumber(12),
          new RationalNumber(0),
          new RationalNumber(-48),
          new RationalNumber(0),
          new RationalNumber(16)
        },
        coefficients);
  }

  @ParameterizedTest
  @MethodSource("recurrenceSamples")
  void valueAt_satisfiesThreeTermRecurrence(int k, double x) {
    Hermite hkPlus1 = new Hermite(k + 1);
    Hermite hk = new Hermite(k);
    Hermite hkMinus1 = new Hermite(k - 1);

    double left = hkPlus1.valueAt(x);
    double right = 2 * x * hk.valueAt(x) - 2 * k * hkMinus1.valueAt(x);

    assertEquals(right, left, 1.0e-10);
  }

  private static Stream<Arguments> recurrenceSamples() {
    return Stream.of(
        Arguments.of(1, -1.3), Arguments.of(2, 0.0), Arguments.of(3, 0.75), Arguments.of(4, 1.2));
  }

  @ParameterizedTest
  @MethodSource("derivativeSamples")
  void derivative_matchesAnalyticalIdentity(int degree, double x) {
    Hermite hn = new Hermite(degree);
    Polynomial derivative = hn.getDerivative();

    double expected = 2 * degree * new Hermite(degree - 1).valueAt(x);

    assertEquals(expected, derivative.valueAt(x), 1.0e-10);
  }

  private static Stream<Arguments> derivativeSamples() {
    return Stream.of(
        Arguments.of(1, -2.0), Arguments.of(2, -0.5), Arguments.of(3, 0.0), Arguments.of(4, 1.7));
  }

  @Test
  void derivative_ofConstantPolynomial_isZeroPolynomial() {
    Hermite h0 = new Hermite();

    Polynomial derivative = h0.getDerivative();

    assertTrue(derivative.isZero());
    assertEquals(0.0, derivative.valueAt(5.0));
  }
}
