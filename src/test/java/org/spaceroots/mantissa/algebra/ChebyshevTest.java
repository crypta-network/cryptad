package org.spaceroots.mantissa.algebra;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.spaceroots.mantissa.algebra.Polynomial.Rational;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ChebyshevTest {

  @Test
  void constructorNoArg_whenInvoked_buildsDegreeZeroConstantOne() {
    Chebyshev polynomial = new Chebyshev();

    assertEquals(0, polynomial.getDegree());
    assertTrue(polynomial.isOne());
    assertEquals(1.0, polynomial.valueAt(2.5));
    assertArrayEquals(new RationalNumber[] {RationalNumber.ONE}, polynomial.getCoefficients());
  }

  @Test
  void constructorWithDegree_whenOne_buildsIdentityPolynomial() {
    Chebyshev polynomial = new Chebyshev(1);

    assertEquals(1, polynomial.getDegree());
    assertTrue(polynomial.isIdentity());
    assertArrayEquals(
        new RationalNumber[] {RationalNumber.ZERO, RationalNumber.ONE},
        polynomial.getCoefficients());
    assertEquals(3.0, polynomial.valueAt(3.0));
  }

  @Test
  void constructorWithDegree_whenThree_buildsExpectedCoefficients() {
    Chebyshev polynomial = new Chebyshev(3);

    RationalNumber[] expected =
        new RationalNumber[] {
          RationalNumber.ZERO, new RationalNumber(-3L), RationalNumber.ZERO, new RationalNumber(4L)
        };

    assertEquals(3, polynomial.getDegree());
    assertArrayEquals(expected, polynomial.getCoefficients());
  }

  @Test
  void derivative_whenAppliedToDegreeThree_matchesAnalyticDerivative() {
    Chebyshev polynomial = new Chebyshev(3);

    Polynomial derivative = polynomial.getDerivative();

    assertInstanceOf(Rational.class, derivative);
    assertEquals(2, derivative.getDegree());
    assertArrayEquals(
        new RationalNumber[] {
          new RationalNumber(-3L), RationalNumber.ZERO, new RationalNumber(12L)
        },
        ((Polynomial.Rational) derivative).getCoefficients());
  }

  @ParameterizedTest
  @MethodSource("chebyshevValues")
  void valueAt_whenUsingCosIdentity_matchesExpected(int degree, double x, double expected) {
    Chebyshev polynomial = new Chebyshev(degree);

    double actual = polynomial.valueAt(x);

    assertEquals(expected, actual, 1e-12);
  }

  private static Stream<Arguments> chebyshevValues() {
    return Stream.of(
        argumentFor(0, 0.3),
        argumentFor(1, 0.3),
        argumentFor(2, 0.3),
        argumentFor(3, 0.75),
        argumentFor(4, -0.5),
        argumentFor(5, -0.2));
  }

  private static Arguments argumentFor(int degree, double x) {
    double expected = Math.cos(degree * Math.acos(x));
    return Arguments.of(degree, x, expected);
  }
}
