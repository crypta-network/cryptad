package org.spaceroots.mantissa.algebra;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.spaceroots.mantissa.algebra.Polynomial.Rational;

@SuppressWarnings("java:S100")
class LegendreTest {

  @Test
  void constructorNoArg_whenInvoked_buildsDegreeZeroConstantOne() {
    Legendre polynomial = new Legendre();

    assertEquals(0, polynomial.getDegree());
    assertTrue(polynomial.isOne());
    assertEquals(1.0, polynomial.valueAt(2.5));
    assertArrayEquals(new RationalNumber[] {RationalNumber.ONE}, polynomial.getCoefficients());
  }

  @Test
  void constructorWithDegree_whenOne_buildsIdentityPolynomial() {
    Legendre polynomial = new Legendre(1);

    assertEquals(1, polynomial.getDegree());
    assertTrue(polynomial.isIdentity());
    assertArrayEquals(
        new RationalNumber[] {RationalNumber.ZERO, RationalNumber.ONE},
        polynomial.getCoefficients());
    assertEquals(-3.0, polynomial.valueAt(-3.0));
  }

  @Test
  void constructorWithDegree_whenTwo_matchesClosedFormCoefficients() {
    Legendre polynomial = new Legendre(2);

    RationalNumber[] expected =
        new RationalNumber[] {
          new RationalNumber(-1L, 2L), RationalNumber.ZERO, new RationalNumber(3L, 2L)
        };

    assertEquals(2, polynomial.getDegree());
    assertArrayEquals(expected, polynomial.getCoefficients());
    assertEquals(-0.5, polynomial.valueAt(0.0));
    assertEquals(1.0, polynomial.valueAt(1.0));
  }

  @Test
  void constructorWithDegree_whenThree_matchesClosedFormCoefficients() {
    Legendre polynomial = new Legendre(3);

    RationalNumber[] expected =
        new RationalNumber[] {
          RationalNumber.ZERO,
          new RationalNumber(-3L, 2L),
          RationalNumber.ZERO,
          new RationalNumber(5L, 2L)
        };

    assertEquals(3, polynomial.getDegree());
    assertArrayEquals(expected, polynomial.getCoefficients());
    assertEquals(0.0, polynomial.valueAt(0.0));
    assertEquals(-1.0, polynomial.valueAt(-1.0));
  }

  @Test
  void getCoefficients_whenMutatedExternally_doesNotAffectInternalState() {
    Legendre polynomial = new Legendre(3);

    RationalNumber[] original = polynomial.getCoefficients();
    original[0] = new RationalNumber(999L);

    assertArrayEquals(
        new RationalNumber[] {
          RationalNumber.ZERO,
          new RationalNumber(-3L, 2L),
          RationalNumber.ZERO,
          new RationalNumber(5L, 2L)
        },
        polynomial.getCoefficients());
  }

  @Test
  void getDerivative_whenAppliedToDegreeTwo_matchesAnalyticDerivative() {
    Legendre polynomial = new Legendre(2);

    Polynomial derivative = polynomial.getDerivative();

    assertInstanceOf(Rational.class, derivative);
    assertEquals(1, derivative.getDegree());
    assertArrayEquals(
        new RationalNumber[] {RationalNumber.ZERO, new RationalNumber(3L)},
        ((Polynomial.Rational) derivative).getCoefficients());
    assertEquals(6.0, derivative.valueAt(2.0));
  }

  @ParameterizedTest
  @MethodSource("endpointValues")
  void valueAt_whenEvaluatedAtEndpoints_matchesParityProperty(int degree, double expectedAtMinus1) {
    Legendre polynomial = new Legendre(degree);

    assertEquals(1.0, polynomial.valueAt(1.0), 1e-12);
    assertEquals(expectedAtMinus1, polynomial.valueAt(-1.0), 1e-12);
  }

  private static Stream<Arguments> endpointValues() {
    return Stream.of(
        Arguments.of(0, 1.0),
        Arguments.of(1, -1.0),
        Arguments.of(2, 1.0),
        Arguments.of(3, -1.0),
        Arguments.of(4, 1.0));
  }
}
