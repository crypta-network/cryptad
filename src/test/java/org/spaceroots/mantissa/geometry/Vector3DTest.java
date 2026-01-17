package org.spaceroots.mantissa.geometry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@SuppressWarnings("java:S100")
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class Vector3DTest {

  private static final double EPS = 1.0e-12;

  @Test
  void defaultConstructor_createsZeroVector() {
    Vector3D vector = new Vector3D();

    assertEquals(0.0, vector.getX(), EPS);
    assertEquals(0.0, vector.getY(), EPS);
    assertEquals(0.0, vector.getZ(), EPS);
    assertEquals(0.0, vector.getNorm(), EPS);
  }

  @Test
  void coordinateConstructor_setsFields() {
    Vector3D vector = new Vector3D(1.5, -2.0, 3.25);

    assertEquals(1.5, vector.getX(), EPS);
    assertEquals(-2.0, vector.getY(), EPS);
    assertEquals(3.25, vector.getZ(), EPS);
  }

  @Test
  void sphericalConstructor_preservesAlphaAndDelta() {
    double alpha = Math.PI / 3;
    double delta = Math.PI / 6;

    Vector3D vector = new Vector3D(alpha, delta);

    assertEquals(alpha, vector.getAlpha(), EPS);
    assertEquals(delta, vector.getDelta(), EPS);
    assertEquals(1.0, vector.getNorm(), EPS);
  }

  @Test
  void scaleConstructor_multipliesComponents() {
    Vector3D base = new Vector3D(1, -2, 3);

    Vector3D scaled = new Vector3D(2.5, base);

    assertEquals(2.5, scaled.getX(), EPS);
    assertEquals(-5.0, scaled.getY(), EPS);
    assertEquals(7.5, scaled.getZ(), EPS);
  }

  @Test
  void linearConstructor_twoVectors_combinesCorrectly() {
    Vector3D result =
        new Vector3D(
            LinearCombination.of(
                LinearCombination.term(2, Vector3D.plusI),
                LinearCombination.term(-3, Vector3D.minusJ)));

    assertEquals(2.0, result.getX(), EPS);
    assertEquals(3.0, result.getY(), EPS);
    assertEquals(0.0, result.getZ(), EPS);
  }

  @Test
  void linearConstructor_threeVectors_combinesCorrectly() {
    Vector3D result =
        new Vector3D(
            LinearCombination.of(
                LinearCombination.term(1, Vector3D.plusI),
                LinearCombination.term(2, Vector3D.plusJ),
                LinearCombination.term(3, Vector3D.plusK)));

    assertEquals(1.0, result.getX(), EPS);
    assertEquals(2.0, result.getY(), EPS);
    assertEquals(3.0, result.getZ(), EPS);
  }

  @Test
  void linearConstructor_fourVectors_combinesCorrectly() {
    Vector3D result =
        new Vector3D(
            LinearCombination.of(
                LinearCombination.term(1, Vector3D.plusI),
                LinearCombination.term(1, Vector3D.plusJ),
                LinearCombination.term(1, Vector3D.plusK),
                LinearCombination.term(-2, Vector3D.minusK)));

    assertEquals(1.0, result.getX(), EPS);
    assertEquals(1.0, result.getY(), EPS);
    assertEquals(3.0, result.getZ(), EPS);
  }

  @Test
  void getAlpha_handlesAllQuadrants() {
    Vector3D vector = new Vector3D(-1, 1, 0);

    assertEquals(3 * Math.PI / 4, vector.getAlpha(), EPS);
  }

  @Test
  void getDelta_reflectsElevation() {
    Vector3D vector = new Vector3D(0, Math.sqrt(3), 1);

    assertEquals(Math.PI / 6, vector.getDelta(), EPS);
  }

  @Test
  void add_addsCoordinates() {
    Vector3D sum = new Vector3D(1, 2, 3).add(new Vector3D(-2, 4, 1));

    assertEquals(-1.0, sum.getX(), EPS);
    assertEquals(6.0, sum.getY(), EPS);
    assertEquals(4.0, sum.getZ(), EPS);
  }

  @Test
  void add_withFactor_scalesBeforeAdding() {
    Vector3D sum = new Vector3D(1, 1, 1).add(2, new Vector3D(0.5, -1, 3));

    assertEquals(2.0, sum.getX(), EPS);
    assertEquals(-1.0, sum.getY(), EPS);
    assertEquals(7.0, sum.getZ(), EPS);
  }

  @Test
  void subtract_subtractsCoordinates() {
    Vector3D diff = new Vector3D(5, -2, 4).subtract(new Vector3D(1, 1, 6));

    assertEquals(4.0, diff.getX(), EPS);
    assertEquals(-3.0, diff.getY(), EPS);
    assertEquals(-2.0, diff.getZ(), EPS);
  }

  @Test
  void subtract_withFactor_scalesBeforeSubtracting() {
    Vector3D diff = new Vector3D(1, 1, 1).subtract(3, new Vector3D(0.5, -1, 2));

    assertEquals(-0.5, diff.getX(), EPS);
    assertEquals(4.0, diff.getY(), EPS);
    assertEquals(-5.0, diff.getZ(), EPS);
  }

  @Test
  void multiply_scalesVector() {
    Vector3D product = new Vector3D(-1, 2, -3).multiply(4);

    assertEquals(-4.0, product.getX(), EPS);
    assertEquals(8.0, product.getY(), EPS);
    assertEquals(-12.0, product.getZ(), EPS);
  }

  @Test
  void negate_invertsComponents() {
    Vector3D negated = new Vector3D(1.2, -3.4, 5.6).negate();

    assertEquals(-1.2, negated.getX(), EPS);
    assertEquals(3.4, negated.getY(), EPS);
    assertEquals(-5.6, negated.getZ(), EPS);
  }

  @Test
  void normalize_returnsUnitVector() {
    Vector3D vector = new Vector3D(2, 0, 0);

    Vector3D normalized = vector.normalize();

    assertEquals(1.0, normalized.getX(), EPS);
    assertEquals(0.0, normalized.getY(), EPS);
    assertEquals(0.0, normalized.getZ(), EPS);
    assertEquals(1.0, normalized.getNorm(), EPS);
  }

  @Test
  void normalize_zeroVector_throwsArithmeticException() {
    Vector3D zero = new Vector3D();

    assertThrows(ArithmeticException.class, zero::normalize);
  }

  @Test
  void orthogonal_forSmallX_usesYZBranch() {
    Vector3D vector = new Vector3D(0.1, 1, 0);

    Vector3D orthogonal = vector.orthogonal();

    assertTrue(Math.abs(Vector3D.dotProduct(vector, orthogonal)) < EPS);
    assertEquals(1.0, orthogonal.getNorm(), EPS);
  }

  @Test
  void orthogonal_forSmallY_usesXZBranch() {
    Vector3D vector = new Vector3D(1, 0.1, 0);

    Vector3D orthogonal = vector.orthogonal();

    assertTrue(Math.abs(Vector3D.dotProduct(vector, orthogonal)) < EPS);
    assertEquals(1.0, orthogonal.getNorm(), EPS);
  }

  @Test
  void orthogonal_forLargeXY_usesXYBranch() {
    Vector3D vector = new Vector3D(1, 1, 1);

    Vector3D orthogonal = vector.orthogonal();

    assertTrue(Math.abs(Vector3D.dotProduct(vector, orthogonal)) < EPS);
    assertEquals(1.0, orthogonal.getNorm(), EPS);
  }

  @Test
  void orthogonal_zeroVector_throwsArithmeticException() {
    Vector3D zero = new Vector3D();

    assertThrows(ArithmeticException.class, zero::orthogonal);
  }

  @Test
  void angle_forPerpendicularVectors_returnsPiOver2() {
    double angle = Vector3D.angle(Vector3D.plusI, Vector3D.plusJ);

    assertEquals(Math.PI / 2, angle, EPS);
  }

  @Test
  void angle_forAlmostAlignedVectors_returnsSmallAngle() {
    Vector3D v1 = new Vector3D(1, 0, 0);
    Vector3D v2 = new Vector3D(0.99999, 0, 0);

    double angle = Vector3D.angle(v1, v2);

    assertEquals(0.0, angle, 1.0e-6);
  }

  @Test
  void angle_forAlmostOppositeVectors_returnsPi() {
    Vector3D v1 = new Vector3D(1, 0, 0);
    Vector3D v2 = new Vector3D(-0.99999, 0, 0);

    double angle = Vector3D.angle(v1, v2);

    assertEquals(Math.PI, angle, 1.0e-6);
  }

  @Test
  void angle_withZeroNorm_throwsArithmeticException() {
    Vector3D zero = new Vector3D();

    assertThrows(ArithmeticException.class, () -> Vector3D.angle(zero, Vector3D.plusI));
  }

  @ParameterizedTest
  @CsvSource({"1, 0, 0, 1", "0, 1, 0, 2", "0, 0, 1, 3", "3, 4, 5, 26"})
  void dotProduct_calculatesExpectedValue(
      double x2, double y2, double z2, double expectedDotProduct) {
    Vector3D v1 = new Vector3D(1, 2, 3);
    Vector3D v2 = new Vector3D(x2, y2, z2);

    double dot = Vector3D.dotProduct(v1, v2);

    assertEquals(expectedDotProduct, dot, EPS);
  }

  @Test
  void crossProduct_followsRightHandRule() {
    Vector3D cross = Vector3D.crossProduct(Vector3D.plusI, Vector3D.plusJ);

    assertEquals(0.0, cross.getX(), EPS);
    assertEquals(0.0, cross.getY(), EPS);
    assertEquals(1.0, cross.getZ(), EPS);
  }
}
