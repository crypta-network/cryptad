package org.spaceroots.mantissa.geometry;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class RotationTest {

  private static final double EPS = 1.0e-12;

  @Test
  void defaultConstructor_whenAppliedToVector_returnsSame() {
    Rotation rotation = new Rotation();
    Vector3D original = new Vector3D(1.25, -2.5, 3.75);

    Vector3D result = rotation.applyTo(original);

    assertAll(
        () -> assertVectorEquals(original, result, EPS),
        () -> assertEquals(0.0, rotation.getAngle(), EPS),
        () -> assertVectorEquals(new Vector3D(1, 0, 0), rotation.getAxis(), EPS),
        () ->
            assertArrayEquals(
                new double[] {
                  1.0, 0.0, 0.0,
                  0.0, 1.0, 0.0,
                  0.0, 0.0, 1.0
                },
                flatten(rotation.getMatrix()),
                EPS));
  }

  @Test
  void axisAngleConstructor_withPiOverTwoAroundZ_rotatesXToY() {
    Rotation rotation = new Rotation(Vector3D.plusK, Math.PI / 2.0);

    Vector3D rotated = rotation.applyTo(Vector3D.plusI);

    assertVectorEquals(Vector3D.plusJ, rotated, 1.0e-10);
  }

  @Test
  void axisAngleConstructor_withZeroAxis_throwsArithmeticException() {
    Vector3D zero = new Vector3D(0, 0, 0);

    assertThrows(ArithmeticException.class, () -> new Rotation(zero, 1.0));
  }

  @Test
  void quaternionConstructor_needsNormalization_normalizesInputs() {
    Rotation rotation = new Rotation(2.0, 2.0, 0.0, 0.0, true);

    double normSquared =
        rotation.getQ0() * rotation.getQ0()
            + rotation.getQ1() * rotation.getQ1()
            + rotation.getQ2() * rotation.getQ2()
            + rotation.getQ3() * rotation.getQ3();

    assertEquals(1.0, normSquared, EPS);
  }

  @Test
  void matrixConstructor_withImproperDeterminant_throwsNotARotationMatrixException() {
    double[][] improper = {
      {1.0, 0.0, 0.0},
      {0.0, 1.0, 0.0},
      {0.0, 0.0, -1.0}
    };

    assertThrows(NotARotationMatrixException.class, () -> new Rotation(improper, 1.0e-10));
  }

  @Test
  void matrixConstructor_withValidMatrix_producesEquivalentRotation() throws Exception {
    Rotation original = new Rotation(Vector3D.plusK, Math.PI / 3.0);
    double[][] matrix = original.getMatrix();

    Rotation rebuilt = new Rotation(matrix, 1.0e-12);
    Vector3D sample = new Vector3D(0.3, -1.2, 0.9);

    assertVectorEquals(original.applyTo(sample), rebuilt.applyTo(sample), 1.0e-12);
  }

  @Test
  void applyInverseTo_whenAppliedToRotatedVector_returnsOriginal() {
    Rotation rotation = new Rotation(new Vector3D(1, 1, 1), 0.75);
    Vector3D base = new Vector3D(-2.0, 5.0, 0.5);

    Vector3D rotated = rotation.applyTo(base);
    Vector3D recovered = rotation.applyInverseTo(rotated);

    assertVectorEquals(base, recovered, 1.0e-12);
  }

  @Test
  void applyToRotation_composesRotationsConsistently() {
    Rotation aroundX = new Rotation(Vector3D.plusI, Math.PI / 2.0);
    Rotation aroundY = new Rotation(Vector3D.plusJ, Math.PI / 3.0);

    Rotation composed = aroundX.applyTo(aroundY);
    Vector3D probe = new Vector3D(0.2, 0.3, 0.4);

    Vector3D sequential = aroundX.applyTo(aroundY.applyTo(probe));
    Vector3D viaComposition = composed.applyTo(probe);

    assertVectorEquals(sequential, viaComposition, 1.0e-12);
  }

  @Test
  void getAngles_whenUsingXYZOrder_returnsOriginalAngles() throws Exception {
    double a1 = 0.3;
    double a2 = -0.4;
    double a3 = 1.0;
    Rotation rotation = new Rotation(RotationOrder.XYZ, a1, a2, a3);

    double[] angles = rotation.getAngles(RotationOrder.XYZ);

    assertArrayEquals(new double[] {a1, a2, a3}, angles, 1.0e-12);
  }

  @Test
  void getAngles_whenEulerSequenceSingular_throwsCardanEulerSingularityException() {
    Rotation identity = new Rotation();

    assertThrows(
        CardanEulerSingularityException.class, () -> identity.getAngles(RotationOrder.ZYZ));
  }

  @Test
  void constructorWithTwoVectors_oppositeVectors_generatesPiRotation() {
    Vector3D u = Vector3D.plusI;
    Vector3D v = Vector3D.minusI;

    Rotation rotation = new Rotation(u, v);

    Vector3D result = rotation.applyTo(u);
    assertVectorEquals(v, result, 1.0e-12);
    assertEquals(Math.PI, rotation.getAngle(), 1.0e-12);
  }

  @Test
  void revert_whenAppliedAfterRotation_recoversOriginalVector() {
    Rotation rotation = new Rotation(Vector3D.plusJ, 0.9);
    Rotation reverted = rotation.revert();
    Vector3D source = new Vector3D(0.8, -0.6, 0.4);

    Vector3D rotated = rotation.applyTo(source);
    Vector3D recovered = reverted.applyTo(rotated);

    assertVectorEquals(source, recovered, 1.0e-12);
  }

  @Test
  void constructorWithVectorPairs_whenMappingOrthogonalBasis_alignsCorrectly() {
    Vector3D u1 = Vector3D.plusI;
    Vector3D u2 = Vector3D.plusJ;
    Vector3D v1 = Vector3D.plusJ;
    Vector3D v2 = Vector3D.minusI;

    Rotation rotation = new Rotation(u1, u2, v1, v2);

    assertAll(
        () -> assertVectorEquals(v1, rotation.applyTo(u1), 1.0e-12),
        () -> assertVectorEquals(v2, rotation.applyTo(u2), 1.0e-12));
  }

  private static double[] flatten(double[][] matrix) {
    return new double[] {
      matrix[0][0], matrix[0][1], matrix[0][2],
      matrix[1][0], matrix[1][1], matrix[1][2],
      matrix[2][0], matrix[2][1], matrix[2][2]
    };
  }

  private static void assertVectorEquals(Vector3D expected, Vector3D actual, double epsilon) {
    assertAll(
        () -> assertEquals(expected.getX(), actual.getX(), epsilon),
        () -> assertEquals(expected.getY(), actual.getY(), epsilon),
        () -> assertEquals(expected.getZ(), actual.getZ(), epsilon));
  }
}
