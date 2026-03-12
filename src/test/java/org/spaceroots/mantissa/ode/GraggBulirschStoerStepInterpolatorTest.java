package org.spaceroots.mantissa.ode;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

@SuppressWarnings("java:S100")
class GraggBulirschStoerStepInterpolatorTest {

  @Test
  void computeCoefficients_whenMuNegative_setsBaseCoefficientsOnly() {

    double[] y = new double[] {1.0};
    double[] y0Dot = new double[] {0.5};
    double[] y1 = new double[] {3.0};
    double[] y1Dot = new double[] {1.5};
    double[][] yMidDots = new double[][] {new double[] {0.0}};

    GraggBulirschStoerStepInterpolator interpolator =
        new GraggBulirschStoerStepInterpolator(y, y0Dot, y1, y1Dot, yMidDots, true);

    interpolator.computeCoefficients(-1, 2.0);

    double[][] polynoms = polynomsOf(interpolator);
    assertEquals(3, currentDegreeOf(interpolator));
    assertArrayEquals(new double[] {1.0}, polynoms[0], 1.0e-15);
    assertArrayEquals(new double[] {2.0}, polynoms[1], 1.0e-15);
    assertArrayEquals(new double[] {-1.0}, polynoms[2], 1.0e-15);
    assertArrayEquals(new double[] {-1.0}, polynoms[3], 1.0e-15);
  }

  @Test
  void computeInterpolatedState_whenThetaHalf_matchesCubicPolynomial() throws DerivativeException {

    double[] y = new double[] {1.0};
    double[] y0Dot = new double[] {0.5};
    double[] y1 = new double[] {3.0};
    double[] y1Dot = new double[] {1.5};
    double[][] yMidDots = new double[][] {new double[] {0.0}};

    GraggBulirschStoerStepInterpolator interpolator =
        new GraggBulirschStoerStepInterpolator(y, y0Dot, y1, y1Dot, yMidDots, true);

    interpolator.computeCoefficients(-1, 1.0);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);

    interpolator.setInterpolatedTime(0.5);
    double[] state = interpolator.getInterpolatedState();

    assertEquals(1.875, state[0], 1.0e-12);
  }

  @Test
  void estimateError_whenDegreeBelowThreshold_returnsZero() {
    double[] y = new double[] {0.0};
    double[] y0Dot = new double[] {0.0};
    double[] y1 = new double[] {1.0};
    double[] y1Dot = new double[] {0.0};
    double[][] yMidDots = new double[][] {new double[] {0.0}};

    GraggBulirschStoerStepInterpolator interpolator =
        new GraggBulirschStoerStepInterpolator(y, y0Dot, y1, y1Dot, yMidDots, true);

    interpolator.computeCoefficients(-1, 1.0);

    assertEquals(0.0, interpolator.estimateError(new double[] {1.0}), 0.0);
  }

  @Test
  void estimateError_whenDegreeAtLeastFive_appliesErrfacScaling() {
    double[] y = new double[] {1.0};
    double[] y0Dot = new double[] {1.0};
    double[] y1 = new double[] {2.0};
    double[] y1Dot = new double[] {1.0};
    double[][] yMidDots = new double[][] {new double[] {1.6}, new double[] {1.2}};

    GraggBulirschStoerStepInterpolator interpolator =
        new GraggBulirschStoerStepInterpolator(y, y0Dot, y1, y1Dot, yMidDots, true);

    interpolator.computeCoefficients(1, 1.0);

    double[][] polynoms = polynomsOf(interpolator);
    assertEquals(3.2, polynoms[5][0], 1.0e-12);

    double error = interpolator.estimateError(new double[] {1.0});

    double expectedErrfac = 1.0 / 25.0;
    expectedErrfac *= 0.5 * Math.sqrt(1.0 / 5.0);
    double expected = 3.2 * expectedErrfac;

    assertEquals(expected, error, 1.0e-14);
  }

  @Test
  void copy_whenCalled_producesDeepIndependentPolynoms() {
    double[] y = new double[] {2.0};
    double[] y0Dot = new double[] {0.0};
    double[] y1 = new double[] {4.0};
    double[] y1Dot = new double[] {0.0};
    double[][] yMidDots = new double[][] {new double[] {0.0}};

    GraggBulirschStoerStepInterpolator original =
        new GraggBulirschStoerStepInterpolator(y, y0Dot, y1, y1Dot, yMidDots, true);
    original.computeCoefficients(0, 1.0);

    GraggBulirschStoerStepInterpolator copy = original.copy();

    double[][] originalPolynoms = polynomsOf(original);
    double[][] copiedPolynoms = polynomsOf(copy);
    assertEquals(currentDegreeOf(original), currentDegreeOf(copy));
    assertNotSame(originalPolynoms, copiedPolynoms);
    assertArrayEquals(originalPolynoms[0], copiedPolynoms[0], 0.0);

    originalPolynoms[0][0] = 123.0;

    assertEquals(2.0, copiedPolynoms[0][0], 0.0);
  }

  @Test
  void serialization_roundTrip_preservesInterpolatedState()
      throws IOException, DerivativeException {
    double[] y = new double[] {0.0};
    double[] y0Dot = new double[] {1.0};
    double[] y1 = new double[] {1.0};
    double[] y1Dot = new double[] {1.0};
    double[][] yMidDots = new double[][] {new double[] {0.5}, new double[] {0.5}};

    GraggBulirschStoerStepInterpolator original =
        new GraggBulirschStoerStepInterpolator(y, y0Dot, y1, y1Dot, yMidDots, true);
    original.computeCoefficients(1, 1.0);
    original.previousTime = 2.0;
    original.storeTime(3.0);
    original.setInterpolatedTime(2.5);
    double[] expectedState = original.getInterpolatedState();

    byte[] serialized = serialize(original);

    GraggBulirschStoerStepInterpolator restored = new GraggBulirschStoerStepInterpolator();
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
      restored.readExternal(ois);
    }

    assertEquals(original.getPreviousTime(), restored.getPreviousTime(), 0.0);
    assertEquals(original.getCurrentTime(), restored.getCurrentTime(), 0.0);
    assertEquals(currentDegreeOf(original), currentDegreeOf(restored));
    assertArrayEquals(expectedState, restored.getInterpolatedState(), 1.0e-12);
  }

  private static double[][] polynomsOf(GraggBulirschStoerStepInterpolator interpolator) {
    try {
      Field field = GraggBulirschStoerStepInterpolator.class.getDeclaredField("polynoms");
      field.setAccessible(true);
      return (double[][]) field.get(interpolator);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static int currentDegreeOf(GraggBulirschStoerStepInterpolator interpolator) {
    try {
      Field field = GraggBulirschStoerStepInterpolator.class.getDeclaredField("currentDegree");
      field.setAccessible(true);
      return field.getInt(interpolator);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] serialize(GraggBulirschStoerStepInterpolator interpolator)
      throws IOException {
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      interpolator.writeExternal(oos);
      oos.flush();
      return bos.toByteArray();
    }
  }
}
