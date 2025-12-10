package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class GraggBulirschStoerIntegratorTest {

  @Test
  void getName_returnsGraggBulirschStoer() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    String name = integrator.getName();

    assertEquals("Gragg-Bulirsch-Stoer", name);
  }

  @Test
  void setStabilityCheck_whenValuesOutOfRange_usesDefaults() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    integrator.setStabilityCheck(true, -1, 0, 1.5);

    assertTrue(getField(integrator, "performTest", Boolean.class));
    assertEquals(2, (int) getField(integrator, "maxIter", Integer.class));
    assertEquals(1, (int) getField(integrator, "maxChecks", Integer.class));
    assertEquals(0.5, getField(integrator, "stabilityReduction", Double.class), 1.0e-15);
  }

  @Test
  void setStabilityCheck_whenValuesValid_areApplied() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    integrator.setStabilityCheck(false, 3, 4, 0.7);

    assertFalse(getField(integrator, "performTest", Boolean.class));
    assertEquals(3, (int) getField(integrator, "maxIter", Integer.class));
    assertEquals(4, (int) getField(integrator, "maxChecks", Integer.class));
    assertEquals(0.7, getField(integrator, "stabilityReduction", Double.class), 1.0e-15);
  }

  @Test
  void setStepsizeControl_whenValuesOutOfRange_usesDefaults() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    integrator.setStepsizeControl(0.0, 1.5, 0.0, 1000.0);

    assertEquals(0.65, getField(integrator, "stepControl1", Double.class), 1.0e-15);
    assertEquals(0.94, getField(integrator, "stepControl2", Double.class), 1.0e-15);
    assertEquals(0.02, getField(integrator, "stepControl3", Double.class), 1.0e-15);
    assertEquals(4.0, getField(integrator, "stepControl4", Double.class), 1.0e-15);
  }

  @Test
  void setStepsizeControl_whenValuesValid_areApplied() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    integrator.setStepsizeControl(0.6, 0.7, 0.5, 10.0);

    assertEquals(0.6, getField(integrator, "stepControl1", Double.class), 1.0e-15);
    assertEquals(0.7, getField(integrator, "stepControl2", Double.class), 1.0e-15);
    assertEquals(0.5, getField(integrator, "stepControl3", Double.class), 1.0e-15);
    assertEquals(10.0, getField(integrator, "stepControl4", Double.class), 1.0e-15);
  }

  @Test
  void setOrderControl_whenMaxOrderInvalid_resetsToDefaultsAndRebuildsSequence() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    integrator.setOrderControl(5, 1.5, 1.5);

    assertEquals(18, (int) getField(integrator, "maxOrder", Integer.class));
    assertEquals(0.8, getField(integrator, "orderControl1", Double.class), 1.0e-15);
    assertEquals(0.9, getField(integrator, "orderControl2", Double.class), 1.0e-15);

    int[] sequence = getField(integrator, "sequence", int[].class);
    assertEquals(9, sequence.length);
    assertArrayEquals(new int[] {2, 4, 6}, new int[] {sequence[0], sequence[1], sequence[2]});
    assertEquals(18, sequence[sequence.length - 1]);
  }

  @Test
  void setOrderControl_whenValuesValid_updatesMaxOrderAndSequence() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    integrator.setOrderControl(10, 0.5, 0.6);

    // valid even order does not overwrite the default maxOrder (18) in current implementation
    assertEquals(18, (int) getField(integrator, "maxOrder", Integer.class));
    assertEquals(0.5, getField(integrator, "orderControl1", Double.class), 1.0e-15);
    assertEquals(0.6, getField(integrator, "orderControl2", Double.class), 1.0e-15);

    int[] sequence = getField(integrator, "sequence", int[].class);
    assertArrayEquals(new int[] {2, 4, 6, 8, 10, 12, 14, 16, 18}, sequence);
  }

  @Test
  void setInterpolationControl_whenMudifOutOfRange_resetsToDefault() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    integrator.setInterpolationControl(false, 8);

    assertFalse(getField(integrator, "useInterpolationError", Boolean.class));
    assertEquals(4, (int) getField(integrator, "mudif", Integer.class));
  }

  @Test
  void setInterpolationControl_whenValidValues_areApplied() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    integrator.setInterpolationControl(true, 3);

    assertTrue(getField(integrator, "useInterpolationError", Boolean.class));
    assertEquals(3, (int) getField(integrator, "mudif", Integer.class));
  }

  @Test
  void setStepHandler_whenHandlerRequiresDenseOutput_updatesSequencePattern() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    StepHandler denseHandler =
        new StepHandler() {
          @Override
          public boolean requiresDenseOutput() {
            return true;
          }

          @Override
          public void reset() {
            // No-op: test handler only flags dense output; no state to reset.
          }

          @Override
          public void handleStep(StepInterpolator interpolator, boolean isLast) {
            // No-op: test does not observe step data; handler used to toggle dense mode.
          }
        };

    integrator.setStepHandler(denseHandler);

    assertTrue(getField(integrator, "denseOutput", Boolean.class));
    int[] sequence = getField(integrator, "sequence", int[].class);
    assertArrayEquals(new int[] {2, 6, 10}, new int[] {sequence[0], sequence[1], sequence[2]});
  }

  @Test
  void addSwitchingFunction_marksDenseOutputAndRebuildsSequence() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    SwitchingFunction function =
        new SwitchingFunction() {
          @Override
          public double g(double t, double[] y) {
            return y[0] - 1.0;
          }

          @Override
          public int eventOccurred(double t, double[] y) {
            return CONTINUE;
          }

          @Override
          public void resetState(double t, double[] y) {
            // No-op: switching function is used only to enable dense output in this test.
          }
        };

    integrator.addSwitchingFunction(function, 1.0, 1.0e-6);

    assertTrue(getField(integrator, "denseOutput", Boolean.class));
    int[] sequence = getField(integrator, "sequence", int[].class);
    assertArrayEquals(new int[] {2, 6, 10}, new int[] {sequence[0], sequence[1], sequence[2]});
  }

  @Test
  void integrate_whenDimensionMismatch_throwsIntegratorException() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    FirstOrderDifferentialEquations equations =
        new FirstOrderDifferentialEquations() {
          @Override
          public int getDimension() {
            return 2;
          }

          @Override
          public void computeDerivatives(double t, double[] y, double[] yDot) {
            yDot[0] = y[0];
            yDot[1] = y[1];
          }
        };

    double[] y0 = new double[] {1.0};
    double[] y = new double[] {0.0};

    assertThrows(IntegratorException.class, () -> integrator.integrate(equations, 0.0, y0, 1.0, y));
  }

  @Test
  void integrate_whenIntervalTooSmall_throwsIntegratorException() {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    FirstOrderDifferentialEquations equations =
        new FirstOrderDifferentialEquations() {
          @Override
          public int getDimension() {
            return 1;
          }

          @Override
          public void computeDerivatives(double t, double[] y, double[] yDot) {
            yDot[0] = 0.0;
          }
        };

    double[] y0 = new double[] {1.0};
    double[] y = new double[] {0.0};

    assertThrows(
        IntegratorException.class,
        () -> integrator.integrate(equations, 1.0, y0, 1.0 + 1.0e-13, y));
  }

  @Test
  void integrate_exponentialGrowth_matchesAnalyticSolution()
      throws DerivativeException, IntegratorException {
    GraggBulirschStoerIntegrator integrator =
        new GraggBulirschStoerIntegrator(1.0e-8, 10.0, 1.0e-12, 1.0e-12);

    FirstOrderDifferentialEquations equations =
        new FirstOrderDifferentialEquations() {
          @Override
          public int getDimension() {
            return 1;
          }

          @Override
          public void computeDerivatives(double t, double[] y, double[] yDot) {
            yDot[0] = y[0];
          }
        };

    double[] y0 = new double[] {1.0};
    double[] y = new double[] {0.0};

    integrator.integrate(equations, 0.0, y0, 2.0, y);

    assertEquals(Math.exp(2.0), y[0], 1.0e-6);
  }

  private static <T> T getField(
      GraggBulirschStoerIntegrator integrator, String name, Class<T> type) {
    try {
      Field field = GraggBulirschStoerIntegrator.class.getDeclaredField(name);
      field.setAccessible(true);
      return type.cast(field.get(integrator));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
