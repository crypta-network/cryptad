package org.spaceroots.mantissa.ode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DormandPrince853IntegratorTest {

  private static final double MIN_STEP = 1.0e-8;
  private static final double MAX_STEP = 1.0;

  @Test
  void getName_whenCalled_returnsMethodIdentifier() {
    DormandPrince853Integrator integrator = newScalarIntegrator();

    String name = integrator.getName();

    assertEquals("Dormand-Prince 8 (5, 3)", name);
  }

  @Test
  void getOrder_whenCalled_returnsEight() {
    DormandPrince853Integrator integrator = newScalarIntegrator();

    int order = integrator.getOrder();

    assertEquals(8, order);
  }

  @Test
  void estimateError_withZeroDerivatives_returnsZero() {
    DormandPrince853Integrator integrator = newScalarIntegrator();
    double[][] yDotK = new double[12][2];
    double[] y0 = {1.0, -2.0};
    double[] y1 = {1.0, -2.0};

    double error = integrator.estimateError(yDotK, y0, y1, 0.5);

    assertEquals(0.0, error);
  }

  @Test
  void estimateError_withVectorTolerances_usesComponentWiseScaling() {
    double[] vecAbs = {1.0e-6, 2.0e-6};
    double[] vecRel = {1.0e-3, 1.0e-3};
    DormandPrince853Integrator integrator =
        new DormandPrince853Integrator(MIN_STEP, MAX_STEP, vecAbs, vecRel);
    double[][] yDotK = buildDerivativeTable();
    double[] y0 = {1.0, 2.0};
    double[] y1 = {1.5, 1.8};

    double error = integrator.estimateError(yDotK, y0, y1, 0.1);

    assertEquals(2.7178071628129152, error, 1.0e-12);
  }

  @Test
  void estimateError_withScalarTolerances_scalesByMaxStateMagnitude() {
    DormandPrince853Integrator integrator = newScalarIntegrator();
    double[][] yDotK = buildDerivativeTable();
    double[] y0 = {1.0, 2.0};
    double[] y1 = {1.5, 1.8};

    double error = integrator.estimateError(yDotK, y0, y1, 0.1);

    assertEquals(2.7187473516016167, error, 1.0e-12);
  }

  @Test
  void integrate_whenIntervalTooSmall_throwsIntegratorException() {
    DormandPrince853Integrator integrator = newScalarIntegrator();
    double[] y0 = {1.0};
    double[] y = new double[1];

    assertThrows(
        IntegratorException.class,
        () -> integrator.integrate(new IdentityEquation(), 0.0, y0, 0.0, y));
  }

  @Test
  void integrate_whenStateDimensionMismatch_throwsIntegratorException() {
    DormandPrince853Integrator integrator = newScalarIntegrator();
    double[] y0 = {1.0, 2.0};
    double[] y = new double[2];

    assertThrows(
        IntegratorException.class,
        () -> integrator.integrate(new IdentityEquation(), 0.0, y0, 1.0, y));
  }

  private DormandPrince853Integrator newScalarIntegrator() {
    return new DormandPrince853Integrator(MIN_STEP, MAX_STEP, 1.0e-6, 1.0e-3);
  }

  private double[][] buildDerivativeTable() {
    double[][] yDotK = new double[12][2];
    for (int k = 0; k < yDotK.length; k++) {
      yDotK[k][0] = (k + 1) * 0.01;
      yDotK[k][1] = (k + 1) * 0.02;
    }
    return yDotK;
  }

  private static final class IdentityEquation implements FirstOrderDifferentialEquations {

    @Override
    public int getDimension() {
      return 1;
    }

    @Override
    public void computeDerivatives(double t, double[] y, double[] yDot) {
      yDot[0] = y[0];
    }
  }
}
