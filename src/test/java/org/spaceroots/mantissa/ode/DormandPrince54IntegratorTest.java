package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class DormandPrince54IntegratorTest {

  @Test
  void getName_returnsDormandPrinceIdentifier() {
    DormandPrince54Integrator integrator =
        new DormandPrince54Integrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    String name = integrator.getName();

    assertEquals("Dormand-Prince 5(4)", name);
  }

  @Test
  void getOrder_returnsFive() {
    DormandPrince54Integrator integrator =
        new DormandPrince54Integrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

    int order = integrator.getOrder();

    assertEquals(5, order);
  }

  @Test
  void estimateError_withScalarTolerances_computesRootMeanSquare() {
    DormandPrince54Integrator integrator =
        new DormandPrince54Integrator(1.0e-6, 2.0, 1.0e-4, 1.0e-2);

    double[][] yDotK = new double[7][1];
    yDotK[0][0] = 1.0;
    yDotK[1][0] = 2.0;
    yDotK[2][0] = 3.0;
    yDotK[3][0] = 4.0;
    yDotK[4][0] = 5.0;
    yDotK[5][0] = 6.0;
    yDotK[6][0] = 7.0;

    double[] y0 = new double[] {1.0};
    double[] y1 = new double[] {1.2};

    double error = integrator.estimateError(yDotK, y0, y1, 0.5);

    assertEquals(1.714852055225125, error, 1.0e-15);
  }

  @Test
  void estimateError_withVectorTolerances_scalesEachComponentIndependently() {
    double[] absTol = new double[] {1.0e-4, 5.0e-4};
    double[] relTol = new double[] {1.0e-2, 2.0e-2};
    DormandPrince54Integrator integrator =
        new DormandPrince54Integrator(1.0e-6, 2.0, absTol, relTol);

    double[][] yDotK = new double[7][2];
    yDotK[0][0] = 1.0;
    yDotK[1][0] = 2.0;
    yDotK[2][0] = 3.0;
    yDotK[3][0] = 4.0;
    yDotK[4][0] = 5.0;
    yDotK[5][0] = 6.0;
    yDotK[6][0] = 7.0;

    yDotK[0][1] = 0.0;
    yDotK[1][1] = 0.0;
    yDotK[2][1] = 5.0;
    yDotK[3][1] = 0.0;
    yDotK[4][1] = 0.0;
    yDotK[5][1] = 0.0;
    yDotK[6][1] = 0.0;

    double[] y0 = new double[] {0.5, -1.0};
    double[] y1 = new double[] {0.6, -0.9};

    double error = integrator.estimateError(yDotK, y0, y1, 0.3);

    assertEquals(1.4598509404672162, error, 1.0e-15);
  }

  @Test
  void integrate_whenSolvingExp_returnsAccurateState()
      throws DerivativeException, IntegratorException {
    DormandPrince54Integrator integrator =
        new DormandPrince54Integrator(1.0e-8, 10.0, 1.0e-10, 1.0e-10);

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

  @Test
  void integrate_whenDimensionMismatch_throwsIntegratorException() {
    DormandPrince54Integrator integrator =
        new DormandPrince54Integrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

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
    DormandPrince54Integrator integrator =
        new DormandPrince54Integrator(1.0e-6, 1.0, 1.0e-9, 1.0e-9);

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
}
