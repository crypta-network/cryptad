package org.spaceroots.mantissa.ode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyDouble;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ThreeEighthesIntegratorTest {

  private static final double EPS = 1.0e-12;

  private RecordingStepHandler handler;

  @BeforeEach
  void setUp() {
    handler = new RecordingStepHandler();
  }

  @Test
  void getName_whenCalled_returnsThreeEighthsIdentifier() {
    ThreeEighthesIntegrator integrator = new ThreeEighthesIntegrator(0.1);

    assertEquals("3/8", integrator.getName());
  }

  @Test
  void integrate_withConstantDerivative_matchesAnalyticSolutionAndStepCount()
      throws DerivativeException, IntegratorException {

    ThreeEighthesIntegrator integrator = new ThreeEighthesIntegrator(1.0);
    integrator.setStepHandler(handler);

    double[] state = new double[] {0.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 2.3, state);

    assertEquals(2.3, state[0], EPS);

    assertEquals(2, handler.currentTimes.size());
    assertEquals(0.0, handler.previousTimes.getFirst(), EPS);
    assertEquals(1.15, handler.stepSize(0), EPS);
    assertEquals(1.15, handler.stepSize(1), EPS);
    assertTrue(handler.lastFlags.get(1));
  }

  @Test
  void integrate_backwardDirection_decreasesSolution()
      throws DerivativeException, IntegratorException {

    ThreeEighthesIntegrator integrator = new ThreeEighthesIntegrator(0.5);
    integrator.setStepHandler(handler);

    double[] state = new double[] {4.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 2.0, state, 0.0, state);

    assertEquals(2.0, state[0], EPS);
    assertTrue(handler.currentTimes.stream().allMatch(t -> t <= 2.0));
    assertTrue(handler.currentTimes.getLast() < handler.previousTimes.getFirst());
  }

  @Test
  void integrate_withSwitchingFunction_callsGAndContinuesWhenNoZeroCrossing()
      throws DerivativeException, IntegratorException {

    ThreeEighthesIntegrator integrator = new ThreeEighthesIntegrator(0.5);
    integrator.setStepHandler(handler);

    SwitchingFunction switchFn = mock(SwitchingFunction.class);
    when(switchFn.g(anyDouble(), any(double[].class))).thenReturn(-1.0);
    integrator.addSwitchingFunction(
        switchFn, /* maxCheckInterval= */ 0.25, /* convergence= */ 1.0e-9);

    double[] state = new double[] {0.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 2.0, state);

    assertEquals(2.0, state[0], EPS);
    verify(switchFn, atLeastOnce()).g(anyDouble(), any(double[].class));
    verify(switchFn, never()).eventOccurred(anyDouble(), any(double[].class));
  }

  @Test
  void integrate_withTooSmallInterval_throwsIntegratorException() {
    ThreeEighthesIntegrator integrator = new ThreeEighthesIntegrator(0.1);
    double[] state = new double[] {1.0};

    assertThrows(
        IntegratorException.class,
        () -> integrator.integrate(new ConstantEquation(1, 0.0), 1.0, state, 1.0 + 1.0e-16, state));
  }

  @Test
  void integrate_withDimensionMismatch_throwsIntegratorException() {
    ThreeEighthesIntegrator integrator = new ThreeEighthesIntegrator(0.1);

    assertThrows(
        IntegratorException.class,
        () ->
            integrator.integrate(
                new ConstantEquation(2, 1.0), 0.0, new double[] {0.0}, 1.0, new double[] {0.0}));
  }

  private static final class ConstantEquation implements FirstOrderDifferentialEquations {

    private final int dimension;
    private final double derivativeValue;

    ConstantEquation(int dimension, double derivativeValue) {
      this.dimension = dimension;
      this.derivativeValue = derivativeValue;
    }

    @Override
    public int getDimension() {
      return dimension;
    }

    @Override
    public void computeDerivatives(double t, double[] y, double[] yDot) {
      Arrays.fill(yDot, derivativeValue);
    }
  }

  private static final class RecordingStepHandler implements StepHandler {

    private final List<Double> previousTimes = new ArrayList<>();
    private final List<Double> currentTimes = new ArrayList<>();
    private final List<Boolean> lastFlags = new ArrayList<>();

    @Override
    public boolean requiresDenseOutput() {
      return true;
    }

    @Override
    public void reset() {
      previousTimes.clear();
      currentTimes.clear();
      lastFlags.clear();
    }

    @Override
    public void handleStep(StepInterpolator interpolator, boolean isLast) {
      previousTimes.add(interpolator.getPreviousTime());
      currentTimes.add(interpolator.getCurrentTime());
      lastFlags.add(isLast);
    }

    double stepSize(int index) {
      return currentTimes.get(index) - previousTimes.get(index);
    }
  }
}
