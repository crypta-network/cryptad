package org.spaceroots.mantissa.ode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClassicalRungeKuttaIntegratorTest {

  private static final double EPS = 1.0e-5;

  private RecordingStepHandler handler;

  @BeforeEach
  void setUp() {
    handler = new RecordingStepHandler();
  }

  @Test
  void getName_whenCalled_returnsClassicalIdentifier() {
    ClassicalRungeKuttaIntegrator integrator = new ClassicalRungeKuttaIntegrator(0.1);

    assertEquals("classical Runge-Kutta", integrator.getName());
  }

  @Test
  void integrate_withExponentialGrowth_matchesAnalyticSolutionAndStepSizes()
      throws DerivativeException, IntegratorException {

    ClassicalRungeKuttaIntegrator integrator = new ClassicalRungeKuttaIntegrator(0.1);
    integrator.setStepHandler(handler);

    double[] state = new double[] {1.0};
    integrator.integrate(new ExponentialGrowthEquation(), 0.0, state, 1.0, state);

    assertEquals(Math.E, state[0], EPS);
    assertEquals(10, handler.currentTimes.size());
    handler.currentTimes.forEach(t -> assertTrue(t >= 0.0 && t <= 1.0));
    handler.previousTimes.forEach(t -> assertTrue(t >= -EPS && t < 1.0));
    for (int i = 0; i < handler.currentTimes.size(); i++) {
      double step = handler.currentTimes.get(i) - handler.previousTimes.get(i);
      assertEquals(0.1, step, EPS);
    }
    assertTrue(handler.lastFlags.getLast());
  }

  @Test
  void integrate_backwardDirection_decreasesSolutionConsistently()
      throws DerivativeException, IntegratorException {

    ClassicalRungeKuttaIntegrator integrator = new ClassicalRungeKuttaIntegrator(0.5);
    integrator.setStepHandler(handler);

    double[] state = new double[] {4.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 2.0, state, 0.0, state);

    assertEquals(2.0, state[0], EPS);
    assertTrue(handler.currentTimes.stream().allMatch(t -> t <= 2.0 + EPS));
    assertTrue(handler.currentTimes.getFirst() > handler.currentTimes.getLast());
  }

  @Test
  void integrate_withSwitchingFunction_stopsAtEventTime()
      throws DerivativeException, IntegratorException {

    ClassicalRungeKuttaIntegrator integrator = new ClassicalRungeKuttaIntegrator(0.3);
    integrator.setStepHandler(handler);

    RecordingSwitchingFunction switchingFunction = new RecordingSwitchingFunction();
    integrator.addSwitchingFunction(switchingFunction, 0.25, 1.0e-9);

    double[] state = new double[] {0.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 1.0, state);

    assertEquals(0.5, switchingFunction.eventTime, EPS);
    assertTrue(handler.currentTimes.stream().anyMatch(t -> Math.abs(t - 0.5) < EPS));
    assertTrue(handler.lastFlags.getLast());
  }

  @Test
  void integrate_whenHandlerRequiresDenseOutput_usesRungeKuttaInterpolator()
      throws DerivativeException, IntegratorException {

    InterpolatorCapturingHandler capturingHandler = new InterpolatorCapturingHandler();
    ClassicalRungeKuttaIntegrator integrator = new ClassicalRungeKuttaIntegrator(0.2);
    integrator.setStepHandler(capturingHandler);

    double[] state = new double[] {0.0};
    integrator.integrate(new ConstantEquation(1, 0.0), 0.0, state, 0.4, state);

    assertTrue(capturingHandler.usedRungeKuttaInterpolator);
    assertFalse(capturingHandler.usedDummyInterpolator);
  }

  @Test
  void integrate_withTooSmallInterval_throwsIntegratorException() {
    ClassicalRungeKuttaIntegrator integrator = new ClassicalRungeKuttaIntegrator(0.1);
    double[] state = new double[] {1.0};

    assertThrows(
        IntegratorException.class,
        () -> integrator.integrate(new ConstantEquation(1, 0.0), 1.0, state, 1.0 + 1.0e-16, state));
  }

  @Test
  void integrate_withDimensionMismatch_throwsIntegratorException() {
    ClassicalRungeKuttaIntegrator integrator = new ClassicalRungeKuttaIntegrator(0.1);

    assertThrows(
        IntegratorException.class,
        () ->
            integrator.integrate(
                new ConstantEquation(2, 1.0), 0.0, new double[] {0.0}, 1.0, new double[] {0.0}));
  }

  private static final class ExponentialGrowthEquation implements FirstOrderDifferentialEquations {

    @Override
    public int getDimension() {
      return 1;
    }

    @Override
    public void computeDerivatives(double t, double[] y, double[] yDot) {
      yDot[0] = y[0];
    }
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
  }

  private static final class InterpolatorCapturingHandler implements StepHandler {

    private boolean usedRungeKuttaInterpolator;
    private boolean usedDummyInterpolator;

    @Override
    public boolean requiresDenseOutput() {
      return true;
    }

    @Override
    public void reset() {
      usedRungeKuttaInterpolator = false;
      usedDummyInterpolator = false;
    }

    @Override
    public void handleStep(StepInterpolator interpolator, boolean isLast) {
      usedRungeKuttaInterpolator |= interpolator instanceof RungeKuttaStepInterpolator;
      usedDummyInterpolator |= interpolator instanceof DummyStepInterpolator;
    }
  }

  private static final class RecordingSwitchingFunction implements SwitchingFunction {

    private double eventTime = Double.NaN;

    @Override
    public double g(double t, double[] y) {
      return t - 0.5;
    }

    @Override
    public int eventOccurred(double t, double[] y) {
      eventTime = t;
      return STOP;
    }

    @Override
    public void resetState(double t, double[] y) {
      // No-op
    }
  }
}
