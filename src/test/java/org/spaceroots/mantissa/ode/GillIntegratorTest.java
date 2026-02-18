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
class GillIntegratorTest {

  private static final double EPS = 1.0e-9;

  private RecordingStepHandler handler;

  @BeforeEach
  void setUp() {
    handler = new RecordingStepHandler();
  }

  @Test
  void getName_whenCalled_returnsGillIdentifier() {
    GillIntegrator integrator = new GillIntegrator(0.1);

    assertEquals("Gill", integrator.getName());
  }

  @Test
  void integrate_withExponentialGrowth_matchesAnalyticSolutionAndStepSizes()
      throws DerivativeException, IntegratorException {

    GillIntegrator integrator = new GillIntegrator(0.05);
    integrator.setStepHandler(handler);

    double[] state = new double[] {1.0};

    integrator.integrate(new ExponentialGrowthEquation(), 0.0, state, 1.0, state);

    assertEquals(Math.E, state[0], 5.0e-7);
    assertEquals(20, handler.currentTimes.size());
    for (int i = 0; i < handler.currentTimes.size(); i++) {
      double step = handler.currentTimes.get(i) - handler.previousTimes.get(i);
      assertEquals(0.05, step, EPS);
    }
    assertTrue(handler.lastFlags.getLast());
  }

  @Test
  void integrate_backwardDirection_decreasesSolutionConsistently()
      throws DerivativeException, IntegratorException {

    GillIntegrator integrator = new GillIntegrator(0.5);
    integrator.setStepHandler(handler);

    double[] state = new double[] {4.0};

    integrator.integrate(new ConstantEquation(1, 1.0), 2.0, state, 0.0, state);

    assertEquals(2.0, state[0], EPS);
    assertTrue(handler.currentTimes.stream().allMatch(t -> t <= 2.0 + EPS));
    assertTrue(handler.currentTimes.getFirst() > handler.currentTimes.getLast());
  }

  @Test
  void integrate_withSwitchingFunction_stopsAtEventTimeAndUpdatesStepSize()
      throws DerivativeException, IntegratorException {

    List<Double> observedSteps = new ArrayList<>();
    List<Boolean> lastFlags = new ArrayList<>();
    GillIntegrator integrator = new GillIntegrator(0.3);
    integrator.setStepHandler(
        new StepSizeCapturingHandler(
            integrator, observedSteps, lastFlags, /* requireDenseOutput= */ true));

    RecordingSwitchingFunction switchingFunction = new RecordingSwitchingFunction();
    integrator.addSwitchingFunction(switchingFunction, 0.25, 1.0e-9);

    double[] state = new double[] {0.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 1.0, state);

    assertEquals(0.5, switchingFunction.eventTime, EPS);
    assertEquals(4, observedSteps.size());
    assertEquals(1.0 / 3.0, observedSteps.get(0), EPS);
    assertEquals(1.0 / 6.0, observedSteps.get(1), EPS);
    assertEquals(0.25, observedSteps.get(2), EPS);
    assertEquals(0.25, observedSteps.get(3), EPS);
    assertTrue(lastFlags.getLast());
    assertEquals(1.0, state[0], EPS);
  }

  @Test
  void integrate_whenHandlerRequiresDenseOutput_usesGillInterpolatorAndInterpolatesMidpoints()
      throws DerivativeException, IntegratorException {

    InterpolationCheckingHandler capturingHandler = new InterpolationCheckingHandler();
    GillIntegrator integrator = new GillIntegrator(0.5);
    integrator.setStepHandler(capturingHandler);

    double[] state = new double[] {1.0};

    integrator.integrate(new ConstantEquation(1, 2.0), 0.0, state, 1.0, state);

    assertTrue(capturingHandler.usedGillInterpolator);
    assertFalse(capturingHandler.usedDummyInterpolator);
    assertEquals(2, capturingHandler.midpointStates.size());
    assertEquals(1.5, capturingHandler.midpointStates.get(0), EPS);
    assertEquals(2.5, capturingHandler.midpointStates.get(1), EPS);
    assertEquals(3.0, state[0], EPS);
  }

  @Test
  void integrate_whenDenseOutputNotRequired_usesDummyInterpolator()
      throws DerivativeException, IntegratorException {

    InterpolatorTypeRecordingHandler capturingHandler = new InterpolatorTypeRecordingHandler(false);
    GillIntegrator integrator = new GillIntegrator(0.4);
    integrator.setStepHandler(capturingHandler);

    double[] state = new double[] {0.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 0.8, state);

    assertFalse(capturingHandler.usedGillInterpolator);
    assertTrue(capturingHandler.usedDummyInterpolator);
  }

  @Test
  void integrate_afterCompletion_resetsCurrentStepMetadata()
      throws DerivativeException, IntegratorException {

    GillIntegrator integrator = new GillIntegrator(0.2);
    double[] state = new double[] {0.0};

    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 0.4, state);

    assertTrue(Double.isNaN(integrator.getCurrentStepStart()));
    assertTrue(Double.isNaN(integrator.getCurrentStepsize()));
  }

  @Test
  void integrate_withTooSmallInterval_throwsIntegratorException() {
    GillIntegrator integrator = new GillIntegrator(0.1);
    double[] state = new double[] {1.0};

    assertThrows(
        IntegratorException.class,
        () -> integrator.integrate(new ConstantEquation(1, 0.0), 1.0, state, 1.0 + 1.0e-16, state));
  }

  @Test
  void integrate_withDimensionMismatch_throwsIntegratorException() {
    GillIntegrator integrator = new GillIntegrator(0.1);

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

  private static final class InterpolationCheckingHandler implements StepHandler {

    private final List<Double> midpointStates = new ArrayList<>();
    private boolean usedGillInterpolator;
    private boolean usedDummyInterpolator;

    @Override
    public boolean requiresDenseOutput() {
      return true;
    }

    @Override
    public void reset() {
      midpointStates.clear();
      usedGillInterpolator = false;
      usedDummyInterpolator = false;
    }

    @Override
    public void handleStep(StepInterpolator interpolator, boolean isLast) {
      usedGillInterpolator |= interpolator instanceof GillStepInterpolator;
      usedDummyInterpolator |= interpolator instanceof DummyStepInterpolator;

      double midTime = (interpolator.getPreviousTime() + interpolator.getCurrentTime()) / 2.0;
      try {
        interpolator.setInterpolatedTime(midTime);
        midpointStates.add(interpolator.getInterpolatedState()[0]);
      } catch (DerivativeException e) {
        throw new AssertionError("Unexpected derivative exception during interpolation", e);
      }
    }
  }

  private static final class InterpolatorTypeRecordingHandler implements StepHandler {

    private final boolean requireDense;
    private boolean usedGillInterpolator;
    private boolean usedDummyInterpolator;

    InterpolatorTypeRecordingHandler(boolean requireDense) {
      this.requireDense = requireDense;
    }

    @Override
    public boolean requiresDenseOutput() {
      return requireDense;
    }

    @Override
    public void reset() {
      usedGillInterpolator = false;
      usedDummyInterpolator = false;
    }

    @Override
    public void handleStep(StepInterpolator interpolator, boolean isLast) {
      usedGillInterpolator |= interpolator instanceof GillStepInterpolator;
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
      return CONTINUE;
    }

    @Override
    public void resetState(double t, double[] y) {
      // No-op
    }
  }

  private static final class StepSizeCapturingHandler implements StepHandler {

    private final GillIntegrator integrator;
    private final List<Double> stepSizes;
    private final List<Boolean> lastFlags;
    private final boolean requireDense;

    StepSizeCapturingHandler(
        GillIntegrator integrator,
        List<Double> stepSizes,
        List<Boolean> lastFlags,
        boolean requireDenseOutput) {
      this.integrator = integrator;
      this.stepSizes = stepSizes;
      this.lastFlags = lastFlags;
      this.requireDense = requireDenseOutput;
    }

    @Override
    public boolean requiresDenseOutput() {
      return requireDense;
    }

    @Override
    public void reset() {
      stepSizes.clear();
      lastFlags.clear();
    }

    @Override
    public void handleStep(StepInterpolator interpolator, boolean isLast) {
      stepSizes.add(integrator.getCurrentStepsize());
      lastFlags.add(isLast);
    }
  }
}
