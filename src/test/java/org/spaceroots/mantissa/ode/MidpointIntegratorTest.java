package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class MidpointIntegratorTest {

  private static final double EPS = 1.0e-12;

  private RecordingStepHandler handler;

  @BeforeEach
  void setUp() {
    handler = new RecordingStepHandler();
  }

  @Test
  void getName_whenCalled_returnsMidpointIdentifier() {
    MidpointIntegrator integrator = new MidpointIntegrator(0.2);

    assertEquals("midpoint", integrator.getName());
  }

  @Test
  void integrate_withExponentialGrowth_matchesMidpointUpdateAndStepSizes()
      throws DerivativeException, IntegratorException {

    double step = 0.1;
    MidpointIntegrator integrator = new MidpointIntegrator(step);
    integrator.setStepHandler(handler);

    double[] state = new double[] {1.0};

    integrator.integrate(new ExponentialGrowthEquation(), 0.0, state, 1.0, state);

    double expected = Math.pow(1.0 + step + (step * step) / 2.0, 10);
    assertEquals(expected, state[0], EPS);
    assertEquals(10, handler.currentTimes.size());
    for (int i = 0; i < handler.currentTimes.size(); i++) {
      double stepLength = handler.currentTimes.get(i) - handler.previousTimes.get(i);
      assertEquals(step, stepLength, EPS);
    }
    assertTrue(handler.lastFlags.getLast());
  }

  @Test
  void integrate_backwardDirection_decreasesSolutionConsistently()
      throws DerivativeException, IntegratorException {

    MidpointIntegrator integrator = new MidpointIntegrator(0.5);
    integrator.setStepHandler(handler);

    double[] state = new double[] {4.0};

    integrator.integrate(new ConstantEquation(1, 1.0), 2.0, state, 0.0, state);

    assertEquals(2.0, state[0], 1.0e-10);
    assertTrue(handler.currentTimes.stream().allMatch(t -> t <= 2.0 + EPS));
    assertTrue(handler.currentTimes.getFirst() > handler.currentTimes.getLast());
  }

  @Test
  void integrate_withSwitchingFunction_stopsAtEventTimeAndAdaptsStepSize()
      throws DerivativeException, IntegratorException {

    List<Double> observedSteps = new ArrayList<>();
    List<Boolean> lastFlags = new ArrayList<>();
    MidpointIntegrator integrator = new MidpointIntegrator(0.3);
    integrator.setStepHandler(
        new StepSizeCapturingHandler(
            integrator, observedSteps, lastFlags, /* requireDense= */ true));

    RecordingSwitchingFunction switchingFunction = new RecordingSwitchingFunction();
    integrator.addSwitchingFunction(switchingFunction, 0.25, 1.0e-9);

    double[] state = new double[] {0.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 1.0, state);

    assertEquals(0.5, switchingFunction.eventTime, EPS);
    List<Double> expectedSteps = List.of(1.0 / 3.0, 1.0 / 6.0, 0.25, 0.25);
    assertEquals(expectedSteps.size(), observedSteps.size());
    for (int i = 0; i < expectedSteps.size(); i++) {
      assertEquals(expectedSteps.get(i), observedSteps.get(i), EPS);
    }
    assertTrue(lastFlags.getLast());
    assertEquals(1.0, state[0], EPS);
  }

  @Test
  void integrate_whenHandlerRequiresDenseOutput_usesMidpointInterpolatorAndInterpolatesMidpoints()
      throws DerivativeException, IntegratorException {

    InterpolationCheckingHandler capturingHandler = new InterpolationCheckingHandler();
    MidpointIntegrator integrator = new MidpointIntegrator(0.5);
    integrator.setStepHandler(capturingHandler);

    double[] state = new double[] {1.0};

    integrator.integrate(new ConstantEquation(1, 2.0), 0.0, state, 1.0, state);

    assertTrue(capturingHandler.usedMidpointInterpolator);
    assertFalse(capturingHandler.usedDummyInterpolator);
    assertEquals(Arrays.asList(1.5, 2.5), capturingHandler.midpointStates);
    assertEquals(3.0, state[0], EPS);
  }

  @Test
  void integrate_whenDenseOutputNotRequired_usesDummyInterpolator()
      throws DerivativeException, IntegratorException {

    InterpolatorTypeRecordingHandler capturingHandler = new InterpolatorTypeRecordingHandler(false);
    MidpointIntegrator integrator = new MidpointIntegrator(0.4);
    integrator.setStepHandler(capturingHandler);

    double[] state = new double[] {0.0};
    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 0.8, state);

    assertFalse(capturingHandler.usedMidpointInterpolator);
    assertTrue(capturingHandler.usedDummyInterpolator);
  }

  @Test
  void integrate_afterCompletion_resetsCurrentStepMetadata()
      throws DerivativeException, IntegratorException {

    MidpointIntegrator integrator = new MidpointIntegrator(0.2);
    double[] state = new double[] {0.0};

    integrator.integrate(new ConstantEquation(1, 1.0), 0.0, state, 0.4, state);

    assertTrue(Double.isNaN(integrator.getCurrentStepStart()));
    assertTrue(Double.isNaN(integrator.getCurrentStepsize()));
  }

  @Test
  void integrate_withTooSmallInterval_throwsIntegratorException() {
    MidpointIntegrator integrator = new MidpointIntegrator(0.1);
    double[] state = new double[] {1.0};

    assertThrows(
        IntegratorException.class,
        () -> integrator.integrate(new ConstantEquation(1, 0.0), 1.0, state, 1.0 + 1.0e-16, state));
  }

  @Test
  void integrate_withDimensionMismatch_throwsIntegratorException() {
    MidpointIntegrator integrator = new MidpointIntegrator(0.1);

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
    private boolean usedMidpointInterpolator;
    private boolean usedDummyInterpolator;

    @Override
    public boolean requiresDenseOutput() {
      return true;
    }

    @Override
    public void reset() {
      midpointStates.clear();
      usedMidpointInterpolator = false;
      usedDummyInterpolator = false;
    }

    @Override
    public void handleStep(StepInterpolator interpolator, boolean isLast) {
      usedMidpointInterpolator |= interpolator instanceof MidpointStepInterpolator;
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
    private boolean usedMidpointInterpolator;
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
      usedMidpointInterpolator = false;
      usedDummyInterpolator = false;
    }

    @Override
    public void handleStep(StepInterpolator interpolator, boolean isLast) {
      usedMidpointInterpolator |= interpolator instanceof MidpointStepInterpolator;
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

    private final MidpointIntegrator integrator;
    private final List<Double> stepSizes;
    private final List<Boolean> lastFlags;
    private final boolean requireDense;

    StepSizeCapturingHandler(
        MidpointIntegrator integrator,
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
