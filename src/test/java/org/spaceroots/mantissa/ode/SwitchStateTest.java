package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.Externalizable;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.roots.ConvergenceChecker;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SwitchStateTest {

  private static final double CONVERGENCE = 1.0e-4;

  @Mock private SwitchingFunction function;

  @Test
  void evaluateStep_whenSignChange_detectsPendingEventAndRootTime() {
    when(function.g(anyDouble(), any(double[].class)))
        .thenAnswer(invocation -> (double) invocation.getArgument(0) - 1.0);

    SwitchState state = new SwitchState(function, 10.0, CONVERGENCE);
    state.reinitializeBegin(0.0, new double[] {0.0});

    boolean rejected = state.evaluateStep(new LinearInterpolator(0.0, 2.0));

    assertTrue(rejected);
    assertEquals(1.0, state.getEventTime(), 1.0e-6);
  }

  @Test
  void evaluateStep_whenNoSignChange_returnsFalseAndClearsPendingEvent() {
    when(function.g(anyDouble(), any(double[].class))).thenReturn(5.0);

    SwitchState state = new SwitchState(function, 10.0, CONVERGENCE);
    state.reinitializeBegin(0.0, new double[] {0.0});

    boolean rejected = state.evaluateStep(new LinearInterpolator(0.0, 2.0));

    assertFalse(rejected);
    assertTrue(Double.isNaN(state.getEventTime()));
  }

  @Test
  void stepAccepted_whenPendingEvent_setsStopAction() {
    when(function.g(anyDouble(), any(double[].class)))
        .thenAnswer(invocation -> (double) invocation.getArgument(0) - 1.0);
    doReturn(SwitchingFunction.STOP).when(function).eventOccurred(anyDouble(), any(double[].class));
    SwitchState state = new SwitchState(function, 10.0, CONVERGENCE);
    state.reinitializeBegin(0.0, new double[] {0.0});
    state.evaluateStep(new LinearInterpolator(0.0, 2.0));

    double eventTime = state.getEventTime();
    state.stepAccepted(eventTime, new double[] {eventTime});

    assertTrue(state.stop());
  }

  @Test
  void reset_whenResetStateRequested_invokesResetStateAndClearsPending() {
    when(function.g(anyDouble(), any(double[].class)))
        .thenAnswer(invocation -> (double) invocation.getArgument(0) - 1.0);
    doReturn(SwitchingFunction.RESET_STATE)
        .when(function)
        .eventOccurred(anyDouble(), any(double[].class));

    SwitchState state = new SwitchState(function, 10.0, CONVERGENCE);
    state.reinitializeBegin(0.0, new double[] {0.0});
    state.evaluateStep(new LinearInterpolator(0.0, 2.0));
    double eventTime = state.getEventTime();
    double[] stateVector = new double[] {eventTime};
    state.stepAccepted(eventTime, stateVector);

    boolean requiresReset = state.reset(eventTime, stateVector);

    assertTrue(requiresReset);
    verify(function).resetState(eventTime, stateVector);
    assertTrue(Double.isNaN(state.getEventTime()));
  }

  @Test
  void reset_whenNoPendingEvent_returnsFalseAndSkipsResetState() {
    when(function.g(anyDouble(), any(double[].class))).thenReturn(1.0);
    SwitchState state = new SwitchState(function, 10.0, CONVERGENCE);
    state.reinitializeBegin(0.0, new double[] {0.0});

    boolean requiresReset = state.reset(0.5, new double[] {0.5});

    assertFalse(requiresReset);
    verify(function, never()).resetState(anyDouble(), any(double[].class));
  }

  @Test
  void evaluateStep_whenPendingEventAtStepEnd_acceptsStepInsteadOfRejecting() {
    when(function.g(anyDouble(), any(double[].class)))
        .thenAnswer(invocation -> (double) invocation.getArgument(0) - 1.0);
    SwitchState state = new SwitchState(function, 10.0, 1.0e-3);
    state.reinitializeBegin(0.0, new double[] {0.0});

    state.evaluateStep(new LinearInterpolator(0.0, 2.0));
    double pendingTime = state.getEventTime();

    boolean rejectedSecond = state.evaluateStep(new LinearInterpolator(0.0, pendingTime));

    assertFalse(rejectedSecond);
    assertEquals(pendingTime, state.getEventTime(), 1.0e-3);
  }

  @Test
  void valueAt_whenInterpolatorThrowsDerivativeException_wrapsInFunctionException() {
    when(function.g(anyDouble(), any(double[].class)))
        .thenAnswer(invocation -> (double) invocation.getArgument(0));
    LinearInterpolator interpolator = new LinearInterpolator(0.0, 1.0);

    SwitchState state = new SwitchState(function, 10.0, CONVERGENCE);
    state.reinitializeBegin(0.0, new double[] {0.0});
    state.evaluateStep(interpolator);
    interpolator.enableThrowOnSet();

    assertThrows(FunctionException.class, () -> state.valueAt(0.5));
  }

  @Test
  void converged_whenIntervalWithinThreshold_returnsSideWithSmallerMagnitude() {
    SwitchState state = new SwitchState(function, 10.0, 0.2);

    int resultLowMagnitude = state.converged(0.0, 0.1, 0.1, 0.5);
    int resultHighMagnitude = state.converged(0.0, 0.5, 0.1, 0.1);
    int resultNone = state.converged(0.0, 0.1, 0.5, 0.2);

    assertEquals(ConvergenceChecker.LOW, resultLowMagnitude);
    assertEquals(ConvergenceChecker.HIGH, resultHighMagnitude);
    assertEquals(ConvergenceChecker.NONE, resultNone);
  }

  /** Minimal deterministic interpolator for tests. */
  private static final class LinearInterpolator implements StepInterpolator, Externalizable {

    private final double previousTime;
    private final double currentTime;
    private double interpolatedTime;
    private boolean throwOnSet;

    public LinearInterpolator() {
      this(0.0, 0.0);
    }

    LinearInterpolator(double previousTime, double currentTime) {
      this.previousTime = previousTime;
      this.currentTime = currentTime;
      this.interpolatedTime = currentTime;
    }

    void enableThrowOnSet() {
      this.throwOnSet = true;
    }

    @Override
    public double getPreviousTime() {
      return previousTime;
    }

    @Override
    public double getCurrentTime() {
      return currentTime;
    }

    @Override
    public double getInterpolatedTime() {
      return interpolatedTime;
    }

    @Override
    public void setInterpolatedTime(double time) throws DerivativeException {
      if (throwOnSet) {
        throw new DerivativeException(new RuntimeException("forced"));
      }
      this.interpolatedTime = time;
    }

    @Override
    public double[] getInterpolatedState() {
      return new double[] {interpolatedTime};
    }

    @Override
    public boolean isForward() {
      return currentTime >= previousTime;
    }

    @Override
    public void writeExternal(ObjectOutput out) {
      // not needed for tests
    }

    @Override
    public void readExternal(ObjectInput in) {
      // not needed for tests
    }
  }
}
