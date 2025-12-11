package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ObjectInput;
import java.io.ObjectOutput;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SwitchingFunctionsHandlerTest {

  @Test
  void isEmpty_whenNoFunctions_returnsTrue() {
    SwitchingFunctionsHandler handler = new SwitchingFunctionsHandler();

    assertTrue(handler.isEmpty());
  }

  @Test
  void add_whenFunctionAdded_handlerNotEmpty() {
    SwitchingFunctionsHandler handler = new SwitchingFunctionsHandler();
    handler.add(mockCrossingFunction(1.0, SwitchingFunction.CONTINUE), 5.0, 1.0e-6);

    assertFalse(handler.isEmpty());
  }

  @Test
  void evaluateStep_whenHandlerEmpty_returnsFalseAndKeepsEventTimeNaN() {
    SwitchingFunctionsHandler handler = new SwitchingFunctionsHandler();
    StepInterpolator interpolator = new LinearStepInterpolator(0.0, 1.0, true);

    boolean hasEvent = handler.evaluateStep(interpolator);

    assertFalse(hasEvent);
    assertTrue(Double.isNaN(handler.getEventTime()));
  }

  @Test
  void evaluateStep_whenSingleFunctionCrossesZero_detectsEventAndStoresEarliestTime() {
    SwitchingFunctionsHandler handler = new SwitchingFunctionsHandler();
    handler.add(mockCrossingFunction(1.0, SwitchingFunction.CONTINUE), 10.0, 1.0e-6);
    StepInterpolator interpolator = new LinearStepInterpolator(0.0, 2.0, true);

    boolean hasEvent = handler.evaluateStep(interpolator);

    assertTrue(hasEvent);
    assertEquals(1.0, handler.getEventTime(), 1.0e-4);
  }

  @Test
  void evaluateStep_whenMultipleFunctionsForward_selectsEarliestEventTime() {
    SwitchingFunctionsHandler handler = new SwitchingFunctionsHandler();
    handler.add(mockCrossingFunction(0.5, SwitchingFunction.CONTINUE), 10.0, 1.0e-6);
    handler.add(mockCrossingFunction(1.5, SwitchingFunction.CONTINUE), 10.0, 1.0e-6);
    StepInterpolator interpolator = new LinearStepInterpolator(0.0, 2.0, true);

    boolean hasEvent = handler.evaluateStep(interpolator);

    assertTrue(hasEvent);
    assertEquals(0.5, handler.getEventTime(), 1.0e-4);
  }

  @Test
  void evaluateStep_whenMultipleFunctionsBackward_selectsLatestEventInDirection() {
    SwitchingFunctionsHandler handler = new SwitchingFunctionsHandler();
    handler.add(mockCrossingFunction(0.5, SwitchingFunction.CONTINUE), 10.0, 1.0e-6);
    handler.add(mockCrossingFunction(1.5, SwitchingFunction.CONTINUE), 10.0, 1.0e-6);
    StepInterpolator interpolator = new LinearStepInterpolator(2.0, 0.0, false);

    boolean hasEvent = handler.evaluateStep(interpolator);

    assertTrue(hasEvent);
    assertEquals(1.5, handler.getEventTime(), 1.0e-4);
  }

  @Test
  void stepAccepted_whenEventRequestsStop_reportsStopOnHandler() {
    SwitchingFunctionsHandler handler = new SwitchingFunctionsHandler();
    SwitchingFunction function = mockCrossingFunction(0.5, SwitchingFunction.STOP);
    handler.add(function, 10.0, 1.0e-6);
    StepInterpolator interpolator = new LinearStepInterpolator(0.0, 1.0, true);

    handler.evaluateStep(interpolator);
    double eventTime = handler.getEventTime();
    double[] stateAtEvent = new double[] {eventTime};

    handler.stepAccepted(eventTime, stateAtEvent);

    assertTrue(handler.stop());
    verify(function).eventOccurred(eq(eventTime), any(double[].class));
  }

  @Test
  void reset_whenEventRequestsStateReset_invokesResetStateAndSignalsDerivativeReset() {
    SwitchingFunctionsHandler handler = new SwitchingFunctionsHandler();
    SwitchingFunction function = mockCrossingFunction(0.5, SwitchingFunction.RESET_STATE);
    handler.add(function, 10.0, 1.0e-6);
    StepInterpolator interpolator = new LinearStepInterpolator(0.0, 1.0, true);

    handler.evaluateStep(interpolator);
    double eventTime = handler.getEventTime();
    double[] stateAtEvent = new double[] {eventTime};

    handler.stepAccepted(eventTime, stateAtEvent);
    boolean resetDerivatives = handler.reset(eventTime, stateAtEvent);

    assertTrue(resetDerivatives);
    verify(function, times(1)).resetState(eventTime, stateAtEvent);

    assertFalse(handler.reset(eventTime, stateAtEvent));
  }

  private SwitchingFunction mockCrossingFunction(double crossingTime, int eventAction) {
    SwitchingFunction function = mock(SwitchingFunction.class);
    lenient()
        .when(function.g(anyDouble(), any(double[].class)))
        .thenAnswer(invocation -> ((double) invocation.getArgument(0)) - crossingTime);
    lenient()
        .when(function.eventOccurred(anyDouble(), any(double[].class)))
        .thenReturn(eventAction);
    return function;
  }

  private static final class LinearStepInterpolator implements StepInterpolator {

    private final double previousTime;
    private final double currentTime;
    private final boolean forward;
    private double interpolatedTime;

    public LinearStepInterpolator() {
      this(0.0, 0.0, true);
    }

    LinearStepInterpolator(double previousTime, double currentTime, boolean forward) {
      this.previousTime = previousTime;
      this.currentTime = currentTime;
      this.forward = forward;
      this.interpolatedTime = currentTime;
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
    public void setInterpolatedTime(double time) {
      this.interpolatedTime = time;
    }

    @Override
    public double[] getInterpolatedState() {
      return new double[] {interpolatedTime};
    }

    @Override
    public boolean isForward() {
      return forward;
    }

    @Override
    public void writeExternal(ObjectOutput out) {
      // Not used in tests
    }

    @Override
    public void readExternal(ObjectInput in) {
      // Not used in tests
    }
  }
}
