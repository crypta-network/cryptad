package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.Mockito.lenient;

import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class StepNormalizerTest {

  @Mock private FixedStepHandler handler;

  private List<StepCall> capturedSteps;

  @BeforeEach
  void setUpHandlerCapture() {
    capturedSteps = new ArrayList<>();
    lenient()
        .doAnswer(
            invocation -> {
              double time = invocation.getArgument(0);
              double[] state = invocation.getArgument(1);
              boolean isLast = invocation.getArgument(2);
              capturedSteps.add(new StepCall(time, state.clone(), isLast));
              return null;
            })
        .when(handler)
        .handleStep(anyDouble(), any(double[].class), anyBoolean());
  }

  @Test
  void requiresDenseOutput_whenQueried_alwaysTrue() {
    StepNormalizer normalizer = new StepNormalizer(0.5, handler);

    assertTrue(normalizer.requiresDenseOutput());
  }

  @Test
  void handleStep_whenForwardIntegration_emitsNormalizedStepsAndMarksLast()
      throws DerivativeException {
    StepNormalizer normalizer = new StepNormalizer(0.5, handler);
    StubStepInterpolator interpolator = new StubStepInterpolator(0.0, 2.0);

    normalizer.handleStep(interpolator, true);

    double[] expectedTimes = {0.0, 0.5, 1.0, 1.5, 2.0};
    assertEquals(expectedTimes.length, capturedSteps.size());
    for (int i = 0; i < expectedTimes.length; i++) {
      StepCall call = capturedSteps.get(i);
      assertEquals(expectedTimes[i], call.time);
      assertEquals(expectedTimes[i], call.state[0]);
      assertEquals(expectedTimes[i] * 2.0, call.state[1]);
      assertEquals(i == expectedTimes.length - 1, call.isLast);
    }
  }

  @Test
  void handleStep_whenBackwardIntegration_flipsDirectionAndEmitsDescendingTimes()
      throws DerivativeException {
    StepNormalizer normalizer = new StepNormalizer(0.5, handler);
    StubStepInterpolator interpolator = new StubStepInterpolator(2.0, 0.0);

    normalizer.handleStep(interpolator, true);

    double[] expectedTimes = {2.0, 1.5, 1.0, 0.5};
    assertEquals(expectedTimes.length, capturedSteps.size());
    for (int i = 0; i < expectedTimes.length; i++) {
      StepCall call = capturedSteps.get(i);
      assertEquals(expectedTimes[i], call.time);
      assertEquals(expectedTimes[i], call.state[0]);
      assertEquals(expectedTimes[i] * 2.0, call.state[1]);
      assertEquals(i == expectedTimes.length - 1, call.isLast);
    }
  }

  @Test
  void handleStep_whenStepsAccumulateAcrossCalls_emitsOnlyWhenGridCrossed()
      throws DerivativeException {
    StepNormalizer normalizer = new StepNormalizer(1.0, handler);

    normalizer.handleStep(new StubStepInterpolator(0.0, 0.4), false);
    assertTrue(capturedSteps.isEmpty(), "No output before first full step");

    normalizer.handleStep(new StubStepInterpolator(0.4, 1.2), false);
    assertEquals(1, capturedSteps.size());
    assertEquals(0.0, capturedSteps.getFirst().time);
    assertEquals(0.0, capturedSteps.getFirst().state[0]);
    assertEquals(0.0, capturedSteps.getFirst().state[1]);
    assertFalse(capturedSteps.getFirst().isLast);

    normalizer.handleStep(new StubStepInterpolator(1.2, 2.0), true);

    double[] expectedTimes = {0.0, 1.0, 2.0};
    assertEquals(expectedTimes.length, capturedSteps.size());
    for (int i = 1; i < expectedTimes.length; i++) {
      StepCall call = capturedSteps.get(i);
      assertEquals(expectedTimes[i], call.time);
      assertEquals(expectedTimes[i], call.state[0]);
      assertEquals(expectedTimes[i] * 2.0, call.state[1]);
      assertEquals(i == expectedTimes.length - 1, call.isLast);
    }
  }

  @Test
  void reset_whenCalled_betweenRuns_resetsInternalState() throws DerivativeException {
    StepNormalizer normalizer = new StepNormalizer(0.5, handler);

    normalizer.handleStep(new StubStepInterpolator(0.0, 1.0), true);
    capturedSteps.clear();

    normalizer.reset();
    normalizer.handleStep(new StubStepInterpolator(5.0, 6.0), true);

    double[] expectedTimes = {5.0, 5.5, 6.0};
    assertEquals(expectedTimes.length, capturedSteps.size());
    for (int i = 0; i < expectedTimes.length; i++) {
      StepCall call = capturedSteps.get(i);
      assertEquals(expectedTimes[i], call.time);
      assertEquals(expectedTimes[i], call.state[0]);
      assertEquals(expectedTimes[i] * 2.0, call.state[1]);
      assertEquals(i == expectedTimes.length - 1, call.isLast);
    }
  }

  private static final class StepCall {
    private final double time;
    private final double[] state;
    private final boolean isLast;

    private StepCall(double time, double[] state, boolean isLast) {
      this.time = time;
      this.state = state;
      this.isLast = isLast;
    }
  }

  private static final class StubStepInterpolator implements StepInterpolator {

    private final double previousTime;
    private final double currentTime;
    private final boolean forward;
    private double interpolatedTime;
    private final double[] stateBuffer;

    public StubStepInterpolator() {
      this(0.0, 0.0);
    }

    private StubStepInterpolator(double previousTime, double currentTime) {
      this.previousTime = previousTime;
      this.currentTime = currentTime;
      this.forward = currentTime >= previousTime;
      this.interpolatedTime = currentTime;
      this.stateBuffer = new double[2];
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
      interpolatedTime = time;
      stateBuffer[0] = time;
      stateBuffer[1] = time * 2.0;
    }

    @Override
    public double[] getInterpolatedState() {
      return stateBuffer;
    }

    @Override
    public boolean isForward() {
      return forward;
    }

    @Override
    public void writeExternal(ObjectOutput out) {
      // not used in tests
    }

    @Override
    public void readExternal(ObjectInput in) {
      // not used in tests
    }
  }
}
