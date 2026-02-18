package org.spaceroots.mantissa.ode;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ContinuousOutputModelTest {

  @Test
  void requiresDenseOutput_whenCalled_returnsTrue() {
    ContinuousOutputModel model = new ContinuousOutputModel();

    assertTrue(model.requiresDenseOutput());
  }

  @Test
  void handleStep_whenTwoStepsProvided_tracksInitialFinalAndInterpolates()
      throws DerivativeException {
    ContinuousOutputModel model = new ContinuousOutputModel();

    model.handleStep(step(0.0, 1.0, new double[] {0.0}, new double[] {1.0}, true), false);
    model.handleStep(step(1.0, 2.0, new double[] {1.0}, new double[] {3.0}, true), true);

    assertEquals(0.0, model.getInitialTime());
    assertEquals(2.0, model.getInterpolatedTime());

    model.setInterpolatedTime(1.5);

    assertArrayEquals(new double[] {2.0}, model.getInterpolatedState(), 1.0e-12);
  }

  @Test
  void reset_whenCalled_clearsStoredStepsAndMetadata() throws DerivativeException {
    ContinuousOutputModel model = new ContinuousOutputModel();
    model.handleStep(step(0.0, 1.0, new double[] {0.0}, new double[] {1.0}, true), true);

    model.reset();

    assertTrue(Double.isNaN(model.getInitialTime()));
    assertTrue(Double.isNaN(model.getFinalTime()));

    model.handleStep(step(2.0, 3.0, new double[] {2.0}, new double[] {4.0}, true), true);
    model.setInterpolatedTime(2.5);

    assertEquals(2.0, model.getInitialTime());
    assertArrayEquals(new double[] {3.0}, model.getInterpolatedState(), 1.0e-12);
  }

  @Test
  void append_withValidModel_combinesStepsAndPreservesOrdering() throws DerivativeException {
    ContinuousOutputModel base = new ContinuousOutputModel();
    base.handleStep(step(0.0, 1.0, new double[] {0.0}, new double[] {1.0}, true), true);

    ContinuousOutputModel tail = new ContinuousOutputModel();
    tail.handleStep(step(1.0, 2.0, new double[] {1.0}, new double[] {2.0}, true), true);

    base.append(tail);

    assertEquals(0.0, base.getInitialTime());
    base.setInterpolatedTime(1.5);
    assertArrayEquals(new double[] {1.5}, base.getInterpolatedState(), 1.0e-12);
  }

  @Test
  void append_withDimensionMismatch_throwsIllegalArgumentException() throws DerivativeException {
    ContinuousOutputModel base = new ContinuousOutputModel();
    base.handleStep(step(0.0, 1.0, new double[] {0.0}, new double[] {1.0}, true), true);

    ContinuousOutputModel mismatched = new ContinuousOutputModel();
    mismatched.handleStep(
        step(1.0, 2.0, new double[] {1.0, 2.0}, new double[] {3.0, 4.0}, true), true);

    assertThrows(IllegalArgumentException.class, () -> base.append(mismatched));
  }

  @Test
  void append_withDirectionMismatch_throwsIllegalArgumentException() throws DerivativeException {
    ContinuousOutputModel base = new ContinuousOutputModel();
    base.handleStep(step(0.0, 1.0, new double[] {0.0}, new double[] {1.0}, true), true);

    ContinuousOutputModel reverse = new ContinuousOutputModel();
    reverse.handleStep(step(1.0, 0.0, new double[] {1.0}, new double[] {0.0}, false), true);

    assertThrows(IllegalArgumentException.class, () -> base.append(reverse));
  }

  @Test
  void append_withGapTooLarge_throwsIllegalArgumentException() throws DerivativeException {
    ContinuousOutputModel base = new ContinuousOutputModel();
    base.handleStep(step(0.0, 1.0, new double[] {0.0}, new double[] {1.0}, true), true);

    ContinuousOutputModel gapped = new ContinuousOutputModel();
    gapped.handleStep(step(3.0, 4.0, new double[] {3.0}, new double[] {4.0}, true), true);

    assertThrows(IllegalArgumentException.class, () -> base.append(gapped));
  }

  @Test
  void setInterpolatedTime_whenOutsideBounds_usesEdgeStep() throws DerivativeException {
    ContinuousOutputModel model = new ContinuousOutputModel();
    model.handleStep(step(0.0, 1.0, new double[] {0.0}, new double[] {1.0}, true), false);
    model.handleStep(step(1.0, 3.0, new double[] {1.0}, new double[] {3.0}, true), true);

    model.setInterpolatedTime(-0.5);
    assertArrayEquals(new double[] {-0.5}, model.getInterpolatedState(), 1.0e-12);

    model.setInterpolatedTime(5.0);
    assertArrayEquals(new double[] {5.0}, model.getInterpolatedState(), 1.0e-12);
  }

  @Test
  void setInterpolatedTime_whenDenseOutputSpansManySteps_findsCorrectBracket()
      throws DerivativeException {
    ContinuousOutputModel model = new ContinuousOutputModel();
    for (int i = 0; i < 7; i++) {
      double end = i + 1.0;
      model.handleStep(
          step((double) i, end, new double[] {(double) i}, new double[] {end}, true), i == 6);
    }

    model.setInterpolatedTime(3.4);

    assertArrayEquals(new double[] {3.4}, model.getInterpolatedState(), 1.0e-12);
  }

  @Test
  void setInterpolatedTime_whenInterpolatorThrows_wrapsInIllegalStateException()
      throws DerivativeException {
    ContinuousOutputModel model = new ContinuousOutputModel();
    model.handleStep(new ThrowingStepInterpolator(0.0, 1.0, true), true);

    IllegalStateException exception =
        assertThrows(IllegalStateException.class, () -> model.setInterpolatedTime(0.5));
    assertInstanceOf(DerivativeException.class, exception.getCause());
  }

  private static StepInterpolator step(
      double previousTime,
      double currentTime,
      double[] startState,
      double[] endState,
      boolean forward) {
    return new SimpleStepInterpolator(previousTime, currentTime, startState, endState, forward);
  }

  private static class SimpleStepInterpolator extends AbstractStepInterpolator
      implements StepInterpolator {

    private final double[] startState;

    /** Public no-arg constructor required by Externalizable; initializes to a benign 1D state. */
    public SimpleStepInterpolator() {
      super(new double[] {0.0}, true);
      this.startState = new double[] {0.0};
      this.previousTime = 0.0;
      this.currentTime = 0.0;
      this.h = 0.0;
      this.interpolatedTime = 0.0;
      System.arraycopy(
          this.startState, 0, this.interpolatedState, 0, this.interpolatedState.length);
    }

    SimpleStepInterpolator(
        double previousTime,
        double currentTime,
        double[] startState,
        double[] endState,
        boolean forward) {
      super(endState.clone(), forward);
      this.startState = startState.clone();
      this.previousTime = previousTime;
      this.currentTime = currentTime;
      this.h = currentTime - previousTime;
      this.interpolatedTime = currentTime;
      System.arraycopy(endState, 0, this.interpolatedState, 0, endState.length);
    }

    protected SimpleStepInterpolator(SimpleStepInterpolator that) {
      super(that);
      this.startState = that.startState.clone();
    }

    @Override
    public AbstractStepInterpolator copy() {
      return new SimpleStepInterpolator(this);
    }

    @Override
    protected void computeInterpolatedState(double theta, double oneMinusThetaH)
        throws DerivativeException {
      for (int i = 0; i < interpolatedState.length; i++) {
        double delta = currentState[i] - startState[i];
        interpolatedState[i] = startState[i] + theta * delta;
      }
    }

    @Override
    public void writeExternal(java.io.ObjectOutput out) {
      // no-op: serialization not needed for test double
    }

    @Override
    public void readExternal(java.io.ObjectInput in) {
      // no-op: serialization not needed for test double
    }
  }

  private static final class ThrowingStepInterpolator extends SimpleStepInterpolator {

    /** Public no-arg constructor required by Externalizable. */
    public ThrowingStepInterpolator() {
      super();
    }

    ThrowingStepInterpolator(double previousTime, double currentTime, boolean forward) {
      super(
          previousTime,
          currentTime,
          new double[] {previousTime},
          new double[] {currentTime},
          forward);
    }

    private ThrowingStepInterpolator(ThrowingStepInterpolator that) {
      super(that);
    }

    @Override
    public AbstractStepInterpolator copy() {
      return new ThrowingStepInterpolator(this);
    }

    @Override
    protected void computeInterpolatedState(double theta, double oneMinusThetaH)
        throws DerivativeException {
      throw new DerivativeException(new RuntimeException("forced failure"));
    }
  }
}
