package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class DummyStepInterpolatorTest {

  @Test
  void setInterpolatedTime_whenStateMutated_expectCopiesLatestState() throws DerivativeException {
    double[] state = {1.0, 2.0};
    DummyStepInterpolator interpolator = new DummyStepInterpolator(state, true);

    interpolator.storeTime(1.0);
    interpolator.shift();
    interpolator.storeTime(2.0);

    state[0] = 5.0;
    state[1] = 6.0;

    interpolator.setInterpolatedTime(1.5);
    double[] interpolated = interpolator.getInterpolatedState();

    assertArrayEquals(new double[] {5.0, 6.0}, interpolated);
  }

  @Test
  void getInterpolatedState_whenResultMutated_internalBufferUnaffected()
      throws DerivativeException {
    double[] state = {3.0, 4.0};
    DummyStepInterpolator interpolator = new DummyStepInterpolator(state, true);

    interpolator.storeTime(0.0);
    interpolator.shift();
    interpolator.storeTime(0.5);
    interpolator.setInterpolatedTime(0.25);

    double[] first = interpolator.getInterpolatedState();
    first[0] = 99.0;

    double[] second = interpolator.getInterpolatedState();
    assertArrayEquals(new double[] {3.0, 4.0}, second);
  }

  @Test
  void copy_whenOriginalChanges_copyRemainsIndependent() throws DerivativeException {
    double[] state = {7.0, 8.0};
    DummyStepInterpolator original = new DummyStepInterpolator(state, true);

    original.storeTime(0.0);
    original.shift();
    original.storeTime(1.0);
    original.setInterpolatedTime(0.75);
    original.finalizeStep();

    DummyStepInterpolator snapshot = original.copy();

    state[0] = 11.0;
    original.setInterpolatedTime(0.8);

    assertArrayEquals(new double[] {7.0, 8.0}, snapshot.getInterpolatedState());
    assertArrayEquals(new double[] {11.0, 8.0}, original.getInterpolatedState());
  }

  @Test
  void serializationRoundTrip_whenUsingExternalizable_preservesStepData() throws Exception {
    double[] state = {9.0, 8.0};
    DummyStepInterpolator interpolator = new DummyStepInterpolator(state, false);

    interpolator.storeTime(1.0);
    interpolator.shift();
    interpolator.storeTime(2.0);
    interpolator.setInterpolatedTime(1.5);

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(bout)) {
      oos.writeObject(interpolator);
    }

    DummyStepInterpolator restored;
    try (ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
      restored = (DummyStepInterpolator) ois.readObject();
    }

    assertEquals(1.0, restored.getPreviousTime());
    assertEquals(2.0, restored.getCurrentTime());
    assertEquals(1.5, restored.getInterpolatedTime());
    assertArrayEquals(new double[] {9.0, 8.0}, restored.getInterpolatedState());
    assertFalse(restored.isForward());
    assertEquals(1.0, restored.h);
  }
}
