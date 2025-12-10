package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DummyStepHandlerTest {

  @Mock private StepInterpolator interpolator;

  @Test
  void getInstance_whenCalledMultipleTimes_returnsSameSingleton() {
    DummyStepHandler first = DummyStepHandler.getInstance();
    DummyStepHandler second = DummyStepHandler.getInstance();

    assertNotNull(first);
    assertSame(first, second);
  }

  @Test
  void requiresDenseOutput_whenCalled_returnsFalse() {
    DummyStepHandler handler = DummyStepHandler.getInstance();

    assertFalse(handler.requiresDenseOutput());
  }

  @Test
  void reset_whenInvoked_doesNotAlterSingleton() {
    DummyStepHandler handler = DummyStepHandler.getInstance();

    assertDoesNotThrow(handler::reset);
    assertSame(handler, DummyStepHandler.getInstance());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void handleStep_whenCalledWithInterpolator_doesNothing(boolean isLast) {
    DummyStepHandler handler = DummyStepHandler.getInstance();

    handler.handleStep(interpolator, isLast);

    verifyNoInteractions(interpolator);
  }

  @Test
  void handleStep_whenInterpolatorNull_doesNotThrow() {
    DummyStepHandler handler = DummyStepHandler.getInstance();

    assertDoesNotThrow(() -> handler.handleStep(null, true));
  }

  @Test
  void serializationRoundTrip_whenDeserialized_instanceRemainsStateless() throws Exception {
    DummyStepHandler handler = DummyStepHandler.getInstance();

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(bout)) {
      oos.writeObject(handler);
    }

    DummyStepHandler restored;
    try (ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
      restored = (DummyStepHandler) ois.readObject();
    }

    assertNotNull(restored);
    assertFalse(restored.requiresDenseOutput());
    assertSame(handler, DummyStepHandler.getInstance());

    restored.handleStep(interpolator, false);
    verifyNoInteractions(interpolator);
  }
}
