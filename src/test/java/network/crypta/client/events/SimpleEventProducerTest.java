package network.crypta.client.events;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.async.ClientContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SimpleEventProducerTest {

  @Mock private ClientEventListener l1;
  @Mock private ClientEventListener l2;
  @Mock private ClientEvent event;
  @Mock private ClientEventDispatchContext context;

  @Test
  void constructor_withArray_addsAllListeners() {
    // Arrange
    ClientEventListener[] initial = new ClientEventListener[] {l1, l2};

    // Act
    SimpleEventProducer producer = new SimpleEventProducer(initial);

    // Assert
    ClientEventListener[] listeners = producer.getEventListeners();
    assertNotNull(listeners, "Listeners array must not be null");
    assertEquals(2, listeners.length, "All provided listeners should be registered");
    assertArrayEquals(initial, listeners, "Order and contents should be preserved");
  }

  @Test
  void constructor_withNullInArray_throwsIllegalArgumentException() {
    // Arrange
    ClientEventListener[] initial = new ClientEventListener[] {l1, null};

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> new SimpleEventProducer(initial));
  }

  @Test
  void addEventListener_whenNull_throwsIllegalArgumentException() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> producer.addEventListener(null));
  }

  @Test
  void addEventListener_andGetEventListeners_includesAddedListener() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();

    // Act
    producer.addEventListener(l1);

    // Assert
    ClientEventListener[] listeners = producer.getEventListeners();
    assertEquals(1, listeners.length, "Exactly one listener should be registered");
    assertEquals(l1, listeners[0], "Registered listener should be present");
  }

  @Test
  void addEventListeners_withArray_addsAll() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();
    ClientEventListener[] arr = new ClientEventListener[] {l1, l2};

    // Act
    producer.addEventListeners(arr);

    // Assert
    ClientEventListener[] listeners = producer.getEventListeners();
    assertArrayEquals(arr, listeners, "All listeners should be added in order");
  }

  @Test
  void removeEventListener_whenPresent_returnsTrueAndRemoves() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();
    producer.addEventListener(l1);

    // Act
    boolean removed = producer.removeEventListener(l1);

    // Assert
    assertTrue(removed, "Removal should report success when present");
    assertEquals(0, producer.getEventListeners().length, "Listener should be removed");
  }

  @Test
  void removeEventListener_whenAbsent_returnsFalse() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();
    producer.addEventListener(l1);

    // Act
    boolean removed = producer.removeEventListener(l2);

    // Assert
    assertFalse(removed, "Removal should report false when not present");
    assertEquals(1, producer.getEventListeners().length, "Unrelated listener should remain");
  }

  @Test
  void produceEvent_withNoListeners_doesNothing() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();

    // Act + Assert (no exception thrown)
    producer.produceEvent(event, context);
    verify(l1, never()).receive(event, context);
    verify(l2, never()).receive(event, context);
  }

  @Test
  void produceEvent_callsAllListenersOnce_withProvidedArgs() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();
    producer.addEventListener(l1);
    producer.addEventListener(l2);

    // Act
    producer.produceEvent(event, context);

    // Assert
    verify(l1, times(1)).receive(event, context);
    verify(l2, times(1)).receive(event, context);
  }

  @Test
  void produceEvent_whenOneListenerThrows_callsOthersAndDoesNotPropagate() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();
    producer.addEventListener(l1);
    producer.addEventListener(l2);

    doThrow(new RuntimeException("boom")).when(l1).receive(event, context);

    // Act + Assert (no exception escapes)
    producer.produceEvent(event, context);

    // Both listeners are attempted; the second must still be called
    verify(l1, times(1)).receive(event, context);
    verify(l2, times(1)).receive(event, context);
  }

  @Test
  void produceEvent_whenListenerRemovesAnother_stillCallsBothDueToSnapshot() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();
    producer.addEventListener(l1);
    producer.addEventListener(l2);

    // First listener removes the second during dispatch
    doAnswer(
            _ -> {
              producer.removeEventListener(l2);
              return null;
            })
        .when(l1)
        .receive(event, context);

    // Act
    producer.produceEvent(event, context);

    // Assert - snapshot taken before dispatch ensures both are invoked once
    verify(l1, times(1)).receive(event, context);
    verify(l2, times(1)).receive(event, context);
  }

  @Test
  void produceEvent_whenListenerImplementsLegacySignature_bridgesToLegacyMethod() {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();
    LegacyStyleListener listener = new LegacyStyleListener();
    ClientContext legacyContext = org.mockito.Mockito.mock(ClientContext.class);
    producer.addEventListener(listener);

    // Act
    producer.produceEvent(event, legacyContext);

    // Assert
    assertSame(event, listener.lastEvent, "Legacy listener should receive the emitted event");
    assertSame(
        legacyContext,
        listener.lastContext,
        "Legacy listener should receive the original ClientContext");
  }

  @Test
  void produceEvent_whenProducerImplementsLegacySignature_bridgesToLegacyMethod() {
    // Arrange
    LegacyStyleProducer producer = new LegacyStyleProducer();
    ClientContext legacyContext = org.mockito.Mockito.mock(ClientContext.class);

    // Act
    ClientEventProducer.dispatchEvent(producer, event, legacyContext);

    // Assert
    assertSame(event, producer.lastEvent, "Legacy producer should receive the emitted event");
    assertSame(
        legacyContext,
        producer.lastContext,
        "Legacy producer should receive the original ClientContext");
  }

  // --- Serialization round-trip tests (merged) ---

  private static class CountingListener implements ClientEventListener, Serializable {
    @Serial private static final long serialVersionUID = 1L;
    final AtomicInteger count = new AtomicInteger();

    @Override
    public void receive(ClientEvent ce, ClientEventDispatchContext context) {
      count.incrementAndGet();
    }
  }

  private static final class LegacyStyleListener implements ClientEventListener, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private transient ClientEvent lastEvent;
    private transient ClientContext lastContext;

    @Override
    public void receive(ClientEvent ce, ClientEventDispatchContext context) {
      throw new AbstractMethodError("legacy listener bridge");
    }

    @SuppressWarnings("UnusedMethod")
    public void receive(ClientEvent ce, ClientContext context) {
      lastEvent = ce;
      lastContext = context;
    }
  }

  private static final class LegacyStyleProducer implements ClientEventProducer, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private transient ClientEvent lastEvent;
    private transient ClientContext lastContext;

    @Override
    public void produceEvent(ClientEvent ce, ClientEventDispatchContext context) {
      throw new AbstractMethodError("legacy producer bridge");
    }

    @SuppressWarnings("UnusedMethod")
    public void produceEvent(ClientEvent ce, ClientContext context) {
      lastEvent = ce;
      lastContext = context;
    }

    @Override
    public void addEventListener(ClientEventListener cel) {
      throw new UnsupportedOperationException("Not needed for compatibility bridge test");
    }

    @Override
    public boolean removeEventListener(ClientEventListener cel) {
      throw new UnsupportedOperationException("Not needed for compatibility bridge test");
    }
  }

  private static class DummyEvent implements ClientEvent, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    @Override
    public String getDescription() {
      return "dummy";
    }

    @Override
    public int getCode() {
      return 1;
    }
  }

  private static SimpleEventProducer roundTrip(SimpleEventProducer producer)
      throws IOException, ClassNotFoundException {
    byte[] bytes;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(producer);
      oos.flush();
      bytes = bos.toByteArray();
    }
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
      return (SimpleEventProducer) ois.readObject();
    }
  }

  @Test
  void listeners_survive_java_serialization_roundtrip() throws IOException, ClassNotFoundException {
    // Arrange
    SimpleEventProducer producer = new SimpleEventProducer();
    CountingListener listener = new CountingListener();
    producer.addEventListener(listener);

    // Round-trip through Java serialization
    SimpleEventProducer restored = roundTrip(producer);

    // Act: fire an event against the restored producer; verify restored listener invoked
    DummyEvent ev = new DummyEvent();
    ClientEventListener[] restoredListeners = restored.getEventListeners();
    assertEquals(1, restoredListeners.length, "Exactly one listener should be restored");
    CountingListener restoredListener = (CountingListener) restoredListeners[0];
    restored.produceEvent(ev, null);

    // Assert
    assertEquals(
        1,
        restoredListener.count.get(),
        "Restored listener should be invoked after deserialization");
  }
}
