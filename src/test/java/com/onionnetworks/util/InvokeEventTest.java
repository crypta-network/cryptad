package com.onionnetworks.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100") // Method naming follows given convention
class InvokeEventTest {

  @Test
  void getRunnable_whenRunnableProvided_returnsSameInstance() {
    Runnable runnable = () -> {};
    InvokeEvent event = new InvokeEvent(this, runnable);

    assertSame(runnable, event.getRunnable());
  }

  @Test
  void constructor_whenNullSource_throwsIllegalArgumentException() {
    Runnable runnable = () -> {};

    assertThrows(IllegalArgumentException.class, () -> new InvokeEvent(null, runnable));
  }

  @Test
  void getRunnable_whenRunnableIsNull_returnsNull() {
    InvokeEvent event = new InvokeEvent(this, null);

    assertNull(event.getRunnable());
  }

  @Test
  void serialization_whenDeserialized_transientRunnableIsClearedAndSourceClearedByJdk()
      throws Exception {
    String source = "source";
    InvokeEvent event = new InvokeEvent(source, () -> {});
    byte[] serialized;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(event);
      serialized = baos.toByteArray();
    }

    InvokeEvent restored;
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
      restored = (InvokeEvent) ois.readObject();
    }

    assertNull(restored.getSource());
    assertNull(restored.getRunnable());
  }
}
