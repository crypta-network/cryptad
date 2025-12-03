package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class ExceptionEventTest {

  @Test
  void constructor_whenSourceAndThrowableProvided_expectStored() {
    Object source = new Object();
    IllegalArgumentException throwable = new IllegalArgumentException("boom");

    ExceptionEvent event = new ExceptionEvent(source, throwable);

    assertSame(source, event.getSource(), "Source should be stored by EventObject");
    assertSame(throwable, event.getException(), "Throwable should be accessible via getException");
  }

  @Test
  void constructor_whenSourceNull_expectIllegalArgumentException() {
    RuntimeException throwable = new RuntimeException();

    assertThrows(IllegalArgumentException.class, () -> new ExceptionEvent(null, throwable));
  }

  @Test
  void getException_whenThrowableNull_expectReturnsNull() {
    ExceptionEvent event = new ExceptionEvent(new Object(), null);

    assertNull(event.getException());
  }
}
