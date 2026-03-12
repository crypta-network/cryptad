package com.onionnetworks.util;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.EventListener;
import java.util.EventObject;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ReflectiveEventDispatchTest {

  private static final long AWAIT_TIMEOUT_MS = 750L;

  private ReflectiveEventDispatch dispatch;

  @Mock private ExceptionHandler exceptionHandler;

  @BeforeEach
  void setUp() {
    dispatch = new ReflectiveEventDispatch();
  }

  @AfterEach
  void tearDown() throws Exception {
    closeAndJoinDispatch();
  }

  @Test
  void fire_whenListenerRegistered_invokesMethod() throws Exception {
    Object source = new Object();
    RecordingListener listener = new RecordingListener();

    dispatch.addListener(source, listener, "onEvent");

    EventObject event = new EventObject(source);
    dispatch.fire(event, "onEvent");

    assertTrue(listener.await());
    assertSame(event, listener.lastEvent.get());
  }

  @Test
  void fire_withSubclassEvent_invokesListenerExpectingSuperclass() throws Exception {
    Object source = new Object();
    SuperTypeListener listener = new SuperTypeListener();

    dispatch.addListener(source, listener, "handleAny");

    EventObject event = new CustomEvent(source);
    dispatch.fire(event, "handleAny");

    assertTrue(listener.await());
    assertSame(event, listener.lastEvent.get());
  }

  @Test
  void removeListener_whenNotRegistered_throwsException() {
    EventListener listener = new EventListener() {};
    Object source = new Object();

    assertThrows(
        IllegalArgumentException.class, () -> dispatch.removeListener(source, listener, "missing"));
  }

  @Test
  void removeListener_whenMethodNotRegistered_throwsException() {
    Object source = new Object();
    EventListener listener = new EventListener() {};
    dispatch.addListener(source, listener, "onEvent");

    assertThrows(
        IllegalArgumentException.class,
        () -> dispatch.removeListener(source, listener, "otherMethod"));
  }

  @Test
  void fire_afterListenerRemoved_doesNotInvoke() throws Exception {
    Object source = new Object();
    RecordingListener listener = new RecordingListener();
    dispatch.addListener(source, listener, "onEvent");
    dispatch.removeListener(source, listener, "onEvent");

    dispatch.fire(new EventObject(source), "onEvent");

    assertFalse(listener.await());
  }

  @Test
  void fire_whenListenerThrows_routesExceptionToHandler() throws Exception {
    Object source = new Object();
    IllegalStateException failure = new IllegalStateException("boom");

    ThrowingListener listener = new ThrowingListener(failure);
    CountDownLatch handlerLatch = new CountDownLatch(1);
    AtomicReference<ExceptionEvent> captured = new AtomicReference<>();

    doAnswer(
            invocation -> {
              captured.set(invocation.getArgument(0));
              handlerLatch.countDown();
              return null;
            })
        .when(exceptionHandler)
        .handleException(any());
    dispatch.setExceptionHandler(exceptionHandler);
    dispatch.addListener(source, listener, "onEvent");

    dispatch.fire(new EventObject(source), "onEvent");

    assertTrue(handlerLatch.await(AWAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS));
    ExceptionEvent event = captured.get();
    assertSame(dispatch, event.getSource());
    assertInstanceOf(InvocationTargetException.class, event.getException());
    assertSame(failure, event.getException().getCause());
  }

  private void closeAndJoinDispatch() throws Exception {
    dispatch.close();
    Field field = ReflectiveEventDispatch.class.getDeclaredField("thread");
    field.setAccessible(true);
    Thread thread = (Thread) field.get(dispatch);
    thread.join(AWAIT_TIMEOUT_MS);
  }

  private static final class CustomEvent extends EventObject {
    CustomEvent(Object source) {
      super(source);
    }
  }

  public static final class RecordingListener implements EventListener {
    final CountDownLatch latch = new CountDownLatch(1);
    final AtomicReference<EventObject> lastEvent = new AtomicReference<>();

    @SuppressWarnings("unused")
    public void onEvent(EventObject ev) {
      lastEvent.set(ev);
      latch.countDown();
    }

    boolean await() throws InterruptedException {
      return latch.await(AWAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }
  }

  public static final class SuperTypeListener implements EventListener {
    final CountDownLatch latch = new CountDownLatch(1);
    final AtomicReference<EventObject> lastEvent = new AtomicReference<>();

    @SuppressWarnings("unused")
    public void handleAny(EventObject ev) {
      lastEvent.set(ev);
      latch.countDown();
    }

    boolean await() throws InterruptedException {
      return latch.await(AWAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }
  }

  public static final class ThrowingListener implements EventListener {
    private final RuntimeException toThrow;

    ThrowingListener(RuntimeException toThrow) {
      this.toThrow = toThrow;
    }

    @SuppressWarnings("unused")
    public void onEvent(EventObject ev) {
      if (toThrow != null) {
        throw toThrow;
      }
    }
  }
}
