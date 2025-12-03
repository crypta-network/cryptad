package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class InvokingDispatchTest {

  private static final long AWAIT_TIMEOUT_MS = 750L;

  private InvokingDispatch dispatch;

  @BeforeEach
  void setUp() {
    dispatch = new InvokingDispatch();
  }

  @AfterEach
  void tearDown() throws Exception {
    closeAndJoinDispatch();
  }

  @Test
  void invokeLater_whenRunnableProvided_executesRunnable() throws Exception {
    CountDownLatch latch = new CountDownLatch(1);

    dispatch.invokeLater(latch::countDown);

    assertTrue(latch.await(AWAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS));
  }

  @Test
  void invokeAndWait_whenRunnableCompletes_returnsAfterExecution() throws Exception {
    AtomicBoolean executed = new AtomicBoolean(false);

    dispatch.invokeAndWait(() -> executed.set(true));

    assertTrue(executed.get());
  }

  @Test
  void invokeAndWait_blocksUntilRunnableFinishes() throws Exception {
    CountDownLatch runStarted = new CountDownLatch(1);
    CountDownLatch allowFinish = new CountDownLatch(1);
    AtomicBoolean timedOutAwaitingFinish = new AtomicBoolean(false);
    AtomicBoolean returned = new AtomicBoolean(false);

    Thread caller =
        new Thread(
            () -> {
              try {
                dispatch.invokeAndWait(
                    () -> {
                      runStarted.countDown();
                      try {
                        boolean awaited =
                            allowFinish.await(AWAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                        if (!awaited) {
                          timedOutAwaitingFinish.set(true);
                        }
                      } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                      }
                    });
                returned.set(true);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            },
            "invokeAndWait-caller");

    caller.start();

    assertTrue(runStarted.await(AWAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS));
    assertTrue(caller.isAlive());

    allowFinish.countDown();
    caller.join(AWAIT_TIMEOUT_MS);

    assertTrue(returned.get());
    assertFalse(timedOutAwaitingFinish.get());
    assertFalse(caller.isAlive());
  }

  private void closeAndJoinDispatch() throws Exception {
    dispatch.close();
    Field field = ReflectiveEventDispatch.class.getDeclaredField("thread");
    field.setAccessible(true);
    Thread thread = (Thread) field.get(dispatch);
    thread.join(AWAIT_TIMEOUT_MS);
  }
}
