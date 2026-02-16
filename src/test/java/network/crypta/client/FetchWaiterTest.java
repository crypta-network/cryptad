package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.async.ClientContext;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FetchWaiterTest {

  @Mock RequestClient requestClient;
  @Mock Bucket bucket;
  @Mock ClientContext clientContext;

  @Test
  void waitForCompletion_whenSuccessPosted_expectReturnsResult() throws Exception {
    FetchWaiter waiter = new FetchWaiter(requestClient);
    FetchResult expected = FetchResult.create(new ClientMetadata("text/plain"), bucket);

    // Act
    waiter.onSuccess(expected, null);
    FetchResult got = waiter.waitForCompletion();

    // Assert
    assertSame(expected, got, "waitForCompletion should return the posted result");
  }

  @Test
  void waitForCompletion_whenFailurePosted_expectThrowsSameException() {
    FetchWaiter waiter = new FetchWaiter(requestClient);
    FetchException failure = new FetchException(FetchExceptionMode.INTERNAL_ERROR);

    waiter.onFailure(failure);
    FetchException thrown =
        assertThrows(
            FetchException.class,
            waiter::waitForCompletion,
            "waitForCompletion should throw the posted exception");

    assertSame(failure, thrown, "Thrown exception instance should be identical to posted one");
  }

  @Test
  void waitForCompletion_whenConcurrentSuccess_expectUnblocksAndReturnsResult() throws Exception {
    FetchWaiter waiter = new FetchWaiter(requestClient);
    FetchResult expected =
        FetchResult.create(new ClientMetadata("application/octet-stream"), bucket);

    AtomicReference<FetchResult> resultRef = new AtomicReference<>();
    CountDownLatch done = new CountDownLatch(1);
    Thread t =
        new Thread(
            () -> {
              try {
                resultRef.set(waiter.waitForCompletion());
              } catch (Throwable t1) {
                fail("Unexpected throwable from waitForCompletion: " + t1);
              } finally {
                done.countDown();
              }
            },
            "fetchwaiter-success-test");
    t.start();

    // Wait until the thread is actually waiting on the monitor to avoid a race.
    awaitWaiting(t, Duration.ofSeconds(2));

    // Signal success; the waiter thread should return promptly.
    waiter.onSuccess(expected, null);

    assertTrue(done.await(2, TimeUnit.SECONDS), "Worker thread should complete after onSuccess");
    assertSame(expected, resultRef.get(), "Result returned by worker should match posted result");
  }

  @Test
  void waitForCompletion_whenConcurrentFailure_expectUnblocksAndThrows() throws Exception {
    FetchWaiter waiter = new FetchWaiter(requestClient);
    FetchException failure = new FetchException(FetchExceptionMode.BUCKET_ERROR);

    AtomicReference<FetchException> thrownRef = new AtomicReference<>();
    CountDownLatch done = new CountDownLatch(1);
    Thread t =
        new Thread(
            () -> {
              try {
                waiter.waitForCompletion();
                fail("Expected a FetchException");
              } catch (FetchException e) {
                thrownRef.set(e);
              } finally {
                done.countDown();
              }
            },
            "fetchwaiter-failure-test");
    t.start();

    awaitWaiting(t, Duration.ofSeconds(2));
    waiter.onFailure(failure);

    assertTrue(done.await(2, TimeUnit.SECONDS), "Worker thread should complete after onFailure");
    assertSame(failure, thrownRef.get(), "Worker should observe the same exception instance");
  }

  @Test
  void waitForCompletion_whenInterrupted_expectCancelledAndInterruptFlagPreserved()
      throws Exception {
    FetchWaiter waiter = new FetchWaiter(requestClient);

    AtomicReference<FetchException> thrownRef = new AtomicReference<>();
    AtomicBoolean interruptedFlag = new AtomicBoolean(false);
    CountDownLatch done = new CountDownLatch(1);
    Thread t =
        new Thread(
            () -> {
              try {
                waiter.waitForCompletion();
                fail("Expected cancellation due to interrupt");
              } catch (FetchException e) {
                thrownRef.set(e);
                interruptedFlag.set(Thread.currentThread().isInterrupted());
              } finally {
                done.countDown();
              }
            },
            "fetchwaiter-interrupt-test");
    t.start();

    awaitWaiting(t, Duration.ofSeconds(2));
    t.interrupt();

    assertTrue(done.await(2, TimeUnit.SECONDS), "Worker thread should complete after interrupt");
    FetchException fe = thrownRef.get();
    assertNotNull(fe, "FetchException should be thrown on interrupt");
    assertEquals(
        FetchExceptionMode.CANCELLED,
        fe.mode,
        "Interrupt should be mapped to FetchExceptionMode.CANCELLED");
    assertTrue(interruptedFlag.get(), "Thread interrupt flag should be preserved");
  }

  @Test
  void onSuccess_whenCalledTwice_expectSecondIgnored() throws Exception {
    FetchWaiter waiter = new FetchWaiter(requestClient);
    FetchResult first = FetchResult.create(new ClientMetadata("text/plain"), bucket);
    FetchResult second = FetchResult.create(new ClientMetadata("text/html"), bucket);

    waiter.onSuccess(first, null);
    waiter.onSuccess(second, null); // should be ignored
    FetchResult got = waiter.waitForCompletion();

    assertSame(first, got, "Second onSuccess should be ignored once finished");
  }

  @Test
  void getRequestClient_whenCalled_expectSameReference() {
    FetchWaiter waiter = new FetchWaiter(requestClient);
    assertSame(requestClient, waiter.getRequestClient(), "Must return constructor-supplied client");
  }

  @Test
  void onResume_whenCalled_expectUnsupportedOperation() {
    FetchWaiter waiter = new FetchWaiter(requestClient);
    assertThrows(UnsupportedOperationException.class, () -> waiter.onResume(clientContext));
  }

  private static void awaitWaiting(Thread t, Duration timeout) {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      if (t.getState() == Thread.State.WAITING) return;
      // Small, deterministic pause; avoids busy spin without long sleeps.
      Thread.onSpinWait();
    }
    // A final small grace check before failing to reduce flakiness on loaded CI.
    if (t.getState() != Thread.State.WAITING) {
      fail(
          "Thread did not reach state "
              + Thread.State.WAITING
              + " within "
              + timeout.toMillis()
              + "ms; current state="
              + t.getState());
    }
  }
}
