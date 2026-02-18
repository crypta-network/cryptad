package network.crypta.client;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PutWaiterTest {

  @Mock RequestClient requestClient;
  @Mock Bucket bucket;
  @Mock ClientContext clientContext;
  @Mock BaseClientPutter baseClientPutter;

  @Test
  void waitForCompletion_whenSuccessWithUri_expectReturnsUri() throws Exception {
    PutWaiter waiter = new PutWaiter(requestClient);
    FreenetURI expectedUri = new FreenetURI("KSK", "test-doc");

    waiter.onGeneratedURI(expectedUri, baseClientPutter);
    waiter.onSuccess(baseClientPutter);
    FreenetURI got = waiter.waitForCompletion();

    assertSame(expectedUri, got, "waitForCompletion should return the generated URI on success");
  }

  @Test
  void waitForCompletion_whenSuccessWithoutUri_expectReturnsNull() throws Exception {
    PutWaiter waiter = new PutWaiter(requestClient);

    waiter.onSuccess(baseClientPutter);
    FreenetURI got = waiter.waitForCompletion();

    assertNull(got, "URI should be null when none was generated");
  }

  @Test
  void waitForCompletion_whenFailureWithUriOnException_expectThrowsSameInstance() {
    PutWaiter waiter = new PutWaiter(requestClient);
    FreenetURI uri = new FreenetURI("KSK", "insert-target");
    InsertException failure =
        new InsertException(InsertExceptionMode.BUCKET_ERROR, "bucket-failure", uri);

    waiter.onFailure(failure, baseClientPutter);
    InsertException thrown =
        assertThrows(
            InsertException.class,
            waiter::waitForCompletion,
            "waitForCompletion should rethrow the posted InsertException");

    assertSame(failure, thrown, "Thrown InsertException should be the same instance");
    assertSame(uri, thrown.getUri(), "InsertException URI should remain unchanged");
  }

  @Test
  void waitForCompletion_whenFailureWithoutUriButUriKnown_expectThrowsCopyWithUri() {
    PutWaiter waiter = new PutWaiter(requestClient);
    FreenetURI uri = new FreenetURI("KSK", "known-uri");
    InsertException failure = new InsertException(InsertExceptionMode.REJECTED_OVERLOAD);

    waiter.onGeneratedURI(uri, baseClientPutter);
    waiter.onFailure(failure, baseClientPutter);

    InsertException thrown =
        assertThrows(
            InsertException.class,
            waiter::waitForCompletion,
            "waitForCompletion should wrap InsertException with known URI");

    assertNotNull(thrown, "Wrapped InsertException must not be null");
    assertNotNull(thrown.getUri(), "Wrapped InsertException should carry a URI");
    assertEquals(
        InsertExceptionMode.REJECTED_OVERLOAD,
        thrown.mode,
        "Failure mode must be preserved when wrapping");
    assertSame(uri, thrown.getUri(), "Wrapped InsertException should use waiter URI");
    assertEquals(
        failure.getMessage(),
        thrown.getMessage(),
        "Wrapped InsertException should preserve original message");
    assertNotNull(
        thrown.getStackTrace(), "Wrapped InsertException should preserve throwable state metadata");
    // Must not be the same instance when URI is added.
    assertNotSame(failure, thrown, "Wrapped InsertException should be a distinct instance");
  }

  @Test
  void waitForCompletion_whenFailureWithoutUriAndNoGeneratedUri_expectThrowsSameInstance() {
    PutWaiter waiter = new PutWaiter(requestClient);
    InsertException failure = new InsertException(InsertExceptionMode.COLLISION);

    waiter.onFailure(failure, baseClientPutter);
    InsertException thrown =
        assertThrows(
            InsertException.class,
            waiter::waitForCompletion,
            "waitForCompletion should rethrow original InsertException when URI is unknown");

    assertSame(failure, thrown, "Original InsertException should be propagated as-is");
    assertNull(thrown.getUri(), "URI should still be null when none was known");
  }

  @Test
  void waitForCompletion_whenFinishedWithoutOutcome_expectInternalError() throws Exception {
    PutWaiter waiter = new PutWaiter(requestClient);
    FreenetURI uri = new FreenetURI("KSK", "inconsistent-state");

    Field finishedField = PutWaiter.class.getDeclaredField("finished");
    finishedField.setAccessible(true);
    finishedField.setBoolean(waiter, true);

    Field uriField = PutWaiter.class.getDeclaredField("uri");
    uriField.setAccessible(true);
    uriField.set(waiter, uri);

    InsertException thrown =
        assertThrows(
            InsertException.class,
            waiter::waitForCompletion,
            "Unexpected combination of flags should map to INTERNAL_ERROR");

    assertEquals(
        InsertExceptionMode.INTERNAL_ERROR,
        thrown.mode,
        "Inconsistent state must yield INTERNAL_ERROR");
    assertSame(uri, thrown.getUri(), "Internal error should still expose known URI");
  }

  @Test
  void waitForCompletion_whenConcurrentSuccess_expectUnblocksAndReturnsUri() throws Exception {
    PutWaiter waiter = new PutWaiter(requestClient);
    FreenetURI expectedUri = new FreenetURI("KSK", "concurrent-success");

    AtomicReference<FreenetURI> resultRef = new AtomicReference<>();
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
            "putwaiter-success-test");
    t.start();

    awaitWaiting(t, Duration.ofSeconds(2));

    waiter.onGeneratedURI(expectedUri, baseClientPutter);
    waiter.onSuccess(baseClientPutter);

    assertTrue(done.await(2, TimeUnit.SECONDS), "Worker thread should complete after onSuccess");
    assertSame(expectedUri, resultRef.get(), "Worker should observe the generated URI");
  }

  @Test
  void waitForCompletion_whenConcurrentFailure_expectUnblocksAndThrows() throws Exception {
    PutWaiter waiter = new PutWaiter(requestClient);
    InsertException failure = new InsertException(InsertExceptionMode.BUCKET_ERROR);

    AtomicReference<InsertException> thrownRef = new AtomicReference<>();
    CountDownLatch done = new CountDownLatch(1);
    Thread t =
        new Thread(
            () -> {
              try {
                waiter.waitForCompletion();
                fail("Expected an InsertException");
              } catch (InsertException e) {
                thrownRef.set(e);
              } finally {
                done.countDown();
              }
            },
            "putwaiter-failure-test");
    t.start();

    awaitWaiting(t, Duration.ofSeconds(2));
    waiter.onFailure(failure, baseClientPutter);

    assertTrue(done.await(2, TimeUnit.SECONDS), "Worker thread should complete after onFailure");
    assertSame(failure, thrownRef.get(), "Worker should observe the same InsertException instance");
  }

  @Test
  void waitForCompletion_whenInterruptedWhileWaiting_expectReturnsAfterSuccessAndClearsInterrupt()
      throws Exception {
    PutWaiter waiter = new PutWaiter(requestClient);
    FreenetURI expectedUri = new FreenetURI("KSK", "interrupt-test");

    AtomicReference<FreenetURI> resultRef = new AtomicReference<>();
    AtomicReference<InsertException> thrownRef = new AtomicReference<>();
    CountDownLatch done = new CountDownLatch(1);
    Thread t =
        new Thread(
            () -> {
              try {
                resultRef.set(waiter.waitForCompletion());
              } catch (InsertException e) {
                thrownRef.set(e);
              } finally {
                done.countDown();
              }
            },
            "putwaiter-interrupt-test");
    t.start();

    awaitWaiting(t, Duration.ofSeconds(2));
    t.interrupt();

    waiter.onGeneratedURI(expectedUri, baseClientPutter);
    waiter.onSuccess(baseClientPutter);

    assertTrue(done.await(2, TimeUnit.SECONDS), "Worker thread should complete after success");
    assertNull(thrownRef.get(), "Interruptions should not surface as InsertException");
    assertSame(expectedUri, resultRef.get(), "Result after interrupt should still be the URI");
  }

  @Test
  void onGeneratedURI_whenMultipleUrisProvided_expectFirstUriRetained() throws Exception {
    PutWaiter waiter = new PutWaiter(requestClient);
    FreenetURI first = new FreenetURI("KSK", "first");
    FreenetURI second = new FreenetURI("KSK", "second");

    waiter.onGeneratedURI(first, baseClientPutter);
    waiter.onGeneratedURI(second, baseClientPutter);
    waiter.onSuccess(baseClientPutter);

    FreenetURI got = waiter.waitForCompletion();
    assertSame(first, got, "First generated URI should be retained when others arrive later");
  }

  @Test
  void onGeneratedMetadata_whenCalled_expectBucketFreed() {
    PutWaiter waiter = new PutWaiter(requestClient);

    waiter.onGeneratedMetadata(bucket, baseClientPutter);

    verify(bucket).free();
    verifyNoMoreInteractions(bucket);
  }

  @Test
  void onFetchable_whenCalled_expectNoThrow() {
    PutWaiter waiter = new PutWaiter(requestClient);

    waiter.onFetchable(baseClientPutter);

    // onFetchable is a no-op; verify it does not alter observable state.
    assertSame(
        requestClient,
        waiter.getRequestClient(),
        "onFetchable must not alter the associated request client");
  }

  @Test
  void getRequestClient_whenCalled_expectSameReference() {
    PutWaiter waiter = new PutWaiter(requestClient);

    assertSame(requestClient, waiter.getRequestClient(), "Must return constructor-supplied client");
  }

  @Test
  void onResume_whenCalled_expectUnsupportedOperation() {
    PutWaiter waiter = new PutWaiter(requestClient);

    assertThrows(UnsupportedOperationException.class, () -> waiter.onResume(clientContext));
  }

  private static void awaitWaiting(Thread t, Duration timeout) {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      if (t.getState() == Thread.State.WAITING) {
        return;
      }
      Thread.onSpinWait();
    }
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
