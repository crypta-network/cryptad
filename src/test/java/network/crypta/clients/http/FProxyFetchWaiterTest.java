package network.crypta.clients.http;

import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FProxyFetchWaiterTest {

  @Mock private FProxyFetchInProgress progress;

  @Mock private FProxyFetchResult fetchResult;

  @Test
  void constructor_whenProgressFinished_setsFinishedAndHasWaitedFromProgress() {
    when(progress.finished()).thenReturn(true);
    when(progress.hasWaited()).thenReturn(true);
    when(progress.innerGetResult(true)).thenReturn(fetchResult);

    FProxyFetchWaiter waiter = new FProxyFetchWaiter(progress);

    FProxyFetchResult result = waiter.getResult();

    verify(progress).setHasWaited();
    assertSame(fetchResult, result);
  }

  @Test
  void getResultFast_returnsImmediateResultWithoutMarkingWaited() {
    when(progress.innerGetResult(false)).thenReturn(fetchResult);

    FProxyFetchWaiter waiter = new FProxyFetchWaiter(progress);

    FProxyFetchResult result = waiter.getResultFast();

    assertSame(fetchResult, result);
    verify(progress).finished();
    verify(progress).hasWaited();
    verify(progress).innerGetResult(false);
    verify(progress, never()).setHasWaited();
    verifyNoMoreInteractions(progress);
  }

  @Test
  void getResult_waitForeverWaitsUntilFinishedAndReportsWaited() throws Exception {
    when(progress.finished()).thenReturn(false);
    when(progress.hasWaited()).thenReturn(false);
    when(progress.innerGetResult(true)).thenReturn(fetchResult);

    FProxyFetchWaiter waiter = new FProxyFetchWaiter(progress);
    FutureTask<FProxyFetchResult> result = new FutureTask<>(() -> waiter.getResult(true));
    Thread waiterThread = new Thread(result, "fproxy-fetch-waiter-test");
    waiterThread.setDaemon(true);
    waiterThread.start();

    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
      while (waiterThread.getState() != Thread.State.WAITING
          && !result.isDone()
          && System.nanoTime() < deadline) {
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
      }
      assertEquals(Thread.State.WAITING, waiterThread.getState(), "waiter thread not waiting");
      assertFalse(result.isDone(), "result must remain blocked until completion is signalled");
      waiter.wakeUp(true);

      assertSame(fetchResult, result.get(10, TimeUnit.SECONDS));
      verify(progress).setHasWaited();
      verify(progress).innerGetResult(true);
    } finally {
      waiter.wakeUp(true);
      waiterThread.join(TimeUnit.SECONDS.toMillis(10));
      assertFalse(waiterThread.isAlive(), "waiter thread did not terminate");
    }
  }

  @Test
  void getResult_whenAlreadyWaited_skipsWaitAndPassesWaitedTrue() {
    when(progress.finished()).thenReturn(false);
    when(progress.hasWaited()).thenReturn(true);
    when(progress.innerGetResult(true)).thenReturn(fetchResult);

    FProxyFetchWaiter waiter = new FProxyFetchWaiter(progress);

    FProxyFetchResult result = waiter.getResult(false);

    verify(progress).setHasWaited();
    verify(progress).innerGetResult(true);
    assertSame(fetchResult, result);
  }

  @Test
  void wakeUp_whenAwokenFlagSet_allowsImmediateResultWithoutWaiting() {
    when(progress.finished()).thenReturn(false);
    when(progress.hasWaited()).thenReturn(false);
    when(progress.innerGetResult(false)).thenReturn(fetchResult);

    FProxyFetchWaiter waiter = new FProxyFetchWaiter(progress);

    waiter.wakeUp(false);
    FProxyFetchResult result = waiter.getResult(false);

    verify(progress).setHasWaited();
    verify(progress).innerGetResult(false);
    assertFalse(waiter.hasWaited());
    assertSame(fetchResult, result);
  }

  @Test
  void close_delegatesToProgressWithSameWaiter() {
    FProxyFetchWaiter waiter = new FProxyFetchWaiter(progress);

    waiter.close();

    verify(progress).close(waiter);
  }

  @Test
  void getProgress_returnsOriginalProgress() {
    FProxyFetchWaiter waiter = new FProxyFetchWaiter(progress);

    assertSame(progress, waiter.getProgress());
  }
}
