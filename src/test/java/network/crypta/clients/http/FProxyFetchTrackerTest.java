package network.crypta.clients.http;

import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.MultiValueTable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FProxyFetchTrackerTest {

  @Test
  void getFetchInProgress_whenMatchingSizeAndActive_returnsFetcher() throws Exception {
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient rc = mock(RequestClient.class);
    FProxyFetchTracker tracker = new FProxyFetchTracker(fetchContext, runtimeSupport, rc);

    FreenetURI key = mock(FreenetURI.class);
    FProxyFetchInProgress fetch = mock(FProxyFetchInProgress.class);
    setFinalField(fetch, "maxSize", 1024L);
    when(fetch.notFinishedOrFatallyFinished()).thenReturn(true);
    when(fetch.fetchContextEquivalent(fetchContext)).thenReturn(true);
    setFinalField(fetch, "uri", key);

    getFetchers(tracker).put(key, fetch);

    FProxyFetchInProgress result =
        tracker.getFetchInProgress(new FProxyFetchCriteria(key, 1024L, fetchContext));

    assertSame(fetch, result);
  }

  @Test
  void getFetchInProgress_whenHasData_returnsFetcher() throws Exception {
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient rc = mock(RequestClient.class);
    FProxyFetchTracker tracker = new FProxyFetchTracker(fetchContext, runtimeSupport, rc);

    FreenetURI key = mock(FreenetURI.class);
    FProxyFetchInProgress fetch = mock(FProxyFetchInProgress.class);
    setFinalField(fetch, "maxSize", 2048L);
    when(fetch.hasData()).thenReturn(true);
    setFinalField(fetch, "uri", key);

    getFetchers(tracker).put(key, fetch);

    FProxyFetchInProgress result =
        tracker.getFetchInProgress(new FProxyFetchCriteria(key, 123L, null));

    assertSame(fetch, result);
  }

  @Test
  void getFetchInProgress_whenContextDiffers_returnsNull() throws Exception {
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FetchContext trackerContext = mock(FetchContext.class);
    RequestClient rc = mock(RequestClient.class);
    FProxyFetchTracker tracker = new FProxyFetchTracker(trackerContext, runtimeSupport, rc);

    FreenetURI key = mock(FreenetURI.class);
    FetchContext requestedContext = mock(FetchContext.class);
    FProxyFetchInProgress fetch = mock(FProxyFetchInProgress.class);
    setFinalField(fetch, "maxSize", 512L);
    when(fetch.notFinishedOrFatallyFinished()).thenReturn(true);
    when(fetch.fetchContextEquivalent(requestedContext)).thenReturn(false);
    setFinalField(fetch, "uri", key);

    getFetchers(tracker).put(key, fetch);

    FProxyFetchInProgress result =
        tracker.getFetchInProgress(new FProxyFetchCriteria(key, 512L, requestedContext));

    assertNull(result);
  }

  @Test
  void makeFetcher_whenExistingFetcherPresent_reusesExistingWaiter() throws Exception {
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient rc = mock(RequestClient.class);
    FProxyFetchTracker tracker = new FProxyFetchTracker(fetchContext, runtimeSupport, rc);

    FreenetURI key = mock(FreenetURI.class);
    FProxyFetchWaiter waiter = mock(FProxyFetchWaiter.class);
    FProxyFetchInProgress fetch = mock(FProxyFetchInProgress.class);
    setFinalField(fetch, "maxSize", 1024L);
    when(fetch.notFinishedOrFatallyFinished()).thenReturn(true);
    when(fetch.fetchContextEquivalent(fetchContext)).thenReturn(true);
    when(fetch.getWaiter()).thenReturn(waiter);
    setFinalField(fetch, "uri", key);

    getFetchers(tracker).put(key, fetch);

    FProxyFetchWaiter result =
        tracker.makeFetcher(
            new FProxyFetchCriteria(key, 1024L, fetchContext), RefilterPolicy.RE_FETCH);

    assertSame(waiter, result);
    verify(fetch, never()).start();
  }

  @Test
  void makeFetcher_whenStartThrows_removesFetcherAndPropagates() throws Exception {
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient rc = mock(RequestClient.class);
    FProxyFetchTracker tracker = new FProxyFetchTracker(fetchContext, runtimeSupport, rc);

    FreenetURI key = mock(FreenetURI.class);
    FetchException failure = new FetchException(FetchExceptionMode.INTERNAL_ERROR, "boom");

    try (var _ =
        mockConstruction(
            FProxyFetchInProgress.class,
            (mock, _) -> {
              when(mock.getWaiter()).thenReturn(mock(FProxyFetchWaiter.class));
              doThrow(failure).when(mock).start();
              setFinalField(mock, "uri", key);
            })) {

      FetchException thrown =
          assertThrows(
              FetchException.class,
              () ->
                  tracker.makeFetcher(
                      new FProxyFetchCriteria(key, 2048L, fetchContext), RefilterPolicy.RE_FILTER));

      assertSame(failure, thrown);
      assertTrue(getFetchers(tracker).values().isEmpty(), "fetcher should be removed on failure");
    }
  }

  @Test
  void queueCancel_whenAlreadyQueued_setsRequeueWithoutRequeuing() throws Exception {
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient rc = mock(RequestClient.class);
    FProxyFetchTracker tracker = new FProxyFetchTracker(fetchContext, runtimeSupport, rc);

    FProxyFetchInProgress fetch = mock(FProxyFetchInProgress.class);

    tracker.queueCancel(fetch);
    tracker.queueCancel(fetch);

    verify(runtimeSupport, times(1)).queueTimedJob(tracker, FProxyFetchInProgress.LIFETIME);
    Field requeueField = findField(FProxyFetchTracker.class, "requeue");
    requeueField.setAccessible(true);
    assertTrue((Boolean) requeueField.get(tracker));
  }

  @Test
  void run_whenRequeueFlagSet_cancelsEligibleAndRequeues() throws Exception {
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient rc = mock(RequestClient.class);
    FProxyFetchTracker tracker = new FProxyFetchTracker(fetchContext, runtimeSupport, rc);

    FreenetURI key1 = mock(FreenetURI.class);
    FreenetURI key2 = mock(FreenetURI.class);
    FProxyFetchInProgress cancellable = mock(FProxyFetchInProgress.class);
    when(cancellable.canCancel()).thenReturn(true);
    setFinalField(cancellable, "uri", key1);
    FProxyFetchInProgress persistent = mock(FProxyFetchInProgress.class);
    when(persistent.canCancel()).thenReturn(false);
    setFinalField(persistent, "maxSize", 0L);
    when(persistent.notFinishedOrFatallyFinished()).thenReturn(true);
    setFinalField(persistent, "uri", key2);

    MultiValueTable<FreenetURI, FProxyFetchInProgress> fetchers = getFetchers(tracker);
    fetchers.put(key1, cancellable);
    fetchers.put(key2, persistent);

    // Mark for requeue via two cancel requests
    tracker.queueCancel(cancellable);
    tracker.queueCancel(cancellable);

    tracker.run();

    verify(cancellable, times(1)).finishCancel();
    assertNull(tracker.getFetchInProgress(new FProxyFetchCriteria(key1, 0L, null)));
    assertSame(persistent, tracker.getFetchInProgress(new FProxyFetchCriteria(key2, 0L, null)));
    verify(runtimeSupport, times(2)).queueTimedJob(tracker, FProxyFetchInProgress.LIFETIME);
  }

  @Test
  void makeRandomElementID_returnsValueFromFastWeakRandom() {
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient rc = mock(RequestClient.class);
    FProxyFetchTracker tracker = new FProxyFetchTracker(fetchContext, runtimeSupport, rc);

    int expected = new Random(1234L).nextInt();
    when(runtimeSupport.nextWeakRandomInt()).thenReturn(expected);

    int actual = tracker.makeRandomElementID();

    assertEquals(expected, actual);
  }

  @SuppressWarnings("unchecked")
  private MultiValueTable<FreenetURI, FProxyFetchInProgress> getFetchers(FProxyFetchTracker tracker)
      throws Exception {
    Field field = FProxyFetchTracker.class.getDeclaredField("fetchers");
    field.setAccessible(true);
    return (MultiValueTable<FreenetURI, FProxyFetchInProgress>) field.get(tracker);
  }

  private void setFinalField(Object target, String name, Object value) throws Exception {
    Field field = findField(target.getClass(), name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private Field findField(Class<?> type, String name) throws NoSuchFieldException {
    Class<?> current = type;
    while (current != null) {
      try {
        return current.getDeclaredField(name);
      } catch (NoSuchFieldException _) {
        current = current.getSuperclass();
      }
    }
    throw new NoSuchFieldException(name);
  }
}
