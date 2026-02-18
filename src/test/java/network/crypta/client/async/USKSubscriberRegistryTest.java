package network.crypta.client.async;

import java.util.Arrays;
import network.crypta.keys.USK;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKSubscriberRegistryTest {

  @Mock private USKKeyWatchSet watchingKeys;
  @Mock private USKManager uskManager;
  @Mock private USKAttemptManager attempts;
  @Mock private USK origUSK;

  private USKSubscriberRegistry registry;

  @BeforeEach
  void setUp() {
    registry = new USKSubscriberRegistry(watchingKeys, uskManager, attempts, origUSK);
  }

  @Test
  void addSubscriber_whenNewSubscriber_updatesHintsAndPriorities() {
    USKCallback subscriber = mockCallback((short) 3, (short) 2);
    USKFetcherCallback fetcherCallback = mockFetcherCallback((short) 4, (short) 1);
    when(uskManager.lookupLatestSlot(origUSK)).thenReturn(11L);

    registry.addSubscriber(subscriber, 5L, new USKFetcherCallback[] {fetcherCallback}, "fetcher");

    ArgumentCaptor<Long[]> hintsCaptor = ArgumentCaptor.forClass(Long[].class);
    verify(watchingKeys).updateSubscriberHints(hintsCaptor.capture(), eq(11L));
    Long[] hints = hintsCaptor.getValue();
    assertEquals(1, hints.length);
    assertEquals(5L, hints[0]);
    assertTrue(registry.hasSubscribers());
    assertEquals(3, registry.normalPriority());
    assertEquals(1, registry.progressPriority());
    verify(attempts).reloadPollParameters();
  }

  @Test
  void removeSubscriber_whenPresent_updatesHintsAndPriorities() {
    USKCallback first = mockCallback((short) 4, (short) 3);
    USKCallback second = mockCallback((short) 2, (short) 2);
    when(uskManager.lookupLatestSlot(origUSK)).thenReturn(7L);
    registry.addSubscriber(first, 3L, new USKFetcherCallback[0], "fetcher");
    registry.addSubscriber(second, 9L, new USKFetcherCallback[0], "fetcher");
    reset(watchingKeys, attempts);
    when(uskManager.lookupLatestSlot(origUSK)).thenReturn(7L);

    registry.removeSubscriber(first, new USKFetcherCallback[0], "fetcher");

    ArgumentCaptor<Long[]> hintsCaptor = ArgumentCaptor.forClass(Long[].class);
    verify(watchingKeys).updateSubscriberHints(hintsCaptor.capture(), eq(7L));
    Long[] hints = hintsCaptor.getValue();
    assertEquals(1, hints.length);
    assertEquals(9L, hints[0]);
    assertEquals(2, registry.normalPriority());
    verify(attempts).reloadPollParameters();
  }

  @Test
  void removeCallback_whenCalled_updatesHintsWithoutReloadingPriorities() {
    USKCallback subscriber = mockCallback((short) 5, (short) 4);
    when(uskManager.lookupLatestSlot(origUSK)).thenReturn(2L);
    registry.addSubscriber(subscriber, 12L, new USKFetcherCallback[0], "fetcher");
    reset(watchingKeys, attempts);
    when(uskManager.lookupLatestSlot(origUSK)).thenReturn(2L);

    registry.removeCallback(subscriber);

    ArgumentCaptor<Long[]> hintsCaptor = ArgumentCaptor.forClass(Long[].class);
    verify(watchingKeys).updateSubscriberHints(hintsCaptor.capture(), eq(2L));
    Long[] hints = hintsCaptor.getValue();
    assertEquals(0, hints.length);
    verify(attempts, never()).reloadPollParameters();
  }

  @Test
  void snapshotSubscribers_whenCalled_returnsRegisteredSnapshot() {
    USKCallback first = mockCallback((short) 2, (short) 2);
    USKCallback second = mockCallback((short) 3, (short) 1);
    registry.addSubscriber(first, 1L, new USKFetcherCallback[0], "fetcher");
    registry.addSubscriber(second, 2L, new USKFetcherCallback[0], "fetcher");

    USKCallback[] snapshot = registry.snapshotSubscribers();

    assertEquals(2, snapshot.length);
    assertTrue(Arrays.asList(snapshot).contains(first));
    assertTrue(Arrays.asList(snapshot).contains(second));
  }

  @Test
  void refreshAndGetProgressPollPriority_whenCalled_updatesAndReturnsCurrentPriority() {
    USKCallback subscriber = mockCallback((short) 5, (short) 4);
    USKFetcherCallback fetcherCallback = mockFetcherCallback((short) 6, (short) 2);
    registry.addSubscriber(subscriber, 6L, new USKFetcherCallback[0], "fetcher");
    reset(attempts);

    short priority =
        registry.refreshAndGetProgressPollPriority(
            new USKFetcherCallback[] {fetcherCallback}, "fetcher");

    assertEquals(2, priority);
    assertEquals(2, registry.progressPriority());
    verify(attempts).reloadPollParameters();
  }

  @ParameterizedTest
  @CsvSource({"0,false", "2,true"})
  void hasCallbacks_whenArraySizeProvided_returnsExpected(int size, boolean expected) {
    USKFetcherCallback[] callbacks = new USKFetcherCallback[size];

    boolean result = registry.hasCallbacks(callbacks);

    assertEquals(expected, result);
  }

  private static USKCallback mockCallback(short normal, short progress) {
    USKCallback callback = mock(USKCallback.class);
    when(callback.getPollingPriorityNormal()).thenReturn(normal);
    when(callback.getPollingPriorityProgress()).thenReturn(progress);
    return callback;
  }

  private static USKFetcherCallback mockFetcherCallback(short normal, short progress) {
    USKFetcherCallback callback = mock(USKFetcherCallback.class);
    when(callback.getPollingPriorityNormal()).thenReturn(normal);
    when(callback.getPollingPriorityProgress()).thenReturn(progress);
    return callback;
  }
}
