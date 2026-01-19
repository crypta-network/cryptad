package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;
import network.crypta.node.RequestStarter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKPriorityPolicyTest {

  @Mock private USKAttemptManager attempts;

  private USKPriorityPolicy policy;

  @BeforeEach
  void setUp() {
    policy = new USKPriorityPolicy(attempts);
  }

  @Test
  void normalPriority_whenNewPolicy_returnsDefaults() {
    assertEquals(RequestStarter.PREFETCH_PRIORITY_CLASS, policy.normalPriority());
    assertEquals(RequestStarter.UPDATE_PRIORITY_CLASS, policy.progressPriority());
  }

  @Test
  void updatePriorities_whenCallbacksProvideMinValues_updatesToMinimumAcrossArrays() {
    USKCallback subscriberA = mock(USKCallback.class);
    USKCallback subscriberB = mock(USKCallback.class);
    USKFetcherCallback fetcherCallback = mock(USKFetcherCallback.class);
    when(subscriberA.getPollingPriorityNormal()).thenReturn((short) 4);
    when(subscriberA.getPollingPriorityProgress()).thenReturn((short) 4);
    when(subscriberB.getPollingPriorityNormal()).thenReturn((short) 2);
    when(subscriberB.getPollingPriorityProgress()).thenReturn((short) 5);
    when(fetcherCallback.getPollingPriorityNormal()).thenReturn((short) 3);
    when(fetcherCallback.getPollingPriorityProgress()).thenReturn((short) 1);

    policy.updatePriorities(
        new USKCallback[] {subscriberA, subscriberB},
        new USKFetcherCallback[] {fetcherCallback},
        "fetcher");

    assertEquals(2, policy.normalPriority());
    assertEquals(1, policy.progressPriority());
    verify(subscriberA).getPollingPriorityNormal();
    verify(subscriberA).getPollingPriorityProgress();
    verify(subscriberB).getPollingPriorityNormal();
    verify(subscriberB).getPollingPriorityProgress();
    verify(fetcherCallback).getPollingPriorityNormal();
    verify(fetcherCallback).getPollingPriorityProgress();
    verify(attempts).reloadPollParameters();
  }

  @Test
  void updatePriorities_whenNoCallbacks_resetsToDefaultsAndReloads() {
    USKCallback subscriber = mock(USKCallback.class);
    when(subscriber.getPollingPriorityNormal()).thenReturn((short) 2);
    when(subscriber.getPollingPriorityProgress()).thenReturn((short) 1);

    policy.updatePriorities(new USKCallback[] {subscriber}, new USKFetcherCallback[0], "fetcher");
    policy.updatePriorities(new USKCallback[0], new USKFetcherCallback[0], "fetcher");

    assertEquals(RequestStarter.PREFETCH_PRIORITY_CLASS, policy.normalPriority());
    assertEquals(RequestStarter.UPDATE_PRIORITY_CLASS, policy.progressPriority());
    verify(attempts, times(2)).reloadPollParameters();
  }

  @ParameterizedTest
  @MethodSource("nullCallbackInputs")
  void updatePriorities_whenNullCallbacks_throwsNullPointerException(
      USKCallback[] subscribers, USKFetcherCallback[] fetcherCallbacks) {
    assertThrows(
        NullPointerException.class,
        () -> policy.updatePriorities(subscribers, fetcherCallbacks, "fetcher"));
  }

  private static Stream<Arguments> nullCallbackInputs() {
    return Stream.of(
        Arguments.of(null, new USKFetcherCallback[0]), Arguments.of(new USKCallback[0], null));
  }
}
