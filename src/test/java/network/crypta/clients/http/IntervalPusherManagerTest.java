package network.crypta.clients.http;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import network.crypta.clients.http.updateableelements.BaseUpdateableElement;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class IntervalPusherManagerTest {

  private static final long REFRESH_PERIOD_MS = 10_000L;

  @Mock private Ticker ticker;

  @Mock private PushDataManager pushDataManager;

  @Mock private BaseUpdateableElement firstElement;

  @Mock private BaseUpdateableElement secondElement;

  private IntervalPusherManager manager;

  @BeforeEach
  void setUp() {
    manager = new IntervalPusherManager(ticker, pushDataManager);
  }

  @Test
  void registerUpdateableElement_whenFirstElement_shouldScheduleRefresher() {
    manager.registerUpdateableElement(firstElement);

    verify(ticker)
        .queueTimedJob(
            any(Runnable.class), eq("Stats refresher"), eq(REFRESH_PERIOD_MS), eq(false), eq(true));
  }

  @Test
  void registerUpdateableElement_whenAdditionalElement_shouldNotScheduleAgain() {
    manager.registerUpdateableElement(firstElement);
    clearInvocations(ticker);

    manager.registerUpdateableElement(secondElement);

    verify(ticker, never())
        .queueTimedJob(any(Runnable.class), anyString(), anyLong(), anyBoolean(), anyBoolean());
  }

  @Test
  void refresherJob_whenRun_updatesElementsAndReschedules() {
    when(firstElement.getUpdaterId(null)).thenReturn("first");
    when(secondElement.getUpdaterId(null)).thenReturn("second");
    ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);

    manager.registerUpdateableElement(firstElement);
    manager.registerUpdateableElement(secondElement);

    verify(ticker)
        .queueTimedJob(
            captor.capture(), eq("Stats refresher"), eq(REFRESH_PERIOD_MS), eq(false), eq(true));

    Runnable refresher = captor.getValue();

    refresher.run();

    verify(pushDataManager).updateElement("first");
    verify(pushDataManager).updateElement("second");
    verify(ticker, times(2))
        .queueTimedJob(
            any(Runnable.class), eq("Stats refresher"), eq(REFRESH_PERIOD_MS), eq(false), eq(true));
  }

  @Test
  void refresherJob_whenNoElements_doesNotReschedule() {
    ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
    manager.registerUpdateableElement(firstElement);

    verify(ticker)
        .queueTimedJob(
            captor.capture(), eq("Stats refresher"), eq(REFRESH_PERIOD_MS), eq(false), eq(true));

    manager.deregisterUpdateableElement(firstElement);
    clearInvocations(ticker, pushDataManager);

    captor.getValue().run();

    verifyNoInteractions(pushDataManager);
    verify(ticker, never())
        .queueTimedJob(any(Runnable.class), anyString(), anyLong(), anyBoolean(), anyBoolean());
  }
}
