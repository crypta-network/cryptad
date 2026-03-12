package network.crypta.store.caching;

import java.util.ArrayList;
import java.util.List;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** Unit tests for {@link CachingFreenetStoreTracker}. */
@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CachingFreenetStoreTrackerTest {

  @Mock private Ticker ticker;

  private static final long MAX_SIZE = 1_000L;
  private static final long PERIOD = 500L;

  private record ScheduledTask(Runnable job, long delay) {}

  private List<ScheduledTask> scheduled;

  @BeforeEach
  void setUp() {
    scheduled = new ArrayList<>();
    org.mockito.Mockito.lenient()
        .doAnswer(
            invocation -> {
              Runnable job = invocation.getArgument(0);
              long delay = invocation.getArgument(1);
              scheduled.add(new ScheduledTask(job, delay));
              return null;
            })
        .when(ticker)
        .queueTimedJob(any(Runnable.class), anyLong());
  }

  @Test
  void constructor_whenTickerNull_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, null));
  }

  @Test
  void add_whenBelowLowerThreshold_expectIncreaseSizeAndScheduleDelayedJobOnce() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);

    // Act
    boolean accepted = tracker.add(100);

    // Assert
    assertTrue(accepted);
    assertEquals(100L, tracker.getSizeOfCache());
    assertEquals(1, scheduled.size());
    assertEquals(PERIOD, scheduled.getFirst().delay);
  }

  @Test
  void add_whenCalledAgainBeforeDelayedRuns_expectNoSecondDelayedSchedule() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);

    // Act
    tracker.add(100);
    tracker.add(150); // still well below lower threshold cumulatively

    // Assert
    assertEquals(250L, tracker.getSizeOfCache());
    // Only one delayed job should be queued while the first is still pending.
    assertEquals(1, scheduled.size());
    assertEquals(PERIOD, scheduled.getFirst().delay);
  }

  @Test
  void add_whenCrossesLowerThresholdButNotMax_expectImmediateJobAndNoDelayedJob() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);

    // Act
    boolean accepted = tracker.add(950); // 95% of MAX_SIZE → triggers immediate push

    // Assert
    assertTrue(accepted);
    assertEquals(950L, tracker.getSizeOfCache());
    assertEquals(1, scheduled.size());
    assertEquals(0L, scheduled.getFirst().delay);
  }

  @Test
  void add_whenExceedsMax_expectReturnFalseImmediateJobAndSizeUnchanged() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);

    // Act
    boolean accepted = tracker.add(1_100); // > max, but still triggers immediate scheduling

    // Assert
    assertFalse(accepted);
    assertEquals(0L, tracker.getSizeOfCache());
    assertEquals(1, scheduled.size());
    assertEquals(0L, scheduled.getFirst().delay);
  }

  @Test
  void add_whenImmediateAlreadyRunning_expectSecondImmediateNotScheduled() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);

    // Act
    // First call triggers immediate scheduling and marks runningJob=true until the job runs.
    boolean accepted1 = tracker.add(950);
    // Second call also crosses the lower threshold, but must not schedule again while running.
    boolean accepted2 = tracker.add(50);

    // Assert
    assertTrue(accepted1);
    assertTrue(accepted2);
    assertEquals(1_000L, tracker.getSizeOfCache());
    assertEquals(1, scheduled.size());
    assertEquals(0L, scheduled.getFirst().delay);
  }

  @Test
  void pushAllCachingStores_whenBlocksAcrossStores_expectDrainsAndSizeZero() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);
    CachingFreenetStore<?> storeA = org.mockito.Mockito.mock(CachingFreenetStore.class);
    CachingFreenetStore<?> storeB = org.mockito.Mockito.mock(CachingFreenetStore.class);
    tracker.registerCachingFS(storeA);
    tracker.registerCachingFS(storeB);

    // Size matches the sum of the yielded sizes below.
    assertTrue(tracker.add(10));
    assertTrue(tracker.add(20));
    assertTrue(tracker.add(5));
    assertEquals(35L, tracker.getSizeOfCache());

    // storeA: 10, 20, then empty; storeB: 5, then empty.
    org.mockito.Mockito.when(storeA.pushLeastRecentlyBlock())
        .thenReturn(10L)
        .thenReturn(20L)
        .thenReturn(-1L);
    org.mockito.Mockito.when(storeB.pushLeastRecentlyBlock()).thenReturn(5L).thenReturn(-1L);

    // Act
    tracker.pushAllCachingStores();

    // Assert
    assertEquals(0L, tracker.getSizeOfCache());
    verify(storeA, times(3)).pushLeastRecentlyBlock();
    verify(storeB, times(1)).pushLeastRecentlyBlock();
  }

  @Test
  void pushAllCachingStores_whenStoreReturnsMoreThanRemaining_expectClampedToZero() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);
    CachingFreenetStore<?> store = org.mockito.Mockito.mock(CachingFreenetStore.class);
    tracker.registerCachingFS(store);

    assertTrue(tracker.add(10));
    assertEquals(10L, tracker.getSizeOfCache());

    org.mockito.Mockito.when(store.pushLeastRecentlyBlock()).thenReturn(15L).thenReturn(-1L);

    // Act
    tracker.pushAllCachingStores();

    // Assert: size must not go negative; tracker clamps to zero.
    assertEquals(0L, tracker.getSizeOfCache());
    verify(store, times(1)).pushLeastRecentlyBlock();
  }

  @Test
  void unregisterCachingFS_whenStoreHasPendingBlocks_expectSizeDrainedToZero() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);
    CachingFreenetStore<?> store = org.mockito.Mockito.mock(CachingFreenetStore.class);
    tracker.registerCachingFS(store);

    assertTrue(tracker.add(20));
    assertTrue(tracker.add(5));
    assertEquals(25L, tracker.getSizeOfCache());

    org.mockito.Mockito.when(store.pushLeastRecentlyBlock())
        .thenReturn(20L)
        .thenReturn(5L)
        .thenReturn(-1L);

    // Act
    tracker.unregisterCachingFS(store);

    // Assert
    assertEquals(0L, tracker.getSizeOfCache());
  }

  @Test
  void delayedJob_whenRuns_expectQueuedFlagResetsAndAllowsAnotherDelayedSchedule() {
    // Arrange
    CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(MAX_SIZE, PERIOD, ticker);
    CachingFreenetStore<?> store = org.mockito.Mockito.mock(CachingFreenetStore.class);
    tracker.registerCachingFS(store);

    // Add a block that the delayed job will flush.
    assertTrue(tracker.add(100));
    org.mockito.Mockito.when(store.pushLeastRecentlyBlock()).thenReturn(100L).thenReturn(-1L);
    assertEquals(1, scheduled.size());
    assertEquals(PERIOD, scheduled.getFirst().delay);

    // Act: run the delayed job now (deterministic, no background threads).
    scheduled.getFirst().job.run();

    // After job completes, a new add below threshold should schedule another delayed job.
    assertTrue(tracker.add(10));

    // Assert
    assertEquals(2, scheduled.size());
    assertEquals(PERIOD, scheduled.get(1).delay);
  }
}
