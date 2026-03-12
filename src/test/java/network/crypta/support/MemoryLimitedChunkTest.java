package network.crypta.support;

import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/** Tests for {@link MemoryLimitedChunk}. */
class MemoryLimitedChunkTest {

  @Test
  void constructorWhenNegativeUsedExpectIllegalArgumentException() {
    MemoryLimitedJobRunner runner = mock(MemoryLimitedJobRunner.class);
    assertThrows(IllegalArgumentException.class, () -> new MemoryLimitedChunk(runner, -1));
  }

  @Test
  void getRunnerWhenConstructedExpectSameInstance() {
    MemoryLimitedJobRunner runner = mock(MemoryLimitedJobRunner.class);
    MemoryLimitedChunk chunk = new MemoryLimitedChunk(runner, 0);
    assertSame(runner, chunk.getRunner());
  }

  @Test
  void releaseWhenUsedIsZeroExpectZeroAndNoDeallocate() {
    MemoryLimitedJobRunner runner = mock(MemoryLimitedJobRunner.class);
    MemoryLimitedChunk chunk = new MemoryLimitedChunk(runner, 0);

    long released = chunk.release();

    assertEquals(0, released);
    verifyNoInteractions(runner);
  }

  @Test
  void releaseWhenUsedPositiveExpectAllReleasedAndDeallocateTrue() {
    long initial = 42L;
    MemoryLimitedJobRunner runner = mock(MemoryLimitedJobRunner.class);
    MemoryLimitedChunk chunk = new MemoryLimitedChunk(runner, initial);

    long released = chunk.release();

    assertEquals(initial, released);
    verify(runner).deallocate(initial, true);

    // Idempotent on second call: nothing more to release, no extra deallocate
    long again = chunk.release();
    assertEquals(0L, again);
    verifyNoMoreInteractions(runner);
  }

  @Test
  void releaseAmountWhenGreaterThanUsedExpectIllegalArgumentExceptionAndNoDeallocate() {
    MemoryLimitedJobRunner runner = mock(MemoryLimitedJobRunner.class);
    MemoryLimitedChunk chunk = new MemoryLimitedChunk(runner, 5L);

    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> chunk.release(6L));
    assertEquals("Only have 5 in use but asked to release 6", ex.getMessage());
    verify(runner, never()).deallocate(anyLong(), anyBoolean());
  }

  @Test
  void releaseAmountWhenEqualsUsedExpectDeallocateTrueAndZeroLeft() {
    MemoryLimitedJobRunner runner = mock(MemoryLimitedJobRunner.class);
    MemoryLimitedChunk chunk = new MemoryLimitedChunk(runner, 10L);

    long released = chunk.release(10L);

    assertEquals(10L, released);
    verify(runner).deallocate(10L, true);

    long again = chunk.release();
    assertEquals(0L, again);
    verifyNoMoreInteractions(runner);
  }

  @Test
  void releaseAmountWhenLessThanUsedExpectDeallocateFalseThenTrue() {
    MemoryLimitedJobRunner runner = mock(MemoryLimitedJobRunner.class);
    MemoryLimitedChunk chunk = new MemoryLimitedChunk(runner, 10L);

    long first = chunk.release(3L);
    long second = chunk.release(7L);

    assertEquals(3L, first);
    assertEquals(7L, second);

    InOrder order = inOrder(runner);
    order.verify(runner).deallocate(3L, false);
    order.verify(runner).deallocate(7L, true);
    order.verifyNoMoreInteractions();
  }

  @Test
  void releaseAmountWhenZeroExpectDeallocateCalledWithZeroAndFinishedFalse() {
    MemoryLimitedJobRunner runner = mock(MemoryLimitedJobRunner.class);
    MemoryLimitedChunk chunk = new MemoryLimitedChunk(runner, 5L);

    long released = chunk.release(0L);

    assertEquals(0L, released);
    verify(runner).deallocate(0L, false);
  }

  @Test
  void releaseWhenRunnerIsNullExpectNullPointerException() {
    MemoryLimitedChunk chunk = new MemoryLimitedChunk(null, 4L);
    assertThrows(NullPointerException.class, chunk::release);
  }
}
