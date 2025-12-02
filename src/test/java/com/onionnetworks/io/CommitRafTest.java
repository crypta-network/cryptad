package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.onionnetworks.util.Range;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CommitRafTest {

  @Mock RAF delegate;

  private CommitRaf commitRaf;
  private ExecutorService executor;

  @BeforeEach
  void setUp() {
    commitRaf = new CommitRaf(delegate);
    executor = Executors.newSingleThreadExecutor();
  }

  @AfterEach
  void tearDown() {
    executor.shutdownNow();
  }

  @Test
  void seekAndWrite_whenExceptionSet_expectIOException() throws Exception {
    IOException failure = new IOException("boom");
    commitRaf.setException(failure);

    IOException thrown =
        assertThrows(IOException.class, () -> commitRaf.seekAndWrite(0, new byte[1], 0, 1));

    assertSame(failure, thrown);
    verify(delegate, never()).seekAndWrite(anyLong(), any(), anyInt(), anyInt());
  }

  @Test
  void seekAndWrite_whenRangeAlreadyCommitted_expectIOException() throws Exception {
    commitRaf.commit(new Range(5, 10));

    assertThrows(IOException.class, () -> commitRaf.seekAndWrite(7, new byte[4], 0, 2));

    verify(delegate, never()).seekAndWrite(anyLong(), any(), anyInt(), anyInt());
  }

  @Test
  void seekAndWrite_withZeroLength_delegatesAndReturnsImmediately() throws Exception {
    commitRaf.seekAndWrite(3, new byte[0], 0, 0);

    verify(delegate).seekAndWrite(3L, new byte[0], 0, 0);
  }

  @Test
  void seekAndRead_whenFullyCommittedAndReadOnly_delegatesToUnderlyingRaf() throws Exception {
    when(delegate.getMode()).thenReturn("r");
    when(delegate.length()).thenReturn(4L);
    when(delegate.seekAndRead(anyLong(), any(), anyInt(), anyInt())).thenReturn(4);
    when(delegate.isClosed()).thenReturn(false);
    byte[] target = new byte[4];
    commitRaf.commit(new Range(0, 3));

    int read = commitRaf.seekAndRead(0, target, 0, 4);

    assertEquals(4, read);
    verify(delegate).seekAndRead(0L, target, 0, 4);
  }

  @Test
  void seekAndRead_waitsForCommit_andReturnsDirectWriteBytes() throws Exception {
    when(delegate.getMode()).thenReturn("rw");
    when(delegate.isClosed()).thenReturn(false);
    doAnswer(invocation -> null).when(delegate).seekAndWrite(anyLong(), any(), anyInt(), anyInt());

    byte[] target = new byte[4];
    Future<Integer> result =
        executor.submit(() -> commitRaf.seekAndRead(0, target, 0, target.length));

    assertTrue(waitForBufferRegistration());

    byte[] data = new byte[] {1, 2, 3, 4};
    commitRaf.seekAndWrite(0, data, 0, data.length);
    commitRaf.commit(new Range(0, data.length - 1));

    assertEquals(data.length, getWithTimeout(result));
    assertArrayEquals(data, target);
    verify(delegate, never()).seekAndRead(anyLong(), any(), anyInt(), anyInt());
  }

  @Test
  void seekAndRead_whenExceptionSetWhileWaiting_throwsOriginalException() throws Exception {
    when(delegate.getMode()).thenReturn("rw");
    when(delegate.isClosed()).thenReturn(false);

    byte[] target = new byte[2];
    Future<Integer> result =
        executor.submit(() -> commitRaf.seekAndRead(0, target, 0, target.length));

    assertTrue(waitForBufferRegistration());

    IOException failure = new IOException("injected");
    commitRaf.setException(failure);

    ExecutionException ex = assertThrows(ExecutionException.class, () -> getWithTimeout(result));
    assertSame(failure, ex.getCause());
    verify(delegate, never()).seekAndRead(anyLong(), any(), anyInt(), anyInt());
  }

  @Test
  void seekAndRead_whenClosedWhileWaiting_throwsClosedIOException() throws Exception {
    AtomicBoolean closed = new AtomicBoolean(false);
    when(delegate.getMode()).thenReturn("rw");
    when(delegate.isClosed()).thenAnswer(invocation -> closed.get());
    doAnswer(
            invocation -> {
              closed.set(true);
              return null;
            })
        .when(delegate)
        .close();

    byte[] target = new byte[3];
    Future<Integer> result =
        executor.submit(() -> commitRaf.seekAndRead(0, target, 0, target.length));

    assertTrue(waitForBufferRegistration());

    commitRaf.close();

    ExecutionException ex = assertThrows(ExecutionException.class, () -> getWithTimeout(result));
    assertInstanceOf(IOException.class, ex.getCause());
    assertEquals("RAF closed", ex.getCause().getMessage());
  }

  @Test
  void seekAndRead_whenLengthIsZero_returnsZeroWithoutWaiting() throws Exception {
    int read = commitRaf.seekAndRead(0, new byte[0], 0, 0);

    assertEquals(0, read);
    assertTrue(commitRaf.buffers.isEmpty());
  }

  private boolean waitForBufferRegistration() throws InterruptedException {
    CommitRaf rafRef = this.commitRaf;
    long deadline = System.currentTimeMillis() + 1_000;
    while (System.currentTimeMillis() < deadline) {
      synchronized (rafRef) {
        if (!rafRef.buffers.isEmpty()) {
          return true;
        }
        long remaining = deadline - System.currentTimeMillis();
        if (remaining > 0) {
          rafRef.wait(Math.min(remaining, 50));
        }
      }
    }
    return false;
  }

  private int getWithTimeout(Future<Integer> future)
      throws InterruptedException, ExecutionException, TimeoutException {
    return future.get(1, TimeUnit.SECONDS);
  }
}
