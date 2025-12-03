package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class BlockingRAFTest {

  private static final long WAIT_TIMEOUT_MILLIS = 1_000L;

  @Mock private RAF delegateRaf;

  private BlockingRAF blockingRaf;

  @BeforeEach
  void setUp() {
    blockingRaf = new BlockingRAF(delegateRaf);
    lenient().when(delegateRaf.getMode()).thenReturn("rw");
    lenient().when(delegateRaf.isClosed()).thenReturn(false);
  }

  @Test
  void seekAndReadFully_alwaysThrowsUnsupportedOperationException() {
    IOException ex =
        assertThrows(IOException.class, () -> blockingRaf.seekAndReadFully(0L, new byte[1], 0, 1));

    assertEquals("unsupported operation", ex.getMessage());
  }

  @Test
  void seekAndWrite_whenExceptionPreviouslySet_rethrowsAndSkipsDelegate() throws Exception {
    IOException failure = new IOException("boom");
    blockingRaf.setException(failure);

    IOException thrown =
        assertThrows(IOException.class, () -> blockingRaf.seekAndWrite(0L, new byte[0], 0, 0));

    assertSame(failure, thrown);
    verify(delegateRaf, never()).seekAndWrite(anyLong(), any(), anyInt(), anyInt());
  }

  @Test
  void seekAndWrite_withZeroLength_doesNotRecordWrittenRange() throws Exception {
    byte[] data = new byte[0];

    blockingRaf.seekAndWrite(5L, data, 0, 0);

    verify(delegateRaf).seekAndWrite(5L, data, 0, 0);
    assertTrue(blockingRaf.written.isEmpty());
  }

  @Test
  void seekAndRead_whenRangeAlreadyWritten_delegatesToUnderlyingRaf() throws Exception {
    byte[] source = new byte[] {1, 2, 3, 4};
    byte[] dest = new byte[4];
    blockingRaf.seekAndWrite(10L, source, 0, source.length);
    when(delegateRaf.seekAndRead(10L, dest, 0, 4)).thenReturn(4);

    int read = blockingRaf.seekAndRead(10L, dest, 0, 4);

    assertEquals(4, read);
    verify(delegateRaf).seekAndRead(10L, dest, 0, 4);
  }

  @Test
  void seekAndRead_whenDataArrivesAfterBlocking_writesDirectlyToCallerBuffer() throws Exception {
    byte[] dest = new byte[4];
    byte[] source = new byte[] {9, 8, 7, 6};
    AtomicInteger bytesRead = new AtomicInteger(-1);
    AtomicReference<Exception> thrown = new AtomicReference<>();

    Thread reader =
        new Thread(
            () -> {
              try {
                bytesRead.set(blockingRaf.seekAndRead(20L, dest, 0, dest.length));
              } catch (Exception e) {
                thrown.set(e);
              }
            });

    reader.start();
    waitForBuffersToBeRegistered();

    blockingRaf.seekAndWrite(20L, source, 0, source.length);

    reader.join(WAIT_TIMEOUT_MILLIS);
    assertFalse(reader.isAlive(), "reader thread should complete");
    assertNotEquals(-1, bytesRead.get());
    if (thrown.get() != null) {
      throw thrown.get();
    }

    assertEquals(source.length, bytesRead.get());
    assertArrayEquals(source, Arrays.copyOf(dest, source.length));
  }

  @Test
  void seekAndRead_whenModeSwitchesToReadOnly_unblocksAndDelegatesToRead() throws Exception {
    AtomicReference<String> mode = new AtomicReference<>("rw");
    when(delegateRaf.getMode()).thenAnswer(inv -> mode.get());
    when(delegateRaf.seekAndRead(anyLong(), any(), anyInt(), anyInt())).thenReturn(0);

    byte[] dest = new byte[3];
    AtomicInteger bytesRead = new AtomicInteger(-1);
    AtomicReference<Exception> thrown = new AtomicReference<>();

    Thread reader =
        new Thread(
            () -> {
              try {
                bytesRead.set(blockingRaf.seekAndRead(0L, dest, 0, dest.length));
              } catch (Exception e) {
                thrown.set(e);
              }
            });

    reader.start();
    waitForBuffersToBeRegistered();

    mode.set("r");
    blockingRaf.setReadOnly();

    reader.join(WAIT_TIMEOUT_MILLIS);
    assertFalse(reader.isAlive(), "reader thread should complete");
    if (thrown.get() != null) {
      throw thrown.get();
    }

    assertEquals(0, bytesRead.get());
    verify(delegateRaf).setReadOnly();
    verify(delegateRaf).seekAndRead(0L, dest, 0, dest.length);
  }

  @Test
  void seekAndRead_whenExceptionSetDuringWait_throwsSameException() throws Exception {
    AtomicReference<Exception> thrown = new AtomicReference<>();

    Thread reader =
        new Thread(
            () -> {
              try {
                blockingRaf.seekAndRead(0L, new byte[2], 0, 2);
              } catch (Exception e) {
                thrown.set(e);
              }
            });

    reader.start();
    waitForBuffersToBeRegistered();

    IOException expected = new IOException("forced");
    blockingRaf.setException(expected);

    reader.join(WAIT_TIMEOUT_MILLIS);
    assertFalse(reader.isAlive(), "reader thread should complete");
    assertSame(expected, thrown.get());
  }

  @Test
  void seekAndRead_whenThreadInterruptedWhileWaiting_wrapsInInterruptedIOException() {
    AtomicReference<Exception> thrown = new AtomicReference<>();

    Thread reader =
        new Thread(
            () -> {
              try {
                blockingRaf.seekAndRead(0L, new byte[1], 0, 1);
              } catch (Exception e) {
                thrown.set(e);
              }
            });

    reader.start();
    waitForBuffersToBeRegistered();

    reader.interrupt();

    assertTimeoutPreemptively(
        Duration.ofMillis(WAIT_TIMEOUT_MILLIS),
        () -> {
          reader.join();
          assertInstanceOf(InterruptedIOException.class, thrown.get());
        });
  }

  private void waitForBuffersToBeRegistered() {
    final BlockingRAF raf = blockingRaf;
    long deadline = System.currentTimeMillis() + WAIT_TIMEOUT_MILLIS;
    synchronized (raf) {
      while (raf.buffers.isEmpty()) {
        long remaining = deadline - System.currentTimeMillis();
        if (remaining <= 0) {
          throw new AssertionError("Reader thread did not block as expected");
        }
        try {
          raf.wait(remaining);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new AssertionError("Interrupted while waiting for buffers", e);
        }
      }
    }
  }
}
