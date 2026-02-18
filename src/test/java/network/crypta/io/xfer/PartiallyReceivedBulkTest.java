package network.crypta.io.xfer;

import java.io.IOException;
import java.util.Arrays;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.RetrievalException;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.RandomAccessBuffer;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100") // Follow requested test naming convention
class PartiallyReceivedBulkTest {

  @Mock RandomAccessBuffer raf;

  @Mock MessageCore usm;

  private static MessageCore dummyMessageCore() {
    // Minimal real instance with a no-op executor to avoid NPEs if used indirectly.
    return new MessageCore(
        new PriorityAwareExecutor() {
          @Override
          public void execute(@NotNull Runnable job) {
            job.run();
          }

          @Override
          public void execute(Runnable job, String jobName) {
            job.run();
          }

          @Override
          public void execute(Runnable job, String jobName, boolean fromTicker) {
            job.run();
          }

          @Override
          public int[] waitingThreads() {
            return new int[0];
          }

          @Override
          public int[] runningThreads() {
            return new int[0];
          }

          @Override
          public int getWaitingThreadsCount() {
            return 0;
          }
        });
  }

  @Test
  @DisplayName("constructor_whenInitialFalse_hasWholeFileFalse")
  void constructor_whenInitialFalse_hasWholeFileFalse() {
    long size = 10;
    int blockSize = 4;
    when(raf.size()).thenReturn(size);

    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    assertFalse(prb.hasWholeFile());
    assertFalse(prb.isAborted());
  }

  @Test
  @DisplayName("constructor_whenInitialTrue_hasWholeFileTrue")
  void constructor_whenInitialTrue_hasWholeFileTrue() {
    long size = 10;
    int blockSize = 4;
    when(raf.size()).thenReturn(size);

    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, true);

    assertTrue(prb.hasWholeFile());
    assertFalse(prb.isAborted());
  }

  @Test
  @DisplayName("received_whenValid_writesToRafAndNotifies")
  void received_whenValid_writesToRafAndNotifies() throws Exception {
    long size = 10; // 3 blocks when blockSize=4 (4,4,2)
    int blockSize = 4;
    when(raf.size()).thenReturn(size);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    BulkTransmitter bt = mock(BulkTransmitter.class);
    prb.add(bt);

    byte[] data = new byte[blockSize];
    Arrays.fill(data, (byte) 1);

    prb.received(1, data, 0, data.length);

    // fileOffset for block 1 is 4, bs = 4
    verify(raf, times(1)).pwrite(4L, data, 0, 4);
    verify(bt, times(1)).blockReceived(1);

    assertFalse(prb.hasWholeFile());
  }

  @Test
  @DisplayName("received_whenAllBlocks_thenHasWholeFileTrue")
  void received_whenAllBlocks_thenHasWholeFileTrue() {
    long size = 10; // Blocks: 0->4, 1->4, 2->2
    int blockSize = 4;
    when(raf.size()).thenReturn(size);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    byte[] blk0 = new byte[4];
    byte[] blk1 = new byte[4];
    byte[] blk2 = new byte[2]; // last block size
    prb.received(0, blk0, 0, blk0.length);
    prb.received(1, blk1, 0, blk1.length);
    prb.received(2, blk2, 0, blk2.length);

    assertTrue(prb.hasWholeFile());
  }

  @Test
  @DisplayName("received_whenLengthTooShort_abortsAndClosesAndNotifies")
  void received_whenLengthTooShort_abortsAndClosesAndNotifies() throws Exception {
    long size = 10; // last block requires 2 bytes
    int blockSize = 4;
    when(raf.size()).thenReturn(size);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    BulkTransmitter bt1 = mock(BulkTransmitter.class);
    BulkTransmitter bt2 = mock(BulkTransmitter.class);
    prb.add(bt1);
    prb.add(bt2);
    BulkReceiver br = mock(BulkReceiver.class);
    prb.recv = br; // same package; allowed for test wiring

    byte[] tooShort = new byte[1]; // but bs for block 2 is 2
    prb.received(2, tooShort, 0, tooShort.length);

    assertTrue(prb.isAborted());
    assertEquals(RetrievalException.PREMATURE_EOF, prb.getAbortReason());
    assertNotNull(prb.getAbortDescription());
    verify(raf, times(1)).close();
    verify(bt1, times(1)).onAborted();
    verify(bt2, times(1)).onAborted();
    verify(br, times(1)).onAborted();
    // Should not attempt a write for invalid length
    verify(raf, never()).pwrite(anyLong(), any(), anyInt(), anyInt());
  }

  @Test
  @DisplayName("received_whenBlockNumTooLarge_ignoresWithoutWriteOrAbort")
  void received_whenBlockNumTooLarge_ignoresWithoutWriteOrAbort() throws Exception {
    long size = 10; // blocks = 3, valid blockNos: 0..2
    int blockSize = 4;
    when(raf.size()).thenReturn(size);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    byte[] data = new byte[4];
    prb.received(4, data, 0, data.length); // 4 > blocks (blocks==3)

    assertFalse(prb.isAborted());
    verify(raf, never()).pwrite(anyLong(), any(), anyInt(), anyInt());
  }

  @Test
  @DisplayName("received_whenDuplicateBlock_ignoredNoExtraWrite")
  void received_whenDuplicateBlock_ignoredNoExtraWrite() throws Exception {
    long size = 10;
    int blockSize = 4;
    when(raf.size()).thenReturn(size);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    byte[] data = new byte[4];
    prb.received(0, data, 0, data.length);
    prb.received(0, data, 0, data.length); // duplicate should be ignored

    verify(raf, times(1)).pwrite(0L, data, 0, 4);
  }

  @Test
  @DisplayName("remove_whenTransmitterRemoved_notifiedOnlyRemaining")
  void remove_whenTransmitterRemoved_notifiedOnlyRemaining() {
    long size = 10;
    int blockSize = 4;
    when(raf.size()).thenReturn(size);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    BulkTransmitter keep = mock(BulkTransmitter.class);
    BulkTransmitter remove = mock(BulkTransmitter.class);
    prb.add(keep);
    prb.add(remove);

    prb.remove(remove);

    byte[] data = new byte[4];
    prb.received(1, data, 0, data.length);

    verify(keep, times(1)).blockReceived(1);
    verify(remove, never()).blockReceived(anyInt());
  }

  @Test
  @DisplayName("getBlockData_whenPreadThrows_abortsAndReturnsNull")
  void getBlockData_whenPreadThrows_abortsAndReturnsNull() throws Exception {
    long size = 8;
    int blockSize = 4;
    when(raf.size()).thenReturn(size);
    doThrow(new IOException("boom")).when(raf).pread(anyLong(), any(), anyInt(), anyInt());

    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    byte[] data = prb.getBlockData(0);
    assertNull(data);
    assertTrue(prb.isAborted());
    assertEquals(RetrievalException.IO_ERROR, prb.getAbortReason());
    verify(raf, times(1)).close();
  }

  @Test
  @DisplayName("getBlockData_whenSuccessful_returnsExpectedBytes")
  void getBlockData_whenSuccessful_returnsExpectedBytes() {
    long size = 10;
    int blockSize = 4;
    InMemoryRaf mem = new InMemoryRaf(size);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, mem, false);

    byte[] block0 = new byte[] {10, 11, 12, 13};
    prb.received(0, block0, 0, block0.length);

    byte[] block1 = new byte[] {21, 22, 23, 24};
    prb.received(1, block1, 0, block1.length);

    byte[] out0 = prb.getBlockData(0);
    byte[] out1 = prb.getBlockData(1);

    assertArrayEquals(block0, out0);
    assertArrayEquals(block1, out1);
    assertFalse(prb.isAborted());
  }

  @Test
  @DisplayName("abort_whenCalled_directlyNotifiesAndCloses")
  void abort_whenCalled_directlyNotifiesAndCloses() {
    long size = 8;
    int blockSize = 4;
    when(raf.size()).thenReturn(size);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(dummyMessageCore(), size, blockSize, raf, false);

    BulkTransmitter bt1 = mock(BulkTransmitter.class);
    BulkTransmitter bt2 = mock(BulkTransmitter.class);
    prb.add(bt1);
    prb.add(bt2);
    BulkReceiver br = mock(BulkReceiver.class);
    prb.recv = br;

    prb.abort(42, "test");

    assertTrue(prb.isAborted());
    assertEquals(42, prb.getAbortReason());
    assertEquals("test", prb.getAbortDescription());
    verify(raf, times(1)).close();
    verify(bt1, times(1)).onAborted();
    verify(bt2, times(1)).onAborted();
    verify(br, times(1)).onAborted();
  }

  /** Simple in-memory RandomAccessBuffer for round-trip tests. */
  private static final class InMemoryRaf implements RandomAccessBuffer {
    private final byte[] buf;
    private boolean closed;

    InMemoryRaf(long size) {
      if (size > Integer.MAX_VALUE) throw new IllegalArgumentException("too big");
      this.buf = new byte[(int) size];
    }

    @Override
    public long size() {
      return buf.length;
    }

    @Override
    public void pread(long fileOffset, byte[] dst, int dstOffset, int length) throws IOException {
      if (closed) throw new IOException("closed");
      if (fileOffset < 0) throw new IllegalArgumentException("neg");
      System.arraycopy(buf, (int) fileOffset, dst, dstOffset, length);
    }

    @Override
    public void pwrite(long fileOffset, byte[] src, int srcOffset, int length) throws IOException {
      if (closed) throw new IOException("closed");
      if (fileOffset < 0) throw new IllegalArgumentException("neg");
      System.arraycopy(src, srcOffset, buf, (int) fileOffset, length);
    }

    @Override
    public void close() {
      closed = true;
    }

    @Override
    public void free() {
      // no-op for test buffer
    }
  }
}
