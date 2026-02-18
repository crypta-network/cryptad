package network.crypta.store.saltedhash;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;
import network.crypta.support.Fields;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ResizablePersistentIntBufferTest {

  @TempDir Path tempDir;

  @Mock Ticker ticker;

  @AfterEach
  void resetPersistenceTime() {
    ResizablePersistentIntBuffer.setPersistenceTime(
        ResizablePersistentIntBuffer.DEFAULT_PERSISTENCE_TIME);
  }

  @Test
  void constructor_whenFileDoesNotExist_isNewTrueAndZeroFilled() throws IOException {
    File f = tempDir.resolve("new-buffer.dat").toFile();
    int size = 8;

    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, size);
    try {
      assertTrue(buf.isNew());
      assertEquals(size, buf.size());
      // All zeros by default
      for (int i = 0; i < size; i++) {
        assertEquals(0, buf.get(i));
      }
    } finally {
      buf.shutdown();
    }
  }

  @Test
  void constructor_whenFileExists_isNewFalse() throws IOException {
    File f = tempDir.resolve("exists.dat").toFile();
    // Create an empty file without an empty try block
    if (!f.createNewFile() && !f.exists()) {
      try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
        raf.setLength(0);
      }
    }

    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 4);
    try {
      assertFalse(buf.isNew());
    } finally {
      buf.shutdown();
    }
  }

  @Test
  void constructor_whenFileExistsReadsUpToExpectedAndTruncates() throws IOException {
    File f = tempDir.resolve("preexisting.dat").toFile();

    // Pre-populate file with 4 little-endian ints: 11,22,33,44 (matches Fields.bytesToInts())
    try (FileOutputStream fos = new FileOutputStream(f)) {
      fos.write(Fields.intsToBytes(new int[] {11, 22, 33, 44}));
    }

    // Expect length to be truncated to 2 ints when constructing with size=2
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 2);
    try {
      assertEquals(2, buf.size());
      assertEquals(11, buf.get(0));
      assertEquals(22, buf.get(1));
      assertEquals(2L * 4L, f.length());
    } finally {
      buf.shutdown();
    }

    // Also verify expanding reads available values and zero-fills the rest
    ResizablePersistentIntBuffer buf2 = new ResizablePersistentIntBuffer(f, 6);
    try {
      assertEquals(6, buf2.size());
      assertEquals(11, buf2.get(0));
      assertEquals(22, buf2.get(1));
      for (int i = 2; i < 6; i++) {
        assertEquals(0, buf2.get(i));
      }
      assertEquals(6L * 4L, f.length());
    } finally {
      buf2.shutdown();
    }
  }

  @Test
  void get_and_put_whenClosed_throwIllegalState() throws IOException {
    File f = tempDir.resolve("closed.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 2);
    buf.shutdown();

    assertThrows(IllegalStateException.class, () -> buf.get(0));
    assertThrows(IllegalStateException.class, () -> buf.put(0, 1));
  }

  @Test
  void put_whenImmediatePersistence_writesAtOffsetLittleEndian() throws IOException {
    ResizablePersistentIntBuffer.setPersistenceTime(-1);
    File f = tempDir.resolve("immediate.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 3);
    try {
      buf.put(1, 123456789); // should write immediately at offset 4
      assertEquals(0, readIntLE(f, 0));
      assertEquals(123456789, readIntLE(f, 1));
      assertEquals(0, readIntLE(f, 2));

      // noWrite=true must not write immediately
      buf.put(2, 555, true);
      assertEquals(0, readIntLE(f, 2));

      // Forcing a write should persist the pending update
      buf.forceWrite();
      assertEquals(555, readIntLE(f, 2));
    } finally {
      buf.shutdown();
    }
  }

  @Test
  void put_whenPositivePersistenceAndTickerPresent_schedulesOnceAndWriterPersists()
      throws Exception {
    ResizablePersistentIntBuffer.setPersistenceTime(1000);
    File f = tempDir.resolve("scheduled.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 4);

    try {
      // Ticker attached before modifications: scheduling happens on first put only.
      buf.start(ticker);
      buf.put(0, 7);
      buf.put(1, 9);

      ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
      verify(ticker, times(1)).queueTimedJob(captor.capture(), eq(1000L));

      // Not written yet
      assertEquals(0, readIntLE(f, 0));
      assertEquals(0, readIntLE(f, 1));

      // Run the scheduled writer; it writes the whole buffer
      captor.getValue().run();
      assertEquals(7, readIntLE(f, 0));
      assertEquals(9, readIntLE(f, 1));
      assertEquals(0, readIntLE(f, 2));
      assertEquals(0, readIntLE(f, 3));
    } finally {
      buf.shutdown();
    }
  }

  @Test
  void start_whenDirtyWithoutTicker_schedulesOnStart() throws Exception {
    ResizablePersistentIntBuffer.setPersistenceTime(500);
    File f = tempDir.resolve("start-schedules.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 2);

    try {
      // Mark as dirty first; no ticker attached yet
      buf.put(0, 42);
      // Now attach ticker; should schedule once
      buf.start(ticker);

      ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
      verify(ticker, times(1)).queueTimedJob(captor.capture(), eq(500L));

      // Execute scheduled writer to persist
      captor.getValue().run();
      assertEquals(42, readIntLE(f, 0));
    } finally {
      buf.shutdown();
    }
  }

  @Test
  void shutdown_whenDirty_writesAndCloses() throws IOException {
    ResizablePersistentIntBuffer.setPersistenceTime(0);
    File f = tempDir.resolve("shutdown.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 3);
    buf.put(0, 101);
    buf.put(1, 202);

    buf.shutdown();

    // Data should be written for entire buffer (little-endian on disk)
    assertEquals(101, readIntLE(f, 0));
    assertEquals(202, readIntLE(f, 1));
    assertEquals(0, readIntLE(f, 2));

    // Idempotent
    buf.shutdown();
  }

  @Test
  void abort_whenDirty_doesNotWrite() throws IOException {
    ResizablePersistentIntBuffer.setPersistenceTime(0);
    File f = tempDir.resolve("abort.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 2);
    buf.put(1, 77);

    buf.abort();

    // Should remain zeros since abort avoids persistence
    assertEquals(0, readIntLE(f, 0));
    assertEquals(0, readIntLE(f, 1));
  }

  @Test
  void resize_whenGrowAndShrink_preservesPrefix_updatesLength_andPersists() throws IOException {
    File f = tempDir.resolve("resize.dat").toFile();
    ResizablePersistentIntBuffer.setPersistenceTime(0); // no background scheduling
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 2);
    try {
      buf.put(0, 1);
      buf.put(1, 2);

      // Grow to 5
      buf.resize(5);
      assertEquals(5, buf.size());
      assertEquals(1, buf.get(0));
      assertEquals(2, buf.get(1));
      assertEquals(0, buf.get(2));
      assertEquals(0, buf.get(3));
      assertEquals(0, buf.get(4));
      assertEquals(5L * 4L, f.length());
      // Persistence after resize
      assertEquals(1, readIntLE(f, 0));
      assertEquals(2, readIntLE(f, 1));

      // Shrink to 1
      buf.resize(1);
      assertEquals(1, buf.size());
      //noinspection PointlessArithmeticExpression
      assertEquals(1L * 4L, f.length());
      assertEquals(1, readIntLE(f, 0));
    } finally {
      buf.shutdown();
    }
  }

  @Test
  void replaceAllEntries_replacesMatchingValues() throws IOException {
    File f = tempDir.resolve("replace.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 6);
    try {
      int[] vals = {3, 3, 1, 3, 2, 3};
      for (int i = 0; i < vals.length; i++) {
        buf.put(i, vals[i]);
      }
      buf.replaceAllEntries(3, 9);
      int[] expected = {9, 9, 1, 9, 2, 9};
      for (int i = 0; i < expected.length; i++) {
        assertEquals(expected[i], buf.get(i));
      }
    } finally {
      buf.shutdown();
    }
  }

  @Test
  void fill_setsAllValues() throws IOException {
    File f = tempDir.resolve("fill.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 4);
    try {
      buf.fill(77);
      for (int i = 0; i < buf.size(); i++) {
        assertEquals(77, buf.get(i));
      }
    } finally {
      buf.shutdown();
    }
  }

  @Test
  void put_whenIndexOutOfBounds_throwsArrayIndexOutOfBounds() throws IOException {
    File f = tempDir.resolve("bounds.dat").toFile();
    ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(f, 2);
    try {
      assertThrows(ArrayIndexOutOfBoundsException.class, () -> buf.put(2, 1));
      assertThrows(ArrayIndexOutOfBoundsException.class, () -> buf.get(2));
    } finally {
      buf.shutdown();
    }
  }

  // Utility: read one int stored little-endian at index
  private static int readIntLE(File f, int index) throws IOException {
    try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
      byte[] b = new byte[4];
      raf.seek(index * 4L);
      raf.readFully(b);
      // little-endian: b[0] is least significant
      int x = 0;
      for (int j = 3; j >= 0; j--) {
        x = (x << 8) | (b[j] & 0xff);
      }
      return x;
    }
  }
}
