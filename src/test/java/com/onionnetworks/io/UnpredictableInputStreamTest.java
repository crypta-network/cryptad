package com.onionnetworks.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Random;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class UnpredictableInputStreamTest {

  @Test
  void skip_whenRandomChoosesZero_returnsZeroAndDoesNotAdvance() throws Exception {
    ByteArrayInputStream base = new ByteArrayInputStream(new byte[] {1, 2, 3});
    try (UnpredictableInputStream stream = new UnpredictableInputStream(base)) {
      setRandom(stream, new SequenceRandom(0));

      long skipped = stream.skip(2);

      assertEquals(0, skipped);
      assertEquals(1, stream.read());
    }
  }

  @Test
  void skip_whenRandomPositive_skipsWithinRequestedRange() throws Exception {
    ByteArrayInputStream base = new ByteArrayInputStream(new byte[] {10, 11, 12, 13, 14});
    try (UnpredictableInputStream stream = new UnpredictableInputStream(base)) {
      setRandom(
          stream, new SequenceRandom(1, 3)); // first avoids zero branch, second chooses length 3

      long skipped = stream.skip(5);

      assertEquals(3, skipped);
      assertEquals(13, stream.read());
    }
  }

  @Test
  void read_whenBufferEmpty_returnsZeroWithoutDelegating() throws Exception {
    TrackingInputStream base = new TrackingInputStream(new byte[] {1, 2, 3});
    try (UnpredictableInputStream stream = new UnpredictableInputStream(base)) {
      int read = stream.read(new byte[0]);

      assertEquals(0, read);
      assertEquals(0, base.getTotalReadCalls());
    }
  }

  @Test
  void read_whenFirstAttemptZero_retriesUntilDataAvailable() throws Exception {
    ByteArrayInputStream base = new ByteArrayInputStream(new byte[] {5, 6, 7, 8});
    try (UnpredictableInputStream stream = new UnpredictableInputStream(base)) {
      // first nextInt(5) -> zero-length read, second avoids zero, third chooses length 2
      setRandom(stream, new SequenceRandom(0, 1, 2));
      byte[] buffer = new byte[4];

      int read = stream.read(buffer);

      assertEquals(2, read);
      assertArrayEquals(new byte[] {5, 6, 0, 0}, buffer);
    }
  }

  @Test
  void readWithOffset_whenRandomZero_returnsZeroAndKeepsStreamPosition() throws Exception {
    ByteArrayInputStream base = new ByteArrayInputStream(new byte[] {9, 10, 11});
    try (UnpredictableInputStream stream = new UnpredictableInputStream(base)) {
      setRandom(stream, new SequenceRandom(0));
      byte[] buffer = new byte[4];

      int read = stream.read(buffer, 1, 2);

      assertEquals(0, read);
      assertEquals(9, stream.read());
    }
  }

  @Test
  void readWithOffset_readsRandomLengthWithinBounds() throws Exception {
    ByteArrayInputStream base = new ByteArrayInputStream(new byte[] {1, 2, 3, 4, 5});
    try (UnpredictableInputStream stream = new UnpredictableInputStream(base)) {
      setRandom(stream, new SequenceRandom(2, 4)); // non-zero branch, read 4 bytes
      byte[] buffer = new byte[6];

      int read = stream.read(buffer, 1, 4);

      assertEquals(4, read);
      assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 0}, buffer);
      assertEquals(5, stream.read());
    }
  }

  @Test
  void skip_afterClose_throwsIOExceptionEvenWhenRandomChoosesZero() throws Exception {
    ByteArrayInputStream base = new ByteArrayInputStream(new byte[] {42});
    try (UnpredictableInputStream stream = new UnpredictableInputStream(base)) {
      setRandom(stream, new SequenceRandom(0));
      stream.close();

      assertThrows(IOException.class, () -> stream.skip(1));
    }
  }

  private static void setRandom(UnpredictableInputStream stream, Random random) throws Exception {
    Field field = UnpredictableInputStream.class.getDeclaredField("rand");
    field.setAccessible(true);
    field.set(stream, random);
  }

  private static final class SequenceRandom extends Random {
    private final int[] values;
    private int index;

    SequenceRandom(int... values) {
      this.values = values.clone();
    }

    @Override
    public int nextInt(int bound) {
      int value = values[Math.min(index, values.length - 1)];
      index++;
      return Math.floorMod(value, bound);
    }
  }

  private static final class TrackingInputStream extends InputStream {
    private final ByteArrayInputStream delegate;
    private int totalReadCalls;

    TrackingInputStream(byte[] data) {
      this.delegate = new ByteArrayInputStream(data);
    }

    @Override
    public int read() {
      totalReadCalls++;
      return delegate.read();
    }

    @Override
    public int read(byte @NotNull [] b, int off, int len) {
      totalReadCalls++;
      return delegate.read(b, off, len);
    }

    int getTotalReadCalls() {
      return totalReadCalls;
    }
  }
}
