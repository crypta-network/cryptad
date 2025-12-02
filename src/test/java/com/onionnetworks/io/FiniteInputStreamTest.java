package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FiniteInputStreamTest {

  @Test
  void constructor_whenInputStreamNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, FiniteInputStreamTest::createStreamWithNullParent);
  }

  @Test
  void constructor_whenCountNegative_throwsIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class, FiniteInputStreamTest::createStreamWithNegativeCount);
  }

  private static void createStreamWithNullParent() throws IOException {
    //noinspection EmptyTryBlock
    try (FiniteInputStream ignored = new FiniteInputStream(null, 1)) {
      // no-op
    }
  }

  private static void createStreamWithNegativeCount() throws IOException {
    //noinspection EmptyTryBlock
    try (FiniteInputStream ignored =
        new FiniteInputStream(new ByteArrayInputStream(new byte[0]), -1)) {
      // no-op
    }
  }

  @Test
  void read_whenWithinLimit_returnsBytesUntilLimitThenMinusOne() throws IOException {
    byte[] source = new byte[] {10, 20, 30, 40};

    try (FiniteInputStream stream = new FiniteInputStream(new ByteArrayInputStream(source), 3)) {
      byte[] buffer = new byte[2];

      int firstRead = stream.read(buffer, 0, buffer.length);
      assertEquals(2, firstRead);
      assertArrayEquals(new byte[] {10, 20}, buffer);

      int secondRead = stream.read(buffer, 0, buffer.length);
      assertEquals(1, secondRead);
      assertEquals(30, buffer[0]);

      int end = stream.read(buffer, 0, 1);
      assertEquals(-1, end);
    }
  }

  @Test
  void read_whenUnderlyingEndsEarly_throwsEOFException() throws IOException {
    byte[] source = new byte[] {1, 2};

    try (FiniteInputStream stream = new FiniteInputStream(new ByteArrayInputStream(source), 3)) {
      byte[] buffer = new byte[2];
      int read = stream.read(buffer, 0, buffer.length);
      assertEquals(2, read);

      assertThrows(EOFException.class, () -> stream.read(new byte[1], 0, 1));
    }
  }

  @Test
  void read_whenCountZero_returnsMinusOneWithoutReadingParent() throws IOException {
    InputStream parent = mock(InputStream.class);

    try (FiniteInputStream stream = new FiniteInputStream(parent, 0)) {
      int result = stream.read();

      assertEquals(-1, result);
      verifyNoInteractions(parent);
    }
  }

  @Test
  void readZeroLength_whenNoBytesLeft_returnsZero() throws IOException {
    try (FiniteInputStream stream =
        new FiniteInputStream(new ByteArrayInputStream(new byte[] {5, 6}), 0)) {
      int result = stream.read(new byte[1], 0, 0);

      assertEquals(0, result);
    }
  }

  @Test
  void skip_whenRequestExceedsRemaining_skipsOnlyRemainingBytes() throws IOException {
    try (FiniteInputStream stream =
        new FiniteInputStream(new ByteArrayInputStream(new byte[] {1, 2, 3, 4, 5}), 3)) {
      long skipped = stream.skip(10);

      assertEquals(3L, skipped);
      assertEquals(-1, stream.read());
    }
  }

  @Test
  void available_afterPartialRead_reflectsRemainingBytes() throws IOException {
    try (FiniteInputStream stream =
        new FiniteInputStream(new ByteArrayInputStream(new byte[] {9, 8, 7, 6, 5}), 4)) {
      int initial = stream.available();
      assertEquals(4, initial);

      byte[] buffer = new byte[2];
      int read = stream.read(buffer, 0, buffer.length);
      assertEquals(2, read);

      int after = stream.available();
      assertEquals(2, after);
    }
  }

  @Test
  void read_whenSingleByteAvailable_returnsUnsignedByteValue() throws IOException {
    try (FiniteInputStream stream =
        new FiniteInputStream(new ByteArrayInputStream(new byte[] {(byte) 0xFF}), 1)) {
      int value = stream.read();
      assertEquals(255, value);

      assertEquals(-1, stream.read());
    }
  }
}
