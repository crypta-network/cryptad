package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link DiskSpaceCheckingOutputStream}.
 *
 * <p>- Uses AAA style - Mocks external I/O using Mockito - Covers null, empty, boundary and error
 * paths
 */
class DiskSpaceCheckingOutputStreamTest {

  // Helpers
  private static DiskSpaceCheckingOutputStream newStream(
      OutputStream out, DiskSpaceChecker checker, File file, int bufferSize) {
    return new DiskSpaceCheckingOutputStream(out, checker, file, bufferSize);
  }

  @Test
  @DisplayName("write_whenBelowBuffer_doesNotCheckSpace")
  void write_whenBelowBuffer_doesNotCheckSpace() throws IOException {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    File file = new File("/tmp/dummy");
    int bufferSize = 8;
    byte[] data = new byte[5];
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, file, bufferSize);

    // Act
    stream.write(data);

    // Assert
    verifyNoInteractions(checker);
    verify(out).write(data, 0, 5);
    verifyNoMoreInteractions(out);
  }

  @Test
  @DisplayName("write_whenCrossesThreshold_callsCheckerOnceAndWrites")
  void write_whenCrossesThreshold_callsCheckerOnceAndWrites() throws IOException {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    when(checker.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    File file = new File("/tmp/dummy");
    int bufferSize = 10;
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, file, bufferSize);

    byte[] a = new byte[5];
    byte[] b = new byte[4];
    byte[] c = new byte[1]; // This write crosses the threshold (5+4 -> 9; +1 -> 10)

    // Act
    stream.write(a);
    stream.write(b);
    stream.write(c);

    // Assert
    // Only the last write should trigger the first check
    verify(checker, times(1)).checkDiskSpace(file, 1, bufferSize);
    verify(out).write(a, 0, a.length);
    verify(out).write(b, 0, b.length);
    verify(out).write(c, 0, c.length);
    verifyNoMoreInteractions(out);
  }

  @Test
  @DisplayName("write_whenEqualToBuffer_callsCheckerOnce")
  void write_whenEqualToBuffer_callsCheckerOnce() throws IOException {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    when(checker.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    File file = new File("/tmp/dummy");
    int bufferSize = 6;
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, file, bufferSize);
    byte[] data = new byte[6];

    // Act
    stream.write(data);

    // Assert
    verify(checker, times(1)).checkDiskSpace(file, 6, bufferSize);
    verify(out).write(data, 0, 6);
  }

  @Test
  @DisplayName("write_whenLargeSingleWrite_callsCheckerOnceWithToWriteLength")
  void write_whenLargeSingleWrite_callsCheckerOnceWithToWriteLength() throws IOException {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    when(checker.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    File file = new File("/tmp/file");
    int bufferSize = 10;
    byte[] data = new byte[25];
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, file, bufferSize);

    // Act
    stream.write(data);

    // Assert
    verify(checker, times(1)).checkDiskSpace(file, 25, bufferSize);
    verify(out).write(data, 0, 25);
  }

  @Test
  @DisplayName("write_whenCheckerReturnsFalse_throwsAndDoesNotWrite")
  void write_whenCheckerReturnsFalse_throwsAndDoesNotWrite() throws IOException {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    when(checker.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(false);
    File file = new File("/tmp/file");
    int bufferSize = 4;
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, file, bufferSize);

    byte[] small = new byte[3]; // below threshold, shouldn't check
    byte[] trigger = new byte[2]; // this writing crosses threshold and should throw

    // Act
    stream.write(small);

    // Assert (first write)
    verifyNoInteractions(checker); // no check yet
    verify(out).write(small, 0, 3);

    // Act & Assert (second write triggers failure before writing to 'out')
    InsufficientDiskSpaceException ex =
        assertThrows(InsufficientDiskSpaceException.class, () -> stream.write(trigger));
    assertNotNull(ex);

    // The failing chunk must not be written to the underlying stream
    verify(out, never()).write(same(trigger), anyInt(), anyInt());
    // And the checker must have been called once with the second chunk's length
    verify(checker, times(1)).checkDiskSpace(file, 2, bufferSize);
  }

  @Test
  @DisplayName("writeInt_whenBufferIsOne_callsCheckerAndWritesOneByte")
  void writeInt_whenBufferIsOne_callsCheckerAndWritesOneByte() throws IOException {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    when(checker.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    File file = new File("/tmp/any");
    int bufferSize = 1;
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, file, bufferSize);

    // Act
    stream.write(42);

    // Assert
    ArgumentCaptor<byte[]> captor = ArgumentCaptor.forClass(byte[].class);
    verify(checker).checkDiskSpace(file, 1, bufferSize);
    ArgumentCaptor<Integer> offCap = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Integer> lenCap = ArgumentCaptor.forClass(Integer.class);
    verify(out).write(captor.capture(), offCap.capture(), lenCap.capture());
    byte[] written = captor.getValue();
    assertThat(written.length, equalTo(1));
    assertThat(written[0], equalTo((byte) 42));
    assertThat(offCap.getValue(), equalTo(0));
    assertThat(lenCap.getValue(), equalTo(1));
  }

  @Test
  @DisplayName("write_withZeroLength_callsOutButDoesNotCheck")
  void write_withZeroLength_callsOutButDoesNotCheck() throws IOException {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    File file = new File("/tmp/zero");
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, file, 8);
    byte[] empty = new byte[0];

    // Act
    stream.write(empty);

    // Assert
    verifyNoInteractions(checker);
    verify(out).write(empty, 0, 0);
  }

  @Test
  @DisplayName("write_withNullBuffer_throwsNPE")
  @SuppressWarnings("DataFlowIssue")
  void write_withNullBuffer_throwsNPE() {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, null, 8);

    // Act & Assert
    assertThrows(NullPointerException.class, () -> stream.write(null));
  }

  @ParameterizedTest(name = "buffer={0}: sequence triggers {1} checks")
  @MethodSource("seqProvider")
  @DisplayName("write_whenSequentialThresholds_checkCalledExpectedTimes")
  void write_whenSequentialThresholds_checkCalledExpectedTimes(int bufferSize, int expectedChecks)
      throws IOException {
    // Arrange
    OutputStream out = mock(OutputStream.class);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    when(checker.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    DiskSpaceCheckingOutputStream stream = newStream(out, checker, new File("/tmp/x"), bufferSize);

    // Writes: 5, 6, 4, 1
    // With buffer=10, checks on 6 and 4 => 2 checks
    // With buffer=5, checks on 5 (first), 6, 4, 1 => 3 checks (first write = exactly 5)
    // With buffer=20, checks on 6 (5+6 >=20? no), after adding 4: 5+6+4 >=20? no, +1: 5+6+4+1=16<20
    // => 0 checks
    // But due to algorithm (checks based on lastChecked before the chunk), calculations:
    // We'll assert via invocation count, not recompute here.
    int[] writes = new int[] {5, 6, 4, 1};

    // Act
    for (int w : writes) stream.write(new byte[w]);

    // Assert
    ArgumentCaptor<Integer> bufSizeCap = ArgumentCaptor.forClass(Integer.class);
    verify(checker, times(expectedChecks)).checkDiskSpace(any(), anyInt(), bufSizeCap.capture());
    for (Integer v : bufSizeCap.getAllValues()) {
      assertThat(v, equalTo(bufferSize));
    }
  }

  static Stream<Arguments> seqProvider() {
    return Stream.of(
        Arguments.of(10, 2), // threshold crossed by 6 and later by 4
        Arguments.of(5, 4),
        Arguments.of(20, 0));
  }

  @Nested
  class OffsetWrite {
    @Test
    @DisplayName("write_withOffset_writesExactRangeToOut")
    void write_withOffset_writesExactRangeToOut() throws IOException {
      // Arrange
      OutputStream out = mock(OutputStream.class);
      DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
      when(checker.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
      DiskSpaceCheckingOutputStream stream = newStream(out, checker, new File("/tmp/y"), 2);

      byte[] buf = new byte[] {10, 20, 30, 40, 50};

      // Act
      stream.write(buf, 1, 3); // [20,30,40]

      // Assert
      ArgumentCaptor<Integer> toWriteCap = ArgumentCaptor.forClass(Integer.class);
      ArgumentCaptor<Integer> bufSizeCap = ArgumentCaptor.forClass(Integer.class);
      verify(checker, times(1)).checkDiskSpace(any(), toWriteCap.capture(), bufSizeCap.capture());
      assertThat(toWriteCap.getValue(), equalTo(3));
      assertThat(bufSizeCap.getValue(), equalTo(2));
      verify(out).write(buf, 1, 3);
    }
  }
}
