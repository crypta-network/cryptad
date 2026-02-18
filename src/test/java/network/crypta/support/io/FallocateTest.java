package network.crypta.support.io;

import com.sun.jna.Platform;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link Fallocate} in AAA style. These tests avoid native calls by providing a
 * mocked {@link FileChannel} which forces the fallback path regardless of OS (descriptor becomes
 * 0). OS-specific expectations are guarded with assumptions.
 */
class FallocateTest {

  // region fromOffset()

  @ParameterizedTest
  @DisplayName("fromOffset_whenOutOfRange_expectIllegalArgumentException")
  @ValueSource(longs = {-1L, 11L})
  void fromOffset_whenOutOfRange_expectIllegalArgumentException(long badOffset) {
    // Arrange
    FileChannel channel = mock(FileChannel.class);
    Fallocate f = Fallocate.forChannel(channel, 10L);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> f.fromOffset(badOffset));
  }

  @ParameterizedTest
  @DisplayName("fromOffset_whenWithinBounds_expectSameInstance")
  @ValueSource(longs = {0L, 10L})
  void fromOffset_whenWithinBounds_expectSameInstance(long okOffset) {
    // Arrange
    FileChannel channel = mock(FileChannel.class);
    Fallocate f = Fallocate.forChannel(channel, 10L);

    // Act
    Fallocate result = f.fromOffset(okOffset);

    // Assert
    assertSame(f, result);
  }

  // endregion

  // region execute() -> legacy path (fd <= 2)

  @Test
  void execute_whenUnsupportedAndNonWindows_writesExactRemainingFromOffset() throws IOException {
    // Arrange
    assumeFalse(Platform.isWindows(), "This test targets the non-Windows legacy path.");
    FileChannel channel = mock(FileChannel.class);
    // Make write() return the full buffer size in one go
    when(channel.write(any(ByteBuffer.class), anyLong()))
        .thenAnswer(
            inv -> {
              ByteBuffer buf = inv.getArgument(0);
              return buf.remaining();
            });

    long finalSize = 10L;
    long offset = 7L;
    Fallocate f = Fallocate.forChannel(channel, finalSize).fromOffset(offset);

    // Act
    f.execute();

    // Assert
    ArgumentCaptor<ByteBuffer> bufCap = ArgumentCaptor.forClass(ByteBuffer.class);
    ArgumentCaptor<Long> posCap = ArgumentCaptor.forClass(Long.class);
    verify(channel, times(1)).write(bufCap.capture(), posCap.capture());
    assertEquals(3, bufCap.getValue().remaining());
    assertEquals(offset, posCap.getValue());
  }

  @Test
  void execute_whenUnsupportedAndNonWindowsAndPartialWrites_retriesUntilDone() throws IOException {
    // Arrange
    assumeFalse(Platform.isWindows(), "This test targets the non-Windows legacy path.");
    FileChannel channel = mock(FileChannel.class);
    // Simulate partial writes of 1 byte each time
    when(channel.write(any(ByteBuffer.class), anyLong())).thenReturn(1, 1, 1);

    long finalSize = 10L;
    long offset = 7L;
    Fallocate f = Fallocate.forChannel(channel, finalSize).fromOffset(offset);

    // Act
    f.execute();

    // Assert
    ArgumentCaptor<Long> posCap = ArgumentCaptor.forClass(Long.class);
    verify(channel, times(3)).write(any(ByteBuffer.class), posCap.capture());
    assertEquals(3, posCap.getAllValues().size());
    assertEquals(7L, posCap.getAllValues().get(0));
    assertEquals(8L, posCap.getAllValues().get(1));
    assertEquals(9L, posCap.getAllValues().get(2));
  }

  @Test
  void execute_whenUnsupportedAndWindows_writesSingleByteAtEnd() throws IOException {
    // Arrange
    assumeTrue(Platform.isWindows(), "This test targets the Windows legacy path.");
    FileChannel channel = mock(FileChannel.class);
    when(channel.write(any(ByteBuffer.class), anyLong())).thenReturn(1);

    long finalSize = 10L;
    long offset = 7L; // ignored on a Windows path
    Fallocate f = Fallocate.forChannel(channel, finalSize).fromOffset(offset);

    // Act
    f.execute();

    // Assert
    ArgumentCaptor<ByteBuffer> bufCap = ArgumentCaptor.forClass(ByteBuffer.class);
    ArgumentCaptor<Long> posCap = ArgumentCaptor.forClass(Long.class);
    verify(channel, times(1)).write(bufCap.capture(), posCap.capture());
    assertEquals(1, bufCap.getValue().remaining());
    assertEquals(finalSize - 1, posCap.getValue());
  }

  @Test
  void execute_whenOffsetEqualsFinalSize_expectNoWriteOnNonWindowsOrSingleByteOnWindows()
      throws IOException {
    // Arrange
    FileChannel channel = mock(FileChannel.class);
    long finalSize = 10L;
    long offset = 10L; // zero remaining
    Fallocate f = Fallocate.forChannel(channel, finalSize).fromOffset(offset);

    // Act
    f.execute();

    // Assert
    if (Platform.isWindows()) {
      // On Windows, legacy writes a single byte at finalSize-1
      verify(channel, times(1)).write(any(ByteBuffer.class), eq(finalSize - 1));
    } else {
      // On non-Windows, zero remaining => no writes
      verify(channel, never()).write(any(ByteBuffer.class), anyLong());
    }
  }

  // endregion

  // region forChannel(FileDescriptor) null/reflective fallback

  @Test
  void execute_whenProvidedFileDescriptorIsNull_fallsBackToLegacy() throws IOException {
    // Arrange
    FileChannel channel = mock(FileChannel.class);
    when(channel.write(any(ByteBuffer.class), anyLong()))
        .thenAnswer(inv -> ((ByteBuffer) inv.getArgument(0)).remaining());

    long finalSize = 10L;
    long offset = 7L;
    Fallocate f = Fallocate.forChannel(channel, null, finalSize).fromOffset(offset);

    // Act
    f.execute();

    // Assert
    if (Platform.isWindows()) {
      verify(channel, times(1)).write(any(ByteBuffer.class), eq(finalSize - 1));
    } else {
      ArgumentCaptor<ByteBuffer> bufCap = ArgumentCaptor.forClass(ByteBuffer.class);
      ArgumentCaptor<Long> posCap = ArgumentCaptor.forClass(Long.class);
      verify(channel, times(1)).write(bufCap.capture(), posCap.capture());
      assertEquals(3, bufCap.getValue().remaining());
      assertEquals(offset, posCap.getValue());
    }
  }

  // endregion
}
