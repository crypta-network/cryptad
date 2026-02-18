package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.io.EOFException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class RAFInputStreamTest {

  @Test
  void read_whenDataAvailable_returnsUnsignedByteAndAdvancesPosition() throws Exception {
    byte[] data = new byte[] {(byte) 0xFF};
    RAF raf = mock(RAF.class);
    doAnswer(invocation -> fillFromArray(invocation.getArgument(0), invocation, data))
        .when(raf)
        .seekAndRead(anyLong(), any(byte[].class), anyInt(), anyInt());

    try (RAFInputStream stream = new RAFInputStream(raf)) {
      int first = stream.read();
      int second = stream.read();

      assertEquals(255, first);
      assertEquals(-1, second);

      ArgumentCaptor<Long> positions = ArgumentCaptor.forClass(Long.class);
      verify(raf, org.mockito.Mockito.times(2))
          .seekAndRead(positions.capture(), any(byte[].class), anyInt(), anyInt());
      assertEquals(0L, positions.getAllValues().get(0));
      assertEquals(1L, positions.getAllValues().get(1));
      verifyNoMoreInteractions(raf);
    }
  }

  @Test
  void read_whenUnderlyingSignalsEof_doesNotAdvancePosition() throws Exception {
    byte[] data = new byte[] {1, 2};
    RAF raf = mock(RAF.class);
    doAnswer(invocation -> fillFromArray(invocation.getArgument(0), invocation, data))
        .when(raf)
        .seekAndRead(anyLong(), any(byte[].class), anyInt(), anyInt());

    try (RAFInputStream stream = new RAFInputStream(raf)) {
      byte[] buffer = new byte[2];
      int read = stream.read(buffer, 0, 2);
      assertEquals(2, read);
      assertEquals(-1, stream.read(buffer, 0, 1));
      assertEquals(-1, stream.read(buffer, 0, 1));

      ArgumentCaptor<Long> positions = ArgumentCaptor.forClass(Long.class);
      verify(raf, org.mockito.Mockito.times(3))
          .seekAndRead(positions.capture(), any(byte[].class), anyInt(), anyInt());
      assertEquals(0L, positions.getAllValues().get(0));
      assertEquals(2L, positions.getAllValues().get(1));
      assertEquals(2L, positions.getAllValues().get(2));
      verifyNoMoreInteractions(raf);
    }
  }

  @Test
  void read_afterClose_throwsEOFException() throws Exception {
    RAF raf = mock(RAF.class);
    RAFInputStream stream = new RAFInputStream(raf);
    stream.close();

    assertThrows(EOFException.class, () -> stream.read(new byte[1], 0, 1));
    verifyNoMoreInteractions(raf);
  }

  @Test
  void skip_whenWithinFileLength_advancesPositionAndReturnsSkippedAmount() throws Exception {
    RAF raf = mock(RAF.class);
    doAnswer(
            invocation -> {
              byte[] buffer = invocation.getArgument(1);
              int offset = invocation.getArgument(2);
              buffer[offset] = 0x01;
              return 1;
            })
        .when(raf)
        .seekAndRead(anyLong(), any(byte[].class), anyInt(), anyInt());
    doAnswer(_ -> 10L).when(raf).length();

    try (RAFInputStream stream = new RAFInputStream(raf)) {
      long firstSkip = stream.skip(4);
      long secondSkip = stream.skip(3);
      int value = stream.read();

      assertEquals(4L, firstSkip);
      assertEquals(3L, secondSkip);
      assertEquals(1, value);

      ArgumentCaptor<Long> positions = ArgumentCaptor.forClass(Long.class);
      verify(raf, org.mockito.Mockito.times(2)).length();
      verify(raf).seekAndRead(positions.capture(), any(byte[].class), anyInt(), anyInt());
      assertEquals(7L, positions.getValue());
      verifyNoMoreInteractions(raf);
    }
  }

  @Test
  void skip_whenRequestExceedsFileLength_clampsToRemainingBytes() throws Exception {
    RAF raf = mock(RAF.class);
    org.mockito.Mockito.when(raf.length()).thenReturn(5L);
    doAnswer(_ -> -1).when(raf).seekAndRead(anyLong(), any(byte[].class), anyInt(), anyInt());

    try (RAFInputStream stream = new RAFInputStream(raf)) {
      long skipped = stream.skip(10);
      long skippedAgain = stream.skip(1);
      int result = stream.read();

      assertEquals(5L, skipped);
      assertEquals(0L, skippedAgain);
      assertEquals(-1, result);

      ArgumentCaptor<Long> positions = ArgumentCaptor.forClass(Long.class);
      verify(raf, org.mockito.Mockito.times(2)).length();
      verify(raf).seekAndRead(positions.capture(), any(byte[].class), anyInt(), anyInt());
      assertEquals(5L, positions.getValue());
      verifyNoMoreInteractions(raf);
    }
  }

  @Test
  void skip_whenNegative_doesNotChangePosition() throws Exception {
    RAF raf = mock(RAF.class);
    doAnswer(
            invocation -> {
              byte[] buffer = invocation.getArgument(1);
              int offset = invocation.getArgument(2);
              buffer[offset] = 0x01;
              return 1;
            })
        .when(raf)
        .seekAndRead(anyLong(), any(byte[].class), anyInt(), anyInt());

    try (RAFInputStream stream = new RAFInputStream(raf)) {
      //noinspection ConstantValue
      long skipped = stream.skip(-3);
      int value = stream.read();

      assertEquals(0L, skipped);
      assertEquals(1, value);

      ArgumentCaptor<Long> positions = ArgumentCaptor.forClass(Long.class);
      verify(raf).seekAndRead(positions.capture(), any(byte[].class), anyInt(), anyInt());
      assertEquals(0L, positions.getValue());
      verifyNoMoreInteractions(raf);
    }
  }

  private Object fillFromArray(
      long requestedPos, org.mockito.invocation.InvocationOnMock inv, byte[] data) {
    byte[] buffer = inv.getArgument(1);
    int offset = inv.getArgument(2);
    int length = inv.getArgument(3);
    if (requestedPos >= data.length) {
      return -1;
    }
    int toRead = Math.min(length, data.length - (int) requestedPos);
    System.arraycopy(data, (int) requestedPos, buffer, offset, toRead);
    return toRead;
  }
}
