package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.EOFException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RAFOutputStreamTest {

  @Mock private RAF raf;

  private RAFOutputStream outputStream;

  @BeforeEach
  void setUp() {
    outputStream = new RAFOutputStream(raf);
  }

  @Test
  void write_whenSingleByte_expectDelegatesAndAdvancesPosition() throws Exception {
    ArgumentCaptor<byte[]> captor = ArgumentCaptor.forClass(byte[].class);

    outputStream.write(0xAB);

    verify(raf).seekAndWrite(eq(0L), captor.capture(), eq(0), eq(1));
    byte[] written = captor.getValue();
    assertEquals(1, written.length);
    assertEquals((byte) 0xAB, written[0]);
  }

  @Test
  void write_whenCalledMultipleTimes_expectPositionAccumulates() throws Exception {
    byte[] first = new byte[] {1, 2, 3};
    byte[] second = new byte[] {4, 5};

    outputStream.write(first, 0, first.length);
    outputStream.write(second, 0, second.length);

    InOrder order = inOrder(raf);
    order.verify(raf).seekAndWrite(0L, first, 0, first.length);
    order.verify(raf).seekAndWrite(3L, second, 0, second.length);
  }

  @Test
  void write_withOffsetAndLength_expectPassThroughParameters() throws Exception {
    byte[] buffer = new byte[] {9, 8, 7, 6};

    outputStream.write(buffer, 1, 2);

    verify(raf).seekAndWrite(0L, buffer, 1, 2);
  }

  @Test
  void write_afterClose_expectEOFExceptionAndNoRafInteraction() throws Exception {
    outputStream.close();

    assertThrows(EOFException.class, () -> outputStream.write(new byte[] {1}, 0, 1));

    verifyNoInteractions(raf);
  }
}
