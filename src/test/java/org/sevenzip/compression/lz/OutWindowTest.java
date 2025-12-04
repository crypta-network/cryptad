package org.sevenzip.compression.lz;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class OutWindowTest {

  @Test
  void create_whenCalled_setsWindowSizeAndResetsPositions() {
    OutWindow window = new OutWindow();

    window.create(4);

    assertNotNull(window.buffer);
    assertEquals(4, window.buffer.length);
    assertEquals(0, window.pos);
    assertEquals(0, window.streamPos);
  }

  @Test
  void putByte_whenWindowFills_flushesToStreamAndResetsPositions() throws IOException {
    OutWindow window = new OutWindow();
    window.create(2);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    window.setStream(output);

    window.putByte((byte) 0x11);
    window.putByte((byte) 0x22); // triggers flush because windowSize reached

    assertArrayEquals(new byte[] {(byte) 0x11, (byte) 0x22}, output.toByteArray());
    assertEquals(0, window.pos);
    assertEquals(0, window.streamPos);
  }

  @Test
  void flush_whenNoPendingData_writesNothing() throws IOException {
    OutWindow window = new OutWindow();
    window.create(3);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    window.setStream(output);

    window.flush();

    assertEquals(0, output.size());
    assertEquals(0, window.pos);
    assertEquals(0, window.streamPos);
  }

  @Test
  void releaseStream_whenPendingData_flushesAndClearsStream() throws IOException {
    OutWindow window = new OutWindow();
    window.create(3);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    window.setStream(output);

    window.putByte((byte) 'x');
    window.releaseStream();

    assertArrayEquals(new byte[] {(byte) 'x'}, output.toByteArray());
    assertNull(window.stream);
  }

  @Test
  void copyBlock_whenDistanceWrapsAround_repeatsDataCorrectly() throws IOException {
    OutWindow window = new OutWindow();
    window.create(5);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    window.setStream(output);

    window.putByte((byte) 1);
    window.putByte((byte) 2);
    window.putByte((byte) 3);
    window.putByte((byte) 4);
    window.putByte((byte) 5); // triggers flush, resets pos to 0

    window.copyBlock(1, 3); // wraps source position to index 3
    window.flush();

    assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 4, 5, 4}, output.toByteArray());
    assertEquals(3, window.pos);
    assertEquals(3, window.streamPos);
  }

  @Test
  void getByte_whenDistanceWraps_returnsExpectedByte() throws IOException {
    OutWindow window = new OutWindow();
    window.create(3);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    window.setStream(output);

    window.putByte((byte) 10);
    window.putByte((byte) 11);
    window.putByte((byte) 12); // triggers flush, pos resets to 0

    byte value = window.getByte(1);

    assertEquals(11, value);
    assertEquals(0, window.pos);
    assertEquals(0, window.streamPos);
  }
}
