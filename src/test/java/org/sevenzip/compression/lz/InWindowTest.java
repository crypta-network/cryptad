package org.sevenzip.compression.lz;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class InWindowTest {

  @Test
  void create_setsBufferSizeAndSafePosition() {
    InWindow window = new InWindow();

    window.create(2, 3, 4);

    assertEquals(2, window.keepSizeBefore);
    assertEquals(3, window.keepSizeAfter);
    assertNotNull(window.bufferBase);
    assertEquals(9, window.bufferBase.length);
    assertEquals(6, window.pointerToLastSafePosition);
  }

  @Test
  void init_whenStreamHasData_readsInitialBlockAndSetsLimits() throws Exception {
    byte[] data = new byte[] {10, 20, 30, 40};
    InWindow window = prepareWindow(data, 1, 1, 2);

    assertEquals(0, window.pos);
    assertEquals(0, window.bufferOffset);
    assertEquals(data.length, window.streamPos);
    assertEquals(window.streamPos - window.keepSizeAfter, window.posLimit);
    assertFalse(window.streamEndWasReached);
    assertArrayEquals(
        data,
        Arrays.copyOfRange(
            window.bufferBase, window.bufferOffset, window.bufferOffset + window.streamPos));
  }

  @Test
  void movePos_whenCrossingPosLimit_loadsAdditionalBytes() throws Exception {
    byte[] data = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    InWindow window = prepareWindow(data, 1, 2, 3);
    int initialStreamPos = window.streamPos;

    int safetyCounter = 0;
    while (window.streamPos == initialStreamPos && safetyCounter < data.length * 2) {
      window.movePos();
      safetyCounter++;
    }

    assertTrue(window.streamPos > initialStreamPos, "Expected additional bytes to be read");
    assertEquals(data.length - window.pos, window.getNumAvailableBytes());
  }

  @Test
  void movePos_whenBufferNearLimit_preservesCurrentByteAfterMoveBlock() throws Exception {
    byte[] data = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    InWindow window = prepareWindow(data, 2, 2, 2);

    while (window.pos < 5) {
      window.movePos();
    }

    assertEquals(5, window.pos);
    assertEquals(5, window.getIndexByte(0));
  }

  @Test
  void getMatchLen_whenStreamEnded_clampsLimitAndReturnsMatchLength() throws Exception {
    byte[] data = "abcabc".getBytes();
    InWindow window = prepareWindow(data, 3, 1, 3);

    for (int i = 0; i < 3; i++) {
      window.movePos();
    }

    int matchLength = window.getMatchLen(0, 2, 10);

    assertTrue(window.streamEndWasReached);
    assertEquals(3, matchLength);
  }

  @Test
  void reduceOffsets_adjustsInternalPointersConsistently() {
    InWindow window = new InWindow();
    window.bufferOffset = 5;
    window.posLimit = 9;
    window.pos = 7;
    window.streamPos = 10;

    window.reduceOffsets(3);

    assertEquals(8, window.bufferOffset);
    assertEquals(6, window.posLimit);
    assertEquals(4, window.pos);
    assertEquals(7, window.streamPos);
  }

  private InWindow prepareWindow(byte[] data, int keepBefore, int keepAfter, int keepReserve)
      throws IOException {
    InWindow window = new InWindow();
    window.create(keepBefore, keepAfter, keepReserve);
    window.setStream(new ByteArrayInputStream(data));
    window.init();
    return window;
  }
}
