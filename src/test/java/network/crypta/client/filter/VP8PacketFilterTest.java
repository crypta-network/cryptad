package network.crypta.client.filter;

import java.io.IOException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class VP8PacketFilterTest {

  // Helper to build a 6-byte VP8 frame header
  private static byte[] header(int b0, int b1, int b2, int b3, int b4, int b5) {
    return new byte[] {(byte) b0, (byte) b1, (byte) b2, (byte) b3, (byte) b4, (byte) b5};
  }

  @Test
  void parse_whenWebPKeyframeValid_returnsNormally() {
    // Arrange: keyframe (bit0=0), not experimental (bit3=0), is_shown (bit4=1),
    // sizeInHeader=0, valid sync code (0x9d 0x01 0x2a)
    byte[] buf = header(0x10, 0x00, 0x00, 0x9d, 0x01, 0x2a);
    VP8PacketFilter filter = new VP8PacketFilter(true);

    // Act/Assert: size must be > 10 for keyframes when sizeInHeader = 0
    assertDoesNotThrow(() -> filter.parse(buf, 11));
  }

  @Test
  void parse_whenNonWebPNonKeyframe_returnsNormally() {
    // Arrange: non-keyframe (bit0=1), not experimental, is_shown can be 0 for non-WebP
    byte[] buf = header(0x01, 0x00, 0x00, 0x00, 0x00, 0x00);
    VP8PacketFilter filter = new VP8PacketFilter(false);

    // Act/Assert: size must be > 3 for non-keyframes when sizeInHeader = 0
    assertDoesNotThrow(() -> filter.parse(buf, 4));
  }

  @Test
  void parse_whenWebPAndNotKeyframe_throwsDataFilterException() {
    // Arrange: non-keyframe (bit0=1) and WebP. Use non-zero b1/b2 to
    // exercise those parameters as well (sizeInHeader increases but
    // the early non-keyframe/WebP check throws before size is used).
    byte[] buf = header(0x01, 0x12, 0x34, 0x00, 0x00, 0x00);
    VP8PacketFilter filter = new VP8PacketFilter(true);

    // Act
    DataFilterException ex = assertThrows(DataFilterException.class, () -> filter.parse(buf, 4));

    // Assert
    assertEquals("VP8 decode error", ex.getRawTitle());
    assertEquals("Not a keyframe in WebP image", ex.getMessage());
  }

  @Test
  void parse_whenExperimentalBitSet_throwsDataFilterException() {
    // Arrange: keyframe (bit0=0), experimental bit (bit3=1), non-WebP
    byte[] buf = header(0x08, 0x00, 0x00, 0x00, 0x00, 0x00);
    VP8PacketFilter filter = new VP8PacketFilter(false);

    // Act
    DataFilterException ex = assertThrows(DataFilterException.class, () -> filter.parse(buf, 11));

    // Assert
    assertEquals("VP8 decode error", ex.getRawTitle());
    assertEquals("VP8 frame version is unsupported", ex.getMessage());
  }

  @Test
  void parse_whenWebPAndShownFlagMissing_throwsDataFilterException() {
    // Arrange: keyframe (bit0=0), not experimental, is_shown=0, WebP
    byte[] buf = header(0x00, 0x00, 0x00, 0x9d, 0x01, 0x2a);
    VP8PacketFilter filter = new VP8PacketFilter(true);

    // Act
    DataFilterException ex = assertThrows(DataFilterException.class, () -> filter.parse(buf, 11));

    // Assert
    assertEquals("VP8 decode error", ex.getRawTitle());
    assertEquals("WebP frame contains an image without is_shown flag", ex.getMessage());
  }

  @Test
  void parse_whenSizeTooSmall_throwsDataFilterException() {
    // Arrange: keyframe, not experimental, is_shown=1 (WebP), sizeInHeader=0
    byte[] buf = header(0x10, 0x00, 0x00, 0x9d, 0x01, 0x2a);
    VP8PacketFilter filter = new VP8PacketFilter(true);

    // Act: size equal to threshold (10) must fail for keyframes when sizeInHeader=0
    DataFilterException ex = assertThrows(DataFilterException.class, () -> filter.parse(buf, 10));

    // Assert
    assertEquals("VP8 decode error", ex.getRawTitle());
    assertEquals("VP8 frame size is invalid", ex.getMessage());
  }

  @Test
  void parse_whenKeyframeSyncCodeInvalid_throwsDataFilterException() {
    // Arrange: keyframe, not experimental, is_shown=1 (WebP), but bad sync code
    byte[] buf = header(0x10, 0x00, 0x00, 0x00, 0x00, 0x00);
    VP8PacketFilter filter = new VP8PacketFilter(true);

    // Act: size > 10 to pass size check
    DataFilterException ex = assertThrows(DataFilterException.class, () -> filter.parse(buf, 11));

    // Assert
    assertEquals("VP8 decode error", ex.getRawTitle());
    assertEquals("VP8 frame sync code is invalid", ex.getMessage());
  }

  @Test
  void parse_whenBufferShorterThanHeader_throwsIOException() {
    // Arrange: only 5 bytes available, DataInputStream will hit EOF when reading 6th byte
    byte[] buf = new byte[] {0x10, 0x00, 0x00, 0x00, 0x00};
    VP8PacketFilter filter = new VP8PacketFilter(false);

    // Act/Assert
    assertThrows(IOException.class, () -> filter.parse(buf, 11));
  }
}
