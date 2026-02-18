package network.crypta.client.filter;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FlacPacketTest {

  // ---------- Helpers ----------

  private static int headerInt(boolean last, int blockType, int length) {
    int lastBit = last ? 1 : 0;
    return (lastBit << 31) | (blockType << 24) | (length & 0x00FF_FFFF);
  }

  private static int extractHeaderInt(byte[] array) {
    return ByteBuffer.wrap(array).getInt(0);
  }

  private static int extractBlockType(byte[] array) {
    int hdr = extractHeaderInt(array);
    return (hdr & 0x7F00_0000) >>> 24;
  }

  private static Arguments map(int rawType, FlacMetadataBlock.BlockType expected) {
    return Arguments.of(rawType, expected);
  }

  private static Stream<Arguments> blockTypeMapping() {
    return Stream.of(
        map(0, FlacMetadataBlock.BlockType.STREAMINFO),
        map(1, FlacMetadataBlock.BlockType.PADDING),
        map(2, FlacMetadataBlock.BlockType.APPLICATION),
        map(3, FlacMetadataBlock.BlockType.SEEKTABLE),
        map(4, FlacMetadataBlock.BlockType.VORBIS_COMMENT),
        map(5, FlacMetadataBlock.BlockType.CUESHEET),
        map(6, FlacMetadataBlock.BlockType.PICTURE),
        map(7, FlacMetadataBlock.BlockType.UNKNOWN),
        map(127, FlacMetadataBlock.BlockType.INVALID));
  }

  private static int expectedTypeValue(FlacMetadataBlock.BlockType t) {
    return switch (t) {
      case STREAMINFO -> 0;
      case PADDING -> 1;
      case APPLICATION -> 2;
      case SEEKTABLE -> 3;
      case VORBIS_COMMENT -> 4;
      case CUESHEET -> 5;
      case PICTURE -> 6;
      default -> -1; // for UNKNOWN/INVALID we don't expect setter to change header
    };
  }

  private static boolean objectEquals(Object left, Object right) {
    return left.equals(right);
  }

  // ---------- Tests: FlacMetadataBlock construction & array ----------

  @Test
  @DisplayName("toArray_whenHeaderAndPayloadMatch_expectHeaderPrependedAndSamePayload")
  void toArray_whenHeaderAndPayloadMatch_expectHeaderPrependedAndSamePayload() {
    int len = 5;
    byte[] payload = new byte[] {1, 2, 3, 4, 5};
    int hdr = headerInt(false, 0, len);

    FlacMetadataBlock block = new FlacMetadataBlock(hdr, payload);

    byte[] arr = block.toArray();

    assertNotNull(arr);
    assertEquals(4 + len, arr.length);
    assertEquals(hdr, extractHeaderInt(arr));
    byte[] payloadPart = new byte[len];
    System.arraycopy(arr, 4, payloadPart, 0, len);
    assertArrayEquals(payload, payloadPart);

    assertFalse(block.isLastMetadataBlock());
    assertEquals(FlacMetadataBlock.BlockType.STREAMINFO, block.getMetadataBlockType());
    assertEquals(4 + len, block.getLength());
  }

  @Test
  @DisplayName("toArray_whenPayloadShorterThanHeaderLength_expectZeroPadding")
  void toArray_whenPayloadShorterThanHeaderLength_expectZeroPadding() {
    int headerLen = 8;
    byte[] payload = new byte[] {10, 11, 12, 13, 14};
    int hdr = headerInt(false, 1, headerLen); // PADDING
    FlacMetadataBlock block = new FlacMetadataBlock(hdr, payload);

    byte[] arr = block.toArray();
    assertEquals(4 + headerLen, arr.length);
    assertEquals(hdr, extractHeaderInt(arr));

    // First bytes after header must match payload
    byte[] actualPayload = new byte[payload.length];
    System.arraycopy(arr, 4, actualPayload, 0, payload.length);
    assertArrayEquals(payload, actualPayload);

    // Remaining bytes should be zero-filled
    for (int i = 4 + payload.length; i < arr.length; i++) {
      assertEquals(0, arr[i], "Expected zero padding at index " + i);
    }
  }

  @Test
  @DisplayName("toArray_whenPayloadLongerThanHeaderLength_expectBufferOverflowException")
  void toArray_whenPayloadLongerThanHeaderLength_expectBufferOverflowException() {
    int headerLen = 4;
    byte[] payload = new byte[] {1, 2, 3, 4, 5};
    int hdr = headerInt(false, 2, headerLen); // APPLICATION
    FlacMetadataBlock block = new FlacMetadataBlock(hdr, payload);

    assertThrows(BufferOverflowException.class, block::toArray);
  }

  @Test
  @DisplayName("toArray_whenPayloadNull_expectNullPointerException")
  void toArray_whenPayloadNull_expectNullPointerException() {
    int hdr = headerInt(false, 3, 0);
    FlacMetadataBlock block = new FlacMetadataBlock(hdr, null);

    assertThrows(NullPointerException.class, block::toArray);
  }

  // ---------- Tests: Block type mapping ----------

  @ParameterizedTest(name = "rawType={0} -> {1}")
  @MethodSource("blockTypeMapping")
  void getMetadataBlockType_whenHeaderContainsType_expectMappedEnum(
      int rawType, FlacMetadataBlock.BlockType expected) {
    int hdr = headerInt(false, rawType, 0);
    FlacMetadataBlock block = new FlacMetadataBlock(hdr, new byte[0]);
    assertEquals(expected, block.getMetadataBlockType());
  }

  @ParameterizedTest
  @EnumSource(
      value = FlacMetadataBlock.BlockType.class,
      names = {
        "STREAMINFO",
        "PADDING",
        "APPLICATION",
        "SEEKTABLE",
        "VORBIS_COMMENT",
        "CUESHEET",
        "PICTURE"
      })
  void setMetadataBlockType_whenValidType_expectHeaderUpdated(FlacMetadataBlock.BlockType type) {
    int hdr = headerInt(false, 7, 0); // start as UNKNOWN
    FlacMetadataBlock block = new FlacMetadataBlock(hdr, new byte[0]);

    block.setMetadataBlockType(type);

    assertEquals(type, block.getMetadataBlockType());
    byte[] arr = block.toArray();
    int rawType = extractBlockType(arr);
    assertEquals(expectedTypeValue(type), rawType);
  }

  @Test
  void isLastMetadataBlock_whenFlagSet_expectTrue() {
    int hdr = headerInt(true, 0, 0);
    FlacMetadataBlock block = new FlacMetadataBlock(hdr, new byte[0]);
    assertTrue(block.isLastMetadataBlock());
  }

  @Test
  void isLastMetadataBlock_whenFlagNotSet_expectFalse() {
    int hdr = headerInt(false, 0, 0);
    FlacMetadataBlock block = new FlacMetadataBlock(hdr, new byte[0]);
    assertFalse(block.isLastMetadataBlock());
  }

  @Test
  void getHeader_whenMutatedCopy_expectOriginalUnaffected() {
    int len = 3;
    int hdr = headerInt(true, 6, len); // last + PICTURE
    byte[] payload = new byte[] {42, 43, 44};
    FlacMetadataBlock block = new FlacMetadataBlock(hdr, payload);

    FlacMetadataBlock.FlacMetadataBlockHeader copy = block.getHeader();
    assertEquals(hdr, copy.toInt());

    // Mutate the returned header copy
    copy.lastMetadataBlock = false;
    copy.blockType = 0; // STREAMINFO
    copy.length = 12345;

    // Original block should keep original header values
    byte[] arr = block.toArray();
    assertEquals(hdr, extractHeaderInt(arr));
  }

  // ---------- Tests: FlacFrame & equality/hashCode semantics ----------

  @Test
  void flacFrame_toArray_returnsSameArrayReference() {
    byte[] payload = new byte[] {9, 8, 7};
    FlacFrame frame = new FlacFrame(payload);
    assertSame(payload, frame.toArray());
  }

  @Test
  @SuppressWarnings("UnnecessaryLocalVariable")
  void equalsAcrossSubclasses_whenPayloadEqual_expectTrueAndSameHash() {
    byte[] payload = new byte[] {1, 2};
    FlacFrame frame = new FlacFrame(payload);
    FlacMetadataBlock block = new FlacMetadataBlock(headerInt(false, 0, payload.length), payload);

    Object frameObj = frame;
    Object blockObj = block;
    assertTrue(objectEquals(frameObj, blockObj));
    assertTrue(objectEquals(blockObj, frameObj));
    assertEquals(frame.hashCode(), block.hashCode());
  }

  @Test
  void equals_whenHeadersDifferButPayloadSame_expectTrue() {
    byte[] payload = new byte[] {5, 6};
    FlacMetadataBlock a = new FlacMetadataBlock(headerInt(false, 0, payload.length), payload);
    FlacMetadataBlock b = new FlacMetadataBlock(headerInt(false, 6, payload.length), payload);

    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenPayloadDiffers_expectFalse() {
    FlacFrame a = new FlacFrame(new byte[] {1});
    FlacFrame b = new FlacFrame(new byte[] {2});
    assertNotEquals(a, b);
    assertNotEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenNullPayloads_expectTrueAndZeroHash() {
    FlacFrame a = new FlacFrame(null);
    FlacFrame b = new FlacFrame(null);
    assertEquals(a, b);
    // Arrays.hashCode(null) == 0, but CodecPacket seeds the hash with 1 and multiplies by 31
    // before adding the array hash, resulting in 31 for null payloads.
    assertEquals(31, a.hashCode());
    assertEquals(a.hashCode(), b.hashCode());
  }
}
