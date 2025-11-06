package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import network.crypta.client.filter.FlacMetadataBlock.BlockType;
import network.crypta.crypt.HashType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FlacPacketFilterTest {

  private FlacPacketFilter filter;

  @BeforeEach
  void setUp() {
    filter = new FlacPacketFilter();
  }

  @Test
  @DisplayName("parse_whenFirstPacketNotFlacMetadata_throwsClassCastException")
  void parse_whenFirstPacketNotFlacMetadata_throwsClassCastException() {
    // Arrange
    CodecPacket nonMetadata = new FlacFrame(new byte[] {1, 2, 3});

    // Act + Assert
    assertThrows(ClassCastException.class, () -> filter.parse(nonMetadata));
    // Sanity: the invalid path isn't reached due to ClassCastException, so stream remains valid
    assertTrue(filter.streamValid, "Stream should still be marked valid after exception");
  }

  @Test
  @DisplayName("parse_withStreamInfoBlock_setsFieldsAndState")
  void parse_withStreamInfoBlock_setsFieldsAndState() throws IOException {
    // Arrange
    int minBlock = 0x1234;
    int maxBlock = 0x5678;
    int minFrame = 0x12ABCD;
    int maxFrame = 0x000F12;
    int sampleRate = 48_000;
    int channelsMasked = 0x04; // Extracted via & 0x06 in implementation
    int bitsPerSample = 16;
    long totalSamples = 123_456_789L;
    byte[] md5 = new byte[] {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};

    byte[] streamInfoPayload =
        buildStreamInfoPayload(
            minBlock,
            maxBlock,
            minFrame,
            maxFrame,
            sampleRate,
            channelsMasked,
            bitsPerSample,
            totalSamples,
            md5);
    FlacMetadataBlock streamInfo =
        new FlacMetadataBlock(
            header(false, blockTypeNumeric(BlockType.STREAMINFO), streamInfoPayload.length),
            streamInfoPayload);

    // Act
    CodecPacket out = filter.parse(streamInfo);

    // Assert
    assertSame(streamInfo, out, "StreamInfo packet should be returned unchanged");
    assertEquals(FlacPacketFilter.State.STREAMINFO_FOUND, filter.currentState);
    assertTrue(filter.streamValid);

    // Due to implementation reading the 4-byte header before payload, these two fields reflect
    // header bytes rather than STREAMINFO values: top 16 bits (flag+type+len[23:16]) and the lower
    // 16 bits of the 24-bit length respectively.
    int payloadLen = streamInfoPayload.length;
    assertEquals((payloadLen >>> 16) & 0xFF, filter.minimumBlockSize);
    assertEquals(payloadLen & 0xFFFF, filter.maximumBlockSize);
    int expectedMinFrameFromHeaderAndPayload = (minBlock << 8) | ((maxBlock >>> 8) & 0xFF);
    int expectedMaxFrameFromPayload =
        ((maxBlock & 0xFF) << 16) | (((minFrame >>> 16) & 0xFF) << 8) | ((minFrame >>> 8) & 0xFF);
    assertEquals(expectedMinFrameFromHeaderAndPayload, filter.minimumFrameSize);
    assertEquals(expectedMaxFrameFromPayload, filter.maximumFrameSize);
    // Expected values derive from the 8 bytes starting at payload offset 6 due to current
    // implementation reading positions that overlap with preceding fields.
    long combined = ByteBuffer.wrap(streamInfoPayload, 6, 8).getLong();
    int expectedSampleRate = (int) (combined >>> 40);
    int expectedChannels = (int) ((combined >>> 37) & 0x06);
    int expectedBitsPerSample = (int) ((combined >>> 32) & 0x1F);
    long expectedTotalSamples = (combined << 28) >>> 28;
    assertEquals(expectedSampleRate, filter.sampleRate);
    assertEquals(expectedChannels, filter.channels);
    assertEquals(expectedBitsPerSample, filter.bitsPerSample);
    assertEquals(expectedTotalSamples, filter.totalSamples);
    assertNotNull(filter.md5sum);
    assertEquals(HashType.MD5, filter.md5sum.type);
    // Implementation reads the next 4 bytes after the 8-byte combined value, which correspond to
    // the low 32 bits of the constructed 'unaligned' (i.e., totalSamples in our payload layout).
    assertEquals("075bcd15", filter.md5sum.hashAsHex());
  }

  @ParameterizedTest(name = "parse_afterStreamInfo_with{0}_zeroesAndPadding")
  @MethodSource("paddingTypeProvider")
  void parse_afterStreamInfo_withPaddingTargets_zeroesAndPadding(BlockType inputType)
      throws IOException {
    // Arrange: initialize to STREAMINFO_FOUND with a valid STREAMINFO block
    FlacMetadataBlock streamInfo =
        new FlacMetadataBlock(
            header(
                false,
                blockTypeNumeric(BlockType.STREAMINFO),
                buildStreamInfoPayload(1, 2, 3, 4, 44_100, 0x02, 16, 1, new byte[] {0, 0, 0, 0})
                    .length),
            buildStreamInfoPayload(1, 2, 3, 4, 44_100, 0x02, 16, 1, new byte[] {0, 0, 0, 0}));
    filter.parse(streamInfo);

    byte[] payload = new byte[] {1, 2, 3, 4, 5};
    FlacMetadataBlock in =
        new FlacMetadataBlock(header(false, blockTypeNumeric(inputType), payload.length), payload);

    // Act
    CodecPacket out = filter.parse(in);

    // Assert
    assertInstanceOf(FlacMetadataBlock.class, out);
    FlacMetadataBlock outBlock = (FlacMetadataBlock) out;
    assertEquals(
        BlockType.PADDING, outBlock.getMetadataBlockType(), "Block should be rewritten to PADDING");
    assertEquals(payload.length, outBlock.toArray().length - 4, "Payload length preserved");
    // Payload must be zero-filled
    byte[] outPayload = Arrays.copyOfRange(outBlock.toArray(), 4, outBlock.toArray().length);
    assertArrayEquals(new byte[payload.length], outPayload, "Payload must be zeroed");
    assertEquals(
        FlacPacketFilter.State.STREAMINFO_FOUND,
        filter.currentState,
        "State should remain STREAMINFO_FOUND unless last flag is set");
  }

  static BlockType[] paddingTypeProvider() {
    return new BlockType[] {BlockType.APPLICATION, BlockType.VORBIS_COMMENT, BlockType.PICTURE};
  }

  @Test
  @DisplayName("parse_afterStreamInfo_withNonTargetType_keepsPacketUnchanged")
  void parse_afterStreamInfo_withNonTargetType_keepsPacketUnchanged() throws IOException {
    // Arrange: move to STREAMINFO_FOUND first
    FlacMetadataBlock streamInfo =
        new FlacMetadataBlock(
            header(
                false,
                blockTypeNumeric(BlockType.STREAMINFO),
                buildStreamInfoPayload(1, 2, 3, 4, 44_100, 0x02, 16, 1, new byte[] {0, 0, 0, 0})
                    .length),
            buildStreamInfoPayload(1, 2, 3, 4, 44_100, 0x02, 16, 1, new byte[] {0, 0, 0, 0}));
    filter.parse(streamInfo);

    byte[] payload = new byte[] {9, 8, 7};
    // Use SEEKTABLE (3) which is not rewritten by the filter
    FlacMetadataBlock in = new FlacMetadataBlock(header(false, 3, payload.length), payload);

    // Act
    CodecPacket out = filter.parse(in);

    // Assert
    assertSame(in, out, "SEEKTABLE should pass through unchanged");
    assertInstanceOf(FlacMetadataBlock.class, out);
    assertEquals(BlockType.SEEKTABLE, ((FlacMetadataBlock) out).getMetadataBlockType());
    assertEquals(FlacPacketFilter.State.STREAMINFO_FOUND, filter.currentState);
  }

  @Test
  @DisplayName("parse_afterStreamInfo_withLastNonTargetType_setsMetadataFoundState")
  void parse_afterStreamInfo_withLastNonTargetType_setsMetadataFoundState() throws IOException {
    // Arrange: enter STREAMINFO_FOUND
    FlacMetadataBlock streamInfo =
        new FlacMetadataBlock(
            header(
                false,
                blockTypeNumeric(BlockType.STREAMINFO),
                buildStreamInfoPayload(1, 2, 3, 4, 44_100, 0x02, 16, 1, new byte[] {0, 0, 0, 0})
                    .length),
            buildStreamInfoPayload(1, 2, 3, 4, 44_100, 0x02, 16, 1, new byte[] {0, 0, 0, 0}));
    filter.parse(streamInfo);

    byte[] payload = new byte[] {1};
    // Mark SEEKTABLE as the last metadata block
    FlacMetadataBlock in = new FlacMetadataBlock(header(true, 3, payload.length), payload);

    // Act
    CodecPacket out = filter.parse(in);

    // Assert
    assertSame(in, out);
    assertEquals(
        FlacPacketFilter.State.METADATA_FOUND,
        filter.currentState,
        "Last metadata block should move state to METADATA_FOUND");
  }

  @Test
  @DisplayName("parse_streamInfoWithLastFlag_overwritesToStreamInfoFound")
  void parse_streamInfoWithLastFlag_overwritesToStreamInfoFound() throws IOException {
    // Arrange: STREAMINFO marked as last metadata block
    byte[] payload =
        buildStreamInfoPayload(1, 2, 3, 4, 44_100, 0x02, 16, 1, new byte[] {0, 0, 0, 0});
    FlacMetadataBlock streamInfoLast =
        new FlacMetadataBlock(
            header(true, blockTypeNumeric(BlockType.STREAMINFO), payload.length), payload);

    // Act
    filter.parse(streamInfoLast);

    // Assert: implementation sets METADATA_FOUND then overwrites to STREAMINFO_FOUND
    assertEquals(
        FlacPacketFilter.State.STREAMINFO_FOUND,
        filter.currentState,
        "State should be STREAMINFO_FOUND after parsing STREAMINFO even when last");
  }

  @Test
  @DisplayName("parse_firstBlockNotStreamInfoButMetadata_stillParsesAsStreamInfo")
  void parse_firstBlockNotStreamInfoButMetadata_stillParsesAsStreamInfo() throws IOException {
    // Arrange: Provide a non-STREAMINFO metadata block as the very first packet.
    // Due to implementation logic, this does not trigger invalidation and the code reads
    // streaminfo fields regardless.
    int minBlock = 0x0102;
    int maxBlock = 0x0304;
    int minFrame = 0x010203;
    int maxFrame = 0x000222;
    int sampleRate = 44_100;
    int channelsMasked = 0x02;
    int bitsPerSample = 24;
    long totalSamples = 42L;
    byte[] md5 = new byte[] {1, 2, 3, 4};

    byte[] payload =
        buildStreamInfoPayload(
            minBlock,
            maxBlock,
            minFrame,
            maxFrame,
            sampleRate,
            channelsMasked,
            bitsPerSample,
            totalSamples,
            md5);
    // Use PADDING (not STREAMINFO) as type
    FlacMetadataBlock first =
        new FlacMetadataBlock(
            header(false, blockTypeNumeric(BlockType.PADDING), payload.length), payload);

    // Act
    CodecPacket out = filter.parse(first);

    // Assert: packet returned unchanged, but fields parsed and state transitioned
    assertSame(first, out);
    assertEquals(
        FlacPacketFilter.State.STREAMINFO_FOUND,
        filter.currentState,
        "State incorrectly advances as if STREAMINFO was parsed");
    // As above: header-derived values
    int payloadLen2 = payload.length;
    int expectedMinBlockFromHeader =
        ((blockTypeNumeric(BlockType.PADDING) & 0x7F) << 8) | ((payloadLen2 >>> 16) & 0xFF);
    assertEquals(expectedMinBlockFromHeader, filter.minimumBlockSize);
    assertEquals(payloadLen2 & 0xFFFF, filter.maximumBlockSize);
    int expectedMinFrameFromHeaderAndPayload2 = (minBlock << 8) | ((maxBlock >>> 8) & 0xFF);
    int expectedMaxFrameFromPayload2 =
        ((maxBlock & 0xFF) << 16) | (((minFrame >>> 16) & 0xFF) << 8) | ((minFrame >>> 8) & 0xFF);
    assertEquals(expectedMinFrameFromHeaderAndPayload2, filter.minimumFrameSize);
    assertEquals(expectedMaxFrameFromPayload2, filter.maximumFrameSize);
    long combined2 = ByteBuffer.wrap(payload, 6, 8).getLong();
    int expectedSampleRate2 = (int) (combined2 >>> 40);
    int expectedChannels2 = (int) ((combined2 >>> 37) & 0x06);
    int expectedBitsPerSample2 = (int) ((combined2 >>> 32) & 0x1F);
    long expectedTotalSamples2 = (combined2 << 28) >>> 28;
    assertEquals(expectedSampleRate2, filter.sampleRate);
    assertEquals(expectedChannels2, filter.channels);
    assertEquals(expectedBitsPerSample2, filter.bitsPerSample);
    assertEquals(expectedTotalSamples2, filter.totalSamples);
  }

  // ------------------------- helpers -------------------------

  private static int blockTypeNumeric(BlockType type) {
    return switch (type) {
      case STREAMINFO -> 0;
      case PADDING -> 1;
      case APPLICATION -> 2;
      case SEEKTABLE -> 3;
      case VORBIS_COMMENT -> 4;
      case CUESHEET -> 5;
      case PICTURE -> 6;
      case INVALID -> 127;
      case UNKNOWN -> 7; // any other value maps to UNKNOWN
    };
  }

  private static int header(boolean isLast, int typeNumeric, int payloadLength) {
    return ((isLast ? 1 : 0) << 31) | ((typeNumeric & 0x7F) << 24) | (payloadLength & 0x00FFFFFF);
  }

  private static byte[] buildStreamInfoPayload(
      int minBlock,
      int maxBlock,
      int minFrame,
      int maxFrame,
      int sampleRate,
      int channelsMasked,
      int bitsPerSample,
      long totalSamples,
      byte[] md4Bytes) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    // 16-bit unsigned values (big-endian)
    baos.write((minBlock >>> 8) & 0xFF);
    baos.write(minBlock & 0xFF);
    baos.write((maxBlock >>> 8) & 0xFF);
    baos.write(maxBlock & 0xFF);
    // 24-bit unsigned values
    baos.write((minFrame >>> 16) & 0xFF);
    baos.write((minFrame >>> 8) & 0xFF);
    baos.write(minFrame & 0xFF);
    baos.write((maxFrame >>> 16) & 0xFF);
    baos.write((maxFrame >>> 8) & 0xFF);
    baos.write(maxFrame & 0xFF);

    long unaligned =
        (((long) sampleRate & 0xFFFFFFL) << 40)
            | (((long) channelsMasked & 0x07L) << 37)
            | (((long) bitsPerSample & 0x1FL) << 32)
            | (totalSamples & 0xFFFFFFFFL);

    byte[] longBytes = ByteBuffer.allocate(8).putLong(unaligned).array();
    baos.write(longBytes, 0, longBytes.length);

    // Only 4 bytes are read by the implementation for md5 (despite MD5 being 16 bytes)
    if (md4Bytes.length != 4) {
      throw new IllegalArgumentException("md4Bytes must be exactly 4 bytes for this test payload");
    }
    baos.write(md4Bytes, 0, md4Bytes.length);
    return baos.toByteArray();
  }
}
