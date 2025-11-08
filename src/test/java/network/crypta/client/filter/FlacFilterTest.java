package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class FlacFilterTest {

  private static final byte[] MAGIC = new byte[] {0x66, 0x4C, 0x61, 0x43}; // "fLaC"

  private static int flacHeader(boolean last, int blockType, int length) {
    int lastBit = last ? (1 << 31) : 0;
    int typeBits = (blockType & 0x7F) << 24;
    int lenBits = length & 0x00FF_FFFF;
    return lastBit | typeBits | lenBits;
  }

  private static byte[] join(byte[]... chunks) throws IOException {
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    for (byte[] c : chunks) bout.write(c);
    return bout.toByteArray();
  }

  @Test
  void readFilter_withValidMagicAndStreamInfoOnly_writesMagicAndStreamInfo() throws IOException {
    // Arrange
    FlacFilter filter = new FlacFilter();
    ByteArrayOutputStream inputBytes = new ByteArrayOutputStream();
    try (DataOutputStream dout = new DataOutputStream(inputBytes)) {
      // Magic
      dout.write(MAGIC);
      // STREAMINFO (type 0), mark as last block to transition to audio, payload length 22 bytes
      int header = flacHeader(true, 0, 22);
      dout.writeInt(header);
      // Minimal payload content for STREAMINFO: 22 deterministic bytes
      for (int i = 0; i < 22; i++) dout.writeByte(i);
    }
    byte[] input = inputBytes.toByteArray();

    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    filter.readFilter(new ByteArrayInputStream(input), out, null, Map.of(), null, null);

    // Assert: output equals magic + the same single metadata block (unchanged by the parser)
    assertArrayEquals(input, out.toByteArray());
  }

  @Test
  void readFilter_withInvalidMagic_throwsDataFilterException() {
    // Arrange: First byte not equal to 'f'
    byte[] badMagic = new byte[] {0x00, 0x4C, 0x61, 0x43};
    byte[] rest = new byte[] {0x00, 0x00, 0x00, 0x00};
    byte[] input;
    try {
      input = join(badMagic, rest);
    } catch (IOException e) {
      throw new AssertionError(e);
    }
    FlacFilter filter = new FlacFilter();
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        DataFilterException.class,
        () -> filter.readFilter(new ByteArrayInputStream(input), out, null, Map.of(), null, null));
    // Ensure nothing was written
    assertEquals(0, out.size());
  }

  @Test
  void readFilter_streamInfoThenApplication_rewritesApplicationToPaddingWithZeros()
      throws IOException {
    // Arrange
    FlacFilter filter = new FlacFilter();

    // Build input: magic + STREAMINFO (not last) + APPLICATION (last)
    ByteArrayOutputStream inputBytes = new ByteArrayOutputStream();
    try (DataOutputStream dout = new DataOutputStream(inputBytes)) {
      // Magic
      dout.write(MAGIC);

      // STREAMINFO, not last, payload 22
      int streamInfoHeader = flacHeader(false, 0, 22);
      dout.writeInt(streamInfoHeader);
      for (int i = 0; i < 22; i++) dout.writeByte(0xA0 + i); // deterministic payload

      // APPLICATION, last, payload 10
      int applicationHeader = flacHeader(true, 2, 10);
      dout.writeInt(applicationHeader);
      for (int i = 0; i < 10; i++) dout.writeByte(0x10 + i);
    }
    byte[] input = inputBytes.toByteArray();

    // Expected output:
    // - Magic
    // - STREAMINFO unchanged
    // - APPLICATION rewritten by FlacPacketFilter to PADDING (type=1) with zeroed payload
    ByteArrayOutputStream expectedBytes = new ByteArrayOutputStream();
    try (DataOutputStream dout = new DataOutputStream(expectedBytes)) {
      // Magic
      dout.write(MAGIC);

      // STREAMINFO unchanged
      int streamInfoHeader = flacHeader(false, 0, 22);
      dout.writeInt(streamInfoHeader);
      for (int i = 0; i < 22; i++) dout.writeByte(0xA0 + i);

      // APPLICATION -> PADDING with zeroed payload of same length
      int paddingHeader = flacHeader(true, 1, 10); // type changed to 1 (PADDING)
      dout.writeInt(paddingHeader);
      for (int i = 0; i < 10; i++) dout.writeByte(0x00);
    }
    byte[] expected = expectedBytes.toByteArray();

    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    filter.readFilter(new ByteArrayInputStream(input), out, null, Map.of(), null, null);

    // Assert
    assertArrayEquals(expected, out.toByteArray());
  }

  @Test
  void readFilter_streamInfoThenUnknown_keepsUnknownUnchanged() throws IOException {
    // Arrange
    FlacFilter filter = new FlacFilter();

    // Build input: magic + STREAMINFO (not last) + UNKNOWN (last, e.g., type 42)
    ByteArrayOutputStream inputBytes = new ByteArrayOutputStream();
    try (DataOutputStream dout = new DataOutputStream(inputBytes)) {
      dout.write(MAGIC);

      int streamInfoHeader = flacHeader(false, 0, 22);
      dout.writeInt(streamInfoHeader);
      for (int i = 0; i < 22; i++) dout.writeByte(0xB0 + i);

      int unknownHeader = flacHeader(true, 42, 5);
      dout.writeInt(unknownHeader);
      for (int i = 0; i < 5; i++) dout.writeByte(0x20 + i);
    }
    byte[] input = inputBytes.toByteArray();

    // Expected: second block remains type 42 with original payload
    byte[] expected = input.clone();

    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    filter.readFilter(new ByteArrayInputStream(input), out, null, Map.of(), null, null);

    // Assert
    assertArrayEquals(expected, out.toByteArray());
  }

  @Test
  void readFilter_truncatedMetadata_payloadShort_writesOnlyMagicThenStops() throws IOException {
    // Arrange: magic + header claiming 10 bytes, but only 3 payload bytes present
    ByteArrayOutputStream inputBytes = new ByteArrayOutputStream();
    try (DataOutputStream dout = new DataOutputStream(inputBytes)) {
      dout.write(MAGIC);
      int header = flacHeader(true, 0, 10);
      dout.writeInt(header);
      // Only 3 bytes follow - triggers EOF during readFully(payload)
      dout.writeByte(0x01);
      dout.writeByte(0x02);
      dout.writeByte(0x03);
    }
    byte[] input = inputBytes.toByteArray();

    FlacFilter filter = new FlacFilter();
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act: expect no exception; the filter returns on EOF
    filter.readFilter(new ByteArrayInputStream(input), out, null, Map.of(), null, null);

    // Assert: only magic was written before failure
    assertArrayEquals(MAGIC, out.toByteArray());
  }

  @Test
  void readFilter_twoAudioFrames_preservesAllFrameHeadersAndPayloads() throws IOException {
    // Arrange: magic + STREAMINFO(last) + two audio frames
    // Frame headers use sync pattern 0xFF, 0xF8; payloads are simple deterministic bytes
    byte[] frame1Header = new byte[] {(byte) 0xFF, (byte) 0xF8};
    byte[] frame1Payload = new byte[] {0x01, 0x02, 0x03, 0x04};
    byte[] frame2Header = new byte[] {(byte) 0xFF, (byte) 0xF8};
    byte[] frame2Payload = new byte[] {0x05, 0x06, 0x07};

    ByteArrayOutputStream inputBytes = new ByteArrayOutputStream();
    try (DataOutputStream dout = new DataOutputStream(inputBytes)) {
      // Magic
      dout.write(MAGIC);
      // STREAMINFO (type 0), mark as last block to transition to audio, payload length 22 bytes
      int header = flacHeader(true, 0, 22);
      dout.writeInt(header);
      for (int i = 0; i < 22; i++) dout.writeByte(i);
      // Two frames
      dout.write(frame1Header);
      dout.write(frame1Payload);
      dout.write(frame2Header);
      dout.write(frame2Payload);
    }
    byte[] input = inputBytes.toByteArray();

    FlacFilter filter = new FlacFilter();
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    filter.readFilter(new ByteArrayInputStream(input), out, null, Map.of(), null, null);

    // Assert: output matches input exactly; particularly, second frame header must not be dropped
    assertArrayEquals(input, out.toByteArray());
  }

  @Test
  void readFilter_finalFrameEndingWith0xFF_preservesTrailingByteOnEOF() throws IOException {
    // Arrange: stream ends immediately after writing a 0xFF in the frame payload
    byte[] frameHeader = new byte[] {(byte) 0xFF, (byte) 0xF8};
    byte[] payload = new byte[] {0x11, 0x22, 0x33, (byte) 0xFF}; // last byte is 0xFF

    ByteArrayOutputStream inputBytes = new ByteArrayOutputStream();
    try (DataOutputStream dout = new DataOutputStream(inputBytes)) {
      // Magic
      dout.write(MAGIC);
      // STREAMINFO (type 0), mark as last block to transition to audio, payload length 22 bytes
      int header = flacHeader(true, 0, 22);
      dout.writeInt(header);
      for (int i = 0; i < 22; i++) dout.writeByte(i);
      // Single frame whose last byte equals 0xFF
      dout.write(frameHeader);
      dout.write(payload);
      // EOF now (no next byte after the 0xFF)
    }
    byte[] input = inputBytes.toByteArray();

    FlacFilter filter = new FlacFilter();
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    filter.readFilter(new ByteArrayInputStream(input), out, null, Map.of(), null, null);

    // Assert: the trailing 0xFF must be preserved; output equals input
    assertArrayEquals(input, out.toByteArray());
  }
}
