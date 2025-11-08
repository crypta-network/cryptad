package network.crypta.client.filter;

import static network.crypta.client.filter.ResourceFileUtil.resourceToBucket;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S100")
class WebPFilterTest {

  private static void readFilter(
      WebPFilter objWebPFilter, InputStream inStream, OutputStream outStream) throws IOException {
    objWebPFilter.readFilter(inStream, outStream, "", null, null, null);
  }

  @Test
  void readFilter_whenNoImageChunk_expectDataFilterException() throws IOException {
    // Arrange
    ByteBuffer buf =
        ByteBuffer.allocate(12)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(new byte[] {'R', 'I', 'F', 'F'})
            .putInt(4)
            .put(new byte[] {'W', 'E', 'B', 'P'});
    WebPFilter filter = new WebPFilter();
    // Act + Assert
    try (ArrayBucket input = new ArrayBucket(buf.array());
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void readFilter_whenVP8ChunkTooShort_expectDataFilterException() throws IOException {
    // Arrange
    ByteBuffer buf =
        ByteBuffer.allocate(33)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(new byte[] {'R', 'I', 'F', 'F'})
            .putInt(0x1308)
            .put(new byte[] {'W', 'E', 'B', 'P'})
            .put(new byte[] {'V', 'P', '8', ' '})
            .putInt(0x12FC)
            .putLong(((long) 0x2a019d << 24) | (1L << 4));
    WebPFilter filter = new WebPFilter();
    // Act + Assert
    try (ArrayBucket input = new ArrayBucket(buf.array());
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void readFilter_whenOnlyJunkChunk_expectDataFilterException() throws IOException {
    // Arrange
    ByteBuffer buf =
        ByteBuffer.allocate(28)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(new byte[] {'R', 'I', 'F', 'F'})
            .putInt(20)
            .put(new byte[] {'W', 'E', 'B', 'P'})
            .put(new byte[] {'J', 'U', 'N', 'K'})
            .putInt(7)
            .putLong(0);
    WebPFilter filter = new WebPFilter();
    // Act + Assert
    try (ArrayBucket input = new ArrayBucket(buf.array());
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void readFilter_whenChunkSizeTooLarge_expectDataFilterException() throws IOException {
    // Arrange
    ByteBuffer buf =
        ByteBuffer.allocate(32)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(new byte[] {'R', 'I', 'F', 'F'})
            .putInt(0x7fffff0c)
            .put(new byte[] {'W', 'E', 'B', 'P'})
            .put(new byte[] {'V', 'P', '8', ' '})
            .putInt(0x7fffff00)
            .putLong(((long) 0x2a019d << 24) | (1L << 4));
    WebPFilter filter = new WebPFilter();
    // Act + Assert
    try (ArrayBucket input = new ArrayBucket(buf.array());
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void readFilter_whenFileSizeZero_expectDataFilterException() throws IOException {
    // Arrange
    ByteBuffer buf =
        ByteBuffer.allocate(32)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(new byte[] {'R', 'I', 'F', 'F'})
            .putInt(0)
            .put(new byte[] {'W', 'E', 'B', 'P'})
            .put(new byte[] {'V', 'P', '8', ' '})
            .putInt(12)
            .putLong(((long) 0x2a019d << 24) | (1L << 4));
    WebPFilter filter = new WebPFilter();
    // Act + Assert
    try (ArrayBucket input = new ArrayBucket(buf.array());
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"./webp/test.webp", "./webp/1_webp_a.webp", "./webp/Simple_Animated_Clock.webp"})
  void readFilter_whenValidWebP_expectPassThrough(String resourcePath) throws IOException {
    // Arrange
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = resourceToBucket(resourcePath);
        ArrayBucket output = new ArrayBucket()) {
      // Act
      try (InputStream in = input.getInputStream();
          OutputStream out = output.getOutputStream()) {
        readFilter(filter, in, out);
      }
      // Assert
      assertEquals(input.size(), output.size(), "Input and output should be the same length");
      assertArrayEquals(
          BucketTools.toByteArray(input),
          BucketTools.toByteArray(output),
          "Input and output differ");
    }
  }

  @Test
  void readFilter_whenExtraDataAfterEof_expectDataFilterException() throws IOException {
    // Arrange
    ArrayBucketFactory bf = new ArrayBucketFactory();
    WebPFilter filter = new WebPFilter();
    // Act + Assert
    try (ArrayBucket inputValid = resourceToBucket("./webp/test.webp");
        ArrayBucket input =
            (ArrayBucket)
                BucketTools.pad(
                    inputValid, (int) inputValid.size() + 1, bf, (int) inputValid.size());
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertEquals(inputValid.size() + 1L, input.size(), "Input size is wrong");
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  // No helper methods that allocate ArrayBucket outside try-with-resources.

  // -------------------- Additional deterministic tests for edge branches --------------------

  @Test
  void vp8l_whenEncountered_expectLosslessUnsupported() throws IOException {
    byte[] vp8lPayload = new byte[] {0x00}; // minimal payload; filter throws before reading all
    byte[] img = riffWebp(chunk("VP8L", vp8lPayload));
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void alph_whenNoVp8x_expectUnexpectedAlpha() throws IOException {
    byte[] alph = chunk("ALPH", new byte[] {0x00}); // size=1 → padding handled by chunk()
    byte[] img = riffWebp(alph);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void alph_whenReservedBitsSet_expectException() throws IOException {
    // VP8X with ALPHA_FLAG set and tiny canvas 1x1
    byte[] vp8x = vp8xChunk(/*flags*/ 0x10, /*wMinus1*/ 0, /*hMinus1*/ 2);
    // ALPH flags bit1 set (0x02) triggers reserved-bits error
    byte[] alph = chunk("ALPH", new byte[] {0x02});
    byte[] img = riffWebp(vp8x, alph);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void alph_whenUnsupportedCompression_expectException() throws IOException {
    byte[] vp8x = vp8xChunk(/*flags*/ 0x10, /*wMinus1*/ 0, /*hMinus1*/ 3);
    // ALPH flags high bits (0x80) set → unsupported compression path
    byte[] alph = chunk("ALPH", new byte[] {(byte) 0x80});
    byte[] img = riffWebp(vp8x, alph);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void vp8x_whenReservedFlagsSet_expectException() throws IOException {
    // Set a bit outside ALL_VALID_FLAGS (0x3e); e.g., 0x40
    byte[] vp8x = vp8xChunk(/*flags*/ 0x40, /*wMinus1*/ 0, /*hMinus1*/ 1);
    byte[] img = riffWebp(vp8x);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void vp8x_whenInvalidChunkSize_expectException() throws IOException {
    // VP8X size must be exactly 10; here we craft size=8 (flags only, missing width/height)
    byte[] flagsLE = leInt(0x10); // ALPHA flag just for realism
    byte[] badVp8x = rawChunk("VP8X", flagsLE); // size=4 → chunk() would pad; rawChunk keeps size=4
    // Adjust to RIFF by wrapping in riffWebp(); RIFF size accounting is handled there
    byte[] img = riffWebp(badVp8x);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void vp8x_whenImageTooBig_expectException() throws IOException {
    // widthMinus1 = 16384 → width = 16385 (> 16384) triggers size-too-big
    byte[] vp8x = vp8xChunk(/*flags*/ 0x00, /*wMinus1*/ 16384, /*hMinus1*/ 5);
    byte[] img = riffWebp(vp8x);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void vp8_whenIsShownFalse_expectException() throws IOException {
    // VP8 header with is_shown bit (bit 4) cleared (tmp=0x00) and valid sync code
    byte[] vp8 = vp8Chunk(/*size*/ 16, /*tmp*/ 0x00);
    byte[] img = riffWebp(vp8);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void vp8_whenDuplicate_expectUnexpectedSecondVp8() throws IOException {
    byte[] vp8First = vp8Chunk(/*size*/ 12, /*tmp*/ 0x10); // valid
    byte[] vp8Second = vp8Chunk(/*size*/ 14, /*tmp*/ 0x10); // second occurrence not allowed
    byte[] img = riffWebp(vp8First, vp8Second);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void anmf_whenSeenBeforeAnim_expectUnexpected() throws IOException {
    // VP8X with animation flag set but ANMF appears before ANIM → error
    byte[] vp8xAnim =
        vp8xChunk(/*flags*/ 0x02, /*wMinus1*/ 0, /*hMinus1*/ 4); // 0x02 = ANIMATION_FLAG
    // Minimal invalid ANMF (too small) to also exercise size guard; code will fail before reading
    byte[] anmf = rawChunk("ANMF", new byte[8]);
    byte[] img = riffWebp(vp8xAnim, anmf);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void anim_whenInvalidSize_expectException() throws IOException {
    // VP8X with animation flag set, then ANIM with wrong size (not 6)
    byte[] vp8xAnim = vp8xChunk(/*flags*/ 0x02, /*wMinus1*/ 0, /*hMinus1*/ 6);
    byte[] animBad = rawChunk("ANIM", new byte[4]); // size=4
    byte[] img = riffWebp(vp8xAnim, animBad);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  @Test
  void anim_whenAfterVp8_expectUnexpected() throws IOException {
    byte[] vp8 = vp8Chunk(/*size*/ 18, /*tmp*/ 0x10);
    byte[] anim = rawChunk("ANIM", new byte[6]);
    byte[] img = riffWebp(vp8, anim);
    WebPFilter filter = new WebPFilter();
    try (ArrayBucket input = new ArrayBucket(img);
        ArrayBucket output = new ArrayBucket();
        InputStream in = input.getInputStream();
        OutputStream out = output.getOutputStream()) {
      assertThrows(DataFilterException.class, () -> readFilter(filter, in, out));
    }
  }

  // --------------------------------- helpers ---------------------------------

  private static byte[] riffWebp(byte[]... chunks) throws IOException {
    int chunksLen = 0;
    for (byte[] c : chunks) chunksLen += c.length;
    int fileSize = 4 + chunksLen; // FourCC + all chunks
    ByteArrayOutputStream baos = new ByteArrayOutputStream(12 + chunksLen);
    baos.write(new byte[] {'R', 'I', 'F', 'F'});
    baos.write(leInt(fileSize));
    baos.write(new byte[] {'W', 'E', 'B', 'P'});
    for (byte[] c : chunks) baos.write(c);
    return baos.toByteArray();
  }

  private static byte[] chunk(String fourcc, byte[] payload) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream(8 + payload.length + 1);
    baos.write(fourcc.getBytes());
    baos.write(leInt(payload.length));
    baos.write(payload);
    if ((payload.length & 1) != 0) {
      baos.write(0x00); // RIFF padding to even boundary
    }
    return baos.toByteArray();
  }

  private static byte[] rawChunk(String fourcc, byte[] payload) throws IOException {
    // Same as chunk(), but used to craft intentionally malformed sizes for negative tests.
    return chunk(fourcc, payload);
  }

  private static byte[] vp8Chunk(int size, int tmpValue) throws IOException {
    if (size <= 10) size = 12; // ensure > 10 so size guard doesn't mask earlier checks
    int payloadLen = size;
    List<Byte> bytes = new ArrayList<>(payloadLen);
    // 3-byte frame tag (little-endian), with tmpValue controlling flags (e.g., is_shown)
    bytes.add((byte) (tmpValue & 0xFF));
    bytes.add((byte) ((tmpValue >>> 8) & 0xFF));
    bytes.add((byte) ((tmpValue >>> 16) & 0xFF));
    // keyframe sync code
    bytes.add((byte) 0x9d);
    bytes.add((byte) 0x01);
    bytes.add((byte) 0x2a);
    while (bytes.size() < payloadLen) bytes.add((byte) 0x00);
    byte[] payload = new byte[bytes.size()];
    for (int i = 0; i < bytes.size(); i++) payload[i] = bytes.get(i);
    return chunk("VP8 ", payload);
  }

  private static byte[] vp8xChunk(int flags, int wMinus1, int hMinus1) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream(10);
    baos.write(leInt(flags));
    // width/height are 24-bit, little-endian, stored as minus one
    baos.write(
        new byte[] {
          (byte) (wMinus1 & 0xFF), (byte) ((wMinus1 >>> 8) & 0xFF), (byte) ((wMinus1 >>> 16) & 0xFF)
        });
    baos.write(
        new byte[] {
          (byte) (hMinus1 & 0xFF), (byte) ((hMinus1 >>> 8) & 0xFF), (byte) ((hMinus1 >>> 16) & 0xFF)
        });
    return chunk("VP8X", baos.toByteArray());
  }

  private static byte[] leInt(int v) {
    return new byte[] {
      (byte) (v & 0xFF),
      (byte) ((v >>> 8) & 0xFF),
      (byte) ((v >>> 16) & 0xFF),
      (byte) ((v >>> 24) & 0xFF)
    };
  }
}
