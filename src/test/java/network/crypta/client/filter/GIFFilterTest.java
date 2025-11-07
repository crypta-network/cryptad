package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class GIFFilterTest {

  @Test
  void readFilter_whenHeaderNotGif_expectDataFilterException() {
    byte[] badHeader = new byte[] {'N', 'O', 'T', 'G', 'I', 'F'};

    ByteArrayInputStream in = new ByteArrayInputStream(badHeader);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    ContentDataFilter filter = new GIFFilter();
    assertThrows(DataFilterException.class, () -> filter.readFilter(in, out, "", null, null, null));
  }

  @Test
  void readFilter_whenUnexpectedEOF_expectDataFilterException() {
    // Only 5 bytes (header requires 6)
    byte[] truncated = new byte[] {'G', 'I', 'F', '8', '9'};

    ByteArrayInputStream in = new ByteArrayInputStream(truncated);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    ContentDataFilter filter = new GIFFilter();
    assertThrows(DataFilterException.class, () -> filter.readFilter(in, out, "", null, null, null));
  }

  @Test
  void gif87a_validMinimalImage_expectOutputEqualsInput() throws IOException {
    byte[] input = buildMinimalGif87a(/*withSortFlag*/ false, /*aspect*/ 0, /*bgIndex*/ 0);

    byte[] filtered = runFilter(input);

    assertArrayEquals(input, filtered);
  }

  @Test
  void gif87a_withSortFlagOrAspectRatio_expectDataFilterException() {
    // Sort flag set
    byte[] withSort = buildMinimalGif87a(/*withSortFlag*/ true, /*aspect*/ 0, /*bgIndex*/ 0);
    // Aspect ratio non-zero
    byte[] withAspect = buildMinimalGif87a(/*withSortFlag*/ false, /*aspect*/ 1, /*bgIndex*/ 0);

    ContentDataFilter filter = new GIFFilter();
    assertThrows(
        DataFilterException.class,
        () ->
            filter.readFilter(
                new ByteArrayInputStream(withSort),
                new ByteArrayOutputStream(),
                "",
                null,
                null,
                null));
    assertThrows(
        DataFilterException.class,
        () ->
            filter.readFilter(
                new ByteArrayInputStream(withAspect),
                new ByteArrayOutputStream(),
                "",
                null,
                null,
                null));
  }

  @Test
  void gif87a_withInvalidImageFlags_expectNoDataError() {
    // Build a GIF87a where image flags have reserved bits (3..5) set (invalid in 87a)
    byte[] input = buildGifWithCustomImageFlags(/*is89a*/ false, /*imageFlags*/ 0x28);

    ContentDataFilter filter = new GIFFilter();
    assertThrows(
        DataFilterException.class,
        () ->
            filter.readFilter(
                new ByteArrayInputStream(input),
                new ByteArrayOutputStream(),
                "",
                null,
                null,
                null));
  }

  @Test
  void gif89a_withVariousImageFlags_expectAccepted() throws IOException {
    // In GIF89a, reserved bits in image flags are accepted; both custom and default flags
    byte[] inputReserved = buildGifWithCustomImageFlags(/*is89a*/ true, /*imageFlags*/ 0x28);
    byte[] inputDefault = buildGifWithCustomImageFlags(/*is89a*/ true, /*imageFlags*/ 0x00);

    assertArrayEquals(inputReserved, runFilter(inputReserved));
    assertArrayEquals(inputDefault, runFilter(inputDefault));
  }

  @Test
  void gif87a_withBackgroundIndexOutOfRange_expectDataFilterException() {
    // Global color table of size 2 (indices 0..1); set background index to 5
    byte[] input = buildMinimalGif87a(/*withSortFlag*/ false, /*aspect*/ 0, /*bgIndex*/ 5);

    ContentDataFilter filter = new GIFFilter();
    assertThrows(
        DataFilterException.class,
        () ->
            filter.readFilter(
                new ByteArrayInputStream(input),
                new ByteArrayOutputStream(),
                "",
                null,
                null,
                null));
  }

  @Test
  void gif89a_netscapeLoopFirstBlock_expectExtensionPreserved() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    // Header + LSD + GCT
    writeHeader(baos, true);
    writeLsdWithGct(baos, /*withSortFlag*/ false, /*aspect*/ 0, /*bgIndex*/ 0);
    writeMinimalGct(baos);
    // Netscape loop extension as first block
    writeNetscapeLoop(baos, /*loop*/ 3);
    // Valid image
    writeMinimalImage(baos, /*imageFlags*/ 0);
    // Terminator
    baos.write(0x3B);
    byte[] input = baos.toByteArray();

    byte[] filtered = runFilter(input);

    assertArrayEquals(input, filtered);
  }

  @Test
  void gif89a_netscapeLoopAfterImage_expectExtensionStripped() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    // Header + LSD + GCT
    writeHeader(baos, true);
    writeLsdWithGct(baos, /*withSortFlag*/ false, /*aspect*/ 0, /*bgIndex*/ 0);
    writeMinimalGct(baos);
    // Valid image first
    writeMinimalImage(baos, /*imageFlags*/ 0);
    // Netscape loop extension after image (should be skipped)
    writeNetscapeLoop(baos, /*loop*/ 5);
    // Terminator
    baos.write(0x3B);
    byte[] input = baos.toByteArray();

    // Expected output: same but without the application extension
    ByteArrayOutputStream expected = new ByteArrayOutputStream();
    writeHeader(expected, true);
    writeLsdWithGct(expected, false, 0, 0);
    writeMinimalGct(expected);
    writeMinimalImage(expected, 0);
    expected.write(0x3B);
    byte[] expectedBytes = expected.toByteArray();

    byte[] filtered = runFilter(input);

    assertArrayEquals(expectedBytes, filtered);
  }

  @Test
  void gif89a_graphicControlBeforeImage_expectGcWrittenOnce() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    writeHeader(baos, true);
    writeLsdWithGct(baos, false, 0, 0);
    writeMinimalGct(baos);
    // Valid GC: disposal method 2 (010 << 2), delay 10, transparent color index 1
    writeGraphicControl(baos, /*flags*/ 0b0000_1000, /*delay*/ 10, /*trans*/ 1);
    writeMinimalImage(baos, 0);
    baos.write(0x3B);
    byte[] input = baos.toByteArray();

    byte[] filtered = runFilter(input);

    // Should be unchanged
    assertArrayEquals(input, filtered);
  }

  @Test
  void gif89a_graphicControlInvalidLength_expectGcStripped() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    writeHeader(baos, true);
    writeLsdWithGct(baos, false, 0, 0);
    writeMinimalGct(baos);
    // Invalid GC (length 5 instead of 4) followed by garbage subblock and terminator
    baos.write(0x21); // '!'
    baos.write(0xF9); // label
    baos.write(5); // invalid length
    baos.write(new byte[] {0, 0, 0, 0, 0}); // 5 bytes payload
    baos.write(1); // extra subblock length
    baos.write(7); // arbitrary
    baos.write(0); // terminator
    // Then a valid image
    writeMinimalImage(baos, 0);
    baos.write(0x3B);
    byte[] input = baos.toByteArray();

    // Expected output: same but without the invalid GC block
    ByteArrayOutputStream expected = new ByteArrayOutputStream();
    writeHeader(expected, true);
    writeLsdWithGct(expected, false, 0, 0);
    writeMinimalGct(expected);
    writeMinimalImage(expected, 0);
    expected.write(0x3B);
    byte[] expectedBytes = expected.toByteArray();

    byte[] filtered = runFilter(input);

    assertArrayEquals(expectedBytes, filtered);
  }

  @Test
  void gif89a_graphicControlBeforeInvalidImage_expectGcDropped() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    writeHeader(baos, true);
    writeLsdWithGct(baos, false, 0, 0);
    writeMinimalGct(baos);
    // Valid GC with a different disposal method (3) to diversify flags usage
    writeGraphicControl(baos, /*flags*/ 0b0000_1100, /*delay*/ 0, /*trans*/ 0);
    // Invalid image: LZW code size = 1 (must be >= 2)
    baos.write(0x2C); // image sep
    writeLeShort(baos, 0); // left
    writeLeShort(baos, 0); // top
    writeLeShort(baos, 1); // width
    writeLeShort(baos, 1); // height
    baos.write(0); // image flags: no local table
    baos.write(1); // invalid lzw code size
    // data blocks still present
    baos.write(1);
    baos.write(0);
    baos.write(0);
    // Then a valid image
    writeMinimalImage(baos, 0);
    baos.write(0x3B);
    byte[] input = baos.toByteArray();

    // Expected: only the valid image, no GC preserved
    ByteArrayOutputStream expected = new ByteArrayOutputStream();
    writeHeader(expected, true);
    writeLsdWithGct(expected, false, 0, 0);
    writeMinimalGct(expected);
    writeMinimalImage(expected, 0);
    expected.write(0x3B);
    byte[] expectedBytes = expected.toByteArray();

    byte[] filtered = runFilter(input);

    assertArrayEquals(expectedBytes, filtered);
  }

  @Test
  void readFilter_whenUnterminatedGif_expectDataFilterException() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    writeHeader(baos, true);
    writeLsdWithGct(baos, false, 0, 0);
    writeMinimalGct(baos);
    writeMinimalImage(baos, 0);
    // No GIF terminator (0x3B)
    byte[] input = baos.toByteArray();

    ContentDataFilter filter = new GIFFilter();
    assertThrows(
        DataFilterException.class,
        () ->
            filter.readFilter(
                new ByteArrayInputStream(input),
                new ByteArrayOutputStream(),
                "",
                null,
                null,
                null));
  }

  // ---------- Helpers ----------

  private static byte[] runFilter(byte[] data) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    new GIFFilter().readFilter(new ByteArrayInputStream(data), out, "", null, null, null);
    return out.toByteArray();
  }

  private static byte[] buildMinimalGif87a(boolean withSortFlag, int aspect, int bgIndex) {
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      writeHeader(baos, false);
      writeLsdWithGct(baos, withSortFlag, aspect, bgIndex);
      writeMinimalGct(baos);
      writeMinimalImage(baos, /*imageFlags*/ 0); // valid image flags for 87a
      baos.write(0x3B); // terminator
      return baos.toByteArray();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] buildGifWithCustomImageFlags(boolean is89a, int imageFlags) {
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      writeHeader(baos, is89a);
      writeLsdWithGct(baos, /*withSort*/ false, /*aspect*/ 0, /*bg*/ 0);
      writeMinimalGct(baos);
      // Image with custom flags
      writeMinimalImage(baos, imageFlags);
      baos.write(0x3B);
      return baos.toByteArray();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static void writeHeader(ByteArrayOutputStream baos, boolean is89a) throws IOException {
    byte[] header =
        is89a
            ? new byte[] {'G', 'I', 'F', '8', '9', 'a'}
            : new byte[] {'G', 'I', 'F', '8', '7', 'a'};
    baos.write(header);
  }

  private static void writeLsdWithGct(
      ByteArrayOutputStream baos, boolean withSortFlag, int aspect, int bgIndex) {
    // Logical Screen Descriptor: width=2, height=2, GCT flag=1, size=2 entries (N=0)
    writeLeShort(baos, 2);
    writeLeShort(baos, 2);
    int flags = 0x80 /*GCT*/ | (withSortFlag ? 0x08 : 0x00) /*color res=0, N=0*/;
    baos.write(flags);
    baos.write(bgIndex & 0xFF);
    baos.write(aspect & 0xFF);
  }

  private static void writeMinimalGct(ByteArrayOutputStream baos) throws IOException {
    // Two colors: black and white
    baos.write(new byte[] {0, 0, 0, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
  }

  private static void writeMinimalImage(ByteArrayOutputStream baos, int imageFlags) {
    baos.write(0x2C); // image separator
    writeLeShort(baos, 0); // left
    writeLeShort(baos, 0); // top
    writeLeShort(baos, 1); // width
    writeLeShort(baos, 1); // height
    baos.write(imageFlags & 0xFF); // image flags
    baos.write(2); // LZW code size (valid: >=2 and <12)
    // Minimal sub-blocks: one byte then terminator
    baos.write(1); // sub-block length
    baos.write(0); // dummy data
    baos.write(0); // terminator sub-block
  }

  private static void writeNetscapeLoop(ByteArrayOutputStream baos, int loop) throws IOException {
    baos.write(0x21); // extension introducer
    baos.write(0xFF); // application label
    byte[] sig = new byte[] {'N', 'E', 'T', 'S', 'C', 'A', 'P', 'E', '2', '.', '0'};
    baos.write(sig.length);
    baos.write(sig);
    baos.write(3); // sub-block len
    baos.write(1); // sub-id
    writeLeShort(baos, loop);
    baos.write(0); // terminator
  }

  private static void writeGraphicControl(
      ByteArrayOutputStream baos, int flags, int delay, int trans) {
    baos.write(0x21); // extension introducer
    baos.write(0xF9); // graphic control label
    baos.write(4); // length
    baos.write(flags & 0xFF);
    writeLeShort(baos, delay);
    baos.write(trans & 0xFF);
    baos.write(0); // terminator
  }

  private static void writeLeShort(ByteArrayOutputStream baos, int val) {
    baos.write(val & 0xFF);
    baos.write((val >>> 8) & 0xFF);
  }
}
