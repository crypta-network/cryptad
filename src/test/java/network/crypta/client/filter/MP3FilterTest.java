package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTools;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class MP3FilterTest {
  @Test
  void readFilter_whenGoodSamples_expectUnchanged() {
    // Arrange
    //noinspection UnnecessaryLocalVariable
    String[] goods = GOOD;
    // Act & Assert
    for (String good : goods) {
      assertEqualAfterFilter(good, good);
    }
  }

  @Test
  void readFilter_whenFilterPairs_expectExpectedOutput() {
    // Arrange
    //noinspection UnnecessaryLocalVariable
    String[][] pairs = FILTER_PAIRS;
    // Act & Assert
    for (String[] pair : pairs) {
      assertEqualAfterFilter(pair[0], pair[1]);
    }
  }

  /**
   * Asserts that the test file in the first argument, after passing through the content filter, is
   * equal to the reference file in the second argument.
   *
   * @param fileUnfiltered the test file
   * @param fileExpected the reference file
   */
  private static void assertEqualAfterFilter(String fileUnfiltered, String fileExpected) {
    Bucket input = resourceToBucket(fileUnfiltered);
    Bucket expected = resourceToBucket(fileExpected);
    Bucket filtered = filterMP3(input);
    assertTrue(
        equalBuckets(filtered, expected),
        "Filtered and expected output are not identical. "
            + "Input = "
            + fileUnfiltered
            + ", expected = "
            + fileExpected);
  }

  /** Checks for equality of Bucket contents. */
  private static boolean equalBuckets(Bucket a, Bucket b) {
    try {
      return Arrays.equals(BucketTools.toByteArray(a), BucketTools.toByteArray(b));
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * Runs a Bucket through the content filter.
   *
   * @throws AssertionError on failure
   */
  private static Bucket filterMP3(Bucket input) {
    ContentDataFilter filter = new MP3Filter();
    Bucket output = new ArrayBucket();

    try (InputStream inStream = input.getInputStream();
        OutputStream outStream = output.getOutputStream()) {
      filter.readFilter(inStream, outStream, "", null, null, null);
    } catch (Exception e) {
      throw new AssertionError("Unexpected exception in the content filter.", e);
    }

    return output;
  }

  @Test
  void filter_whenEmptyInput_expectBogusMP3Exception() {
    MP3Filter filter = new MP3Filter();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    DataFilterException ex =
        assertThrows(
            DataFilterException.class,
            () -> filter.filter(new ByteArrayInputStream(new byte[0]), out));
    assertEquals(
        NodeL10n.getBase().getString("MP3Filter.bogusMP3NoFrames"),
        ex.getRawTitle(),
        "Raw title should match l10n key");
    assertEquals(
        NodeL10n.getBase().getString("MP3Filter.bogusMP3NoFramesExplanation"),
        ex.getMessage(),
        "Message should be the explanation l10n string");
  }

  @Test
  void filter_whenSingleCRCFrame_expectOutputEqualsInput() throws IOException {
    // Arrange: build a minimal valid frame (Version 1, Layer III, 32 kbps @ 44.1kHz) with CRC
    int version = 3; // MPEG Version 1
    int layer = 1; // Layer III
    boolean hasCRC = true;
    int bitrateIndex = 1; // 32 kbps for Layer III, Version 1
    int samplerateIndex = 0; // 44100 Hz
    boolean padding = false;
    int emphasis = 0; // none

    int header =
        buildHeader(version, layer, hasCRC, bitrateIndex, samplerateIndex, padding, emphasis);
    int frameLength = computeFrameLength(version, layer, bitrateIndex, samplerateIndex, padding);

    byte[] input = new byte[frameLength + 2 /* CRC bytes */];
    try (DataOutputStream dos = new DataOutputStream(new ByteArrayOutputStreamWrapper(input))) {
      dos.writeInt(header);
      dos.writeShort(0xBEEF);
      // payload size expected by filter: frameLength - 4 (header not counted), we already wrote 2
      // CRC bytes, the remaining payload is frameLength - 4 bytes
      byte[] payload = new byte[frameLength - 4];
      for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i & 0xFF);
      dos.write(payload);
    }

    // Act
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    new MP3Filter().filter(new ByteArrayInputStream(input), out);

    // Assert
    assertArrayEquals(input, out.toByteArray(), "Filter must pass through a valid frame with CRC");
  }

  @Test
  void filter_whenId3v2Tag_thenValidFrame_expectTagStripped() throws IOException {
    // Arrange: ID3v2 header (10 bytes) followed by one valid frame
    int version = 3, layer = 1, bitrateIndex = 1, samplerateIndex = 0, emphasis = 0;
    boolean hasCRC = false, padding = false;
    int header =
        buildHeader(version, layer, hasCRC, bitrateIndex, samplerateIndex, padding, emphasis);
    int frameLength = computeFrameLength(version, layer, bitrateIndex, samplerateIndex, padding);

    byte[] frameOnly;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(header);
      byte[] payload = new byte[frameLength - 4];
      for (int i = 0; i < payload.length; i++) payload[i] = (byte) (0xA0 + i);
      dos.write(payload);
      frameOnly = bos.toByteArray();
    }

    byte[] id3v2 = new byte[10];
    id3v2[0] = 0x49; // 'I'
    id3v2[1] = 0x44; // 'D'
    id3v2[2] = 0x33; // '3'
    id3v2[3] = 0x00; // version check mask matches
    id3v2[4] = 0x04; // minor version
    id3v2[5] = 0x00; // flags
    // size = 0 (synchsafe int of 4 bytes all zero)
    // id3v2[6..9] already zero

    byte[] input = new byte[id3v2.length + frameOnly.length];
    System.arraycopy(id3v2, 0, input, 0, id3v2.length);
    System.arraycopy(frameOnly, 0, input, id3v2.length, frameOnly.length);

    // Act
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    new MP3Filter().filter(new ByteArrayInputStream(input), out);

    // Assert: tag stripped, only frame remains
    assertArrayEquals(frameOnly, out.toByteArray(), "ID3v2 tag must be skipped");
  }

  @Test
  void filter_whenId3v1Tag_thenValidFrame_expectTagStripped() throws IOException {
    // Arrange: ID3v1 (128 bytes: 4 already read + 124 to skip) then one valid frame
    int version = 3, layer = 1, bitrateIndex = 1, samplerateIndex = 0, emphasis = 0;
    boolean hasCRC = false, padding = false;
    int header =
        buildHeader(version, layer, hasCRC, bitrateIndex, samplerateIndex, padding, emphasis);
    int frameLength = computeFrameLength(version, layer, bitrateIndex, samplerateIndex, padding);

    byte[] frameOnly;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(header);
      byte[] payload = new byte[frameLength - 4];
      for (int i = 0; i < payload.length; i++) payload[i] = (byte) (0x7F - i);
      dos.write(payload);
      frameOnly = bos.toByteArray();
    }

    byte[] id3v1 = new byte[128];
    id3v1[0] = 0x54; // 'T'
    id3v1[1] = 0x41; // 'A'
    id3v1[2] = 0x47; // 'G'
    id3v1[3] = 0x00; // match mask 0x54414700
    // remaining 124 bytes are zero by default

    byte[] input = new byte[id3v1.length + frameOnly.length];
    System.arraycopy(id3v1, 0, input, 0, id3v1.length);
    System.arraycopy(frameOnly, 0, input, id3v1.length, frameOnly.length);

    // Act
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    new MP3Filter().filter(new ByteArrayInputStream(input), out);

    // Assert
    assertArrayEquals(frameOnly, out.toByteArray(), "ID3v1 tag must be skipped");
  }

  // ---- Test helpers ----

  private static int buildHeader(
      int version,
      int layer,
      boolean hasCRC,
      int bitrateIndex,
      int samplerateIndex,
      boolean padding,
      int emphasis) {
    int h = 0;
    h |= 0xFFE00000; // sync
    h |= (version & 0x3) << 19;
    h |= (layer & 0x3) << 17;
    h |= ((hasCRC ? 0 : 1) & 0x1) << 16; // inverted
    h |= (bitrateIndex & 0xF) << 12;
    h |= (samplerateIndex & 0x3) << 10;
    h |= (padding ? 1 : 0) << 9;
    h |= (emphasis & 0x3);
    return h;
  }

  private static int computeFrameLength(
      int version, int layer, int bitrateIndex, int samplerateIndex, boolean padding) {
    int bitrate = MP3Filter.bitRateIndices[version][layer][bitrateIndex] * 1000;
    int samplerate = MP3Filter.sampleRateIndices[version][samplerateIndex];
    int samples = MP3Filter.samplesPerFrame[version][layer];
    int granularity = MP3Filter.bitsPerSlot[layer];
    int frameLength = samples / granularity * bitrate / samplerate;
    if (padding) frameLength += 1;
    // Avoid intermediate integer truncation on (granularity / 8)
    frameLength = (frameLength * granularity) / 8;
    return frameLength;
  }

  /**
   * Minimal wrapper exposing a DataOutputStream over a fixed backing array without reallocations.
   * Throws if more bytes are written than the provided array can hold.
   */
  private static class ByteArrayOutputStreamWrapper extends ByteArrayOutputStream {
    ByteArrayOutputStreamWrapper(byte[] backing) {
      super(backing.length);
      this.buf = backing;
    }

    @Override
    public synchronized void write(int b) {
      if (count >= buf.length) throw new IndexOutOfBoundsException("overflow");
      super.write(b);
    }

    @Override
    public synchronized void write(byte @NotNull [] b, int off, int len) {
      if (count + len > buf.length) throw new IndexOutOfBoundsException("overflow");
      super.write(b, off, len);
    }
  }

  /**
   * Loads a resource relative to the resource path into a Bucket.
   *
   * @throws AssertionError on failure
   */
  private static Bucket resourceToBucket(String filename) {
    try {
      return ResourceFileUtil.resourceToBucket(RESOURCE_PATH + filename);
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  private static final String RESOURCE_PATH = "mp3/";

  /** Known good files, should pass filter unaltered. */
  private static final String[] GOOD = {
    // MPEG ADTS, layer III, v2.5, 8 kbps, 8 kHz, Stereo
    "8khz-8kbps-cbr-stereo.mp3",
    // MPEG ADTS, layer III, v2.5, 48 kbps, 11.025 kHz, Stereo
    "11khz-48kbps-cbr-stereo.mp3",
    // MPEG ADTS, layer III, v2, 56 kbps, 16 kHz, Stereo
    "16khz-56kbps-cbr-stereo.mp3",
    // MPEG ADTS, layer III, v2, 96 kbps, 22.05 kHz, Stereo
    "22khz-96kbps-cbr-stereo.mp3",
    // MPEG ADTS, layer III, v1, 96 kbps, 32 kHz, Stereo
    "32khz-96kbps-cbr-stereo.mp3",
    // MPEG ADTS, layer III, v1, 96 kbps, 44.1 kHz, Stereo
    "44khz-96kbps-cbr-stereo.mp3",
    // MPEG ADTS, layer III, v1, 128 kbps, 48 kHz, Stereo
    "48khz-64kbps-vbr-stereo.mp3",
    // MPEG ADTS, layer III, v1, 128 kbps, 48 kHz, JntStereo
    "48khz-96kbps-vbr-joint.mp3",
    // MPEG ADTS, layer III, v1, 128 kbps, 48 kHz, Stereo
    "48khz-128kbps-cbr-stereo.mp3",
    // MPEG ADTS, layer III, v1, 320 kbps, 48 kHz, JntStereo
    "48khz-320kbps-cbr-joint.mp3"
  };

  /** Pairs of unfiltered file and their expected output file. */
  private static final String[][] FILTER_PAIRS = {
    // random + 48khz-96kbps-vbr-joint + random + 48khz-96kbps-vbr-joint + random
    // Random data is to be removed, leaving file with duplicate 48khz-96kbps-vbr-joint
    new String[] {
      "48khz-96kbps-vbr-joint-randompadding-unfiltered.mp3",
      "48khz-96kbps-vbr-joint-randompadding-expected.mp3"
    },
    // 48khz-128kbps-cbr-stereo with ID3v2 tags to be stripped
    new String[] {"48khz-128kbps-cbr-stereo-id3v2.mp3", "48khz-128kbps-cbr-stereo.mp3"}
  };
}
