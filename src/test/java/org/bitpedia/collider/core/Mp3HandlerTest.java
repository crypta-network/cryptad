package org.bitpedia.collider.core;

import org.bitpedia.util.Sha1;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class Mp3HandlerTest {

  private static final int[] MPEG1_BITRATES = {
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320
  };

  private static final int[] MPEG1_SAMPLE_RATES = {44100, 48000, 32000};

  private Mp3Handler handler;

  @BeforeEach
  void setUp() {
    handler = new Mp3Handler();
    handler.analyzeInit();
  }

  @Test
  void analyzeInit_whenCalled_resetsFieldsToDefaults() {
    handler.setBitRate(999);
    handler.setSampleRate(999);
    handler.setStereo(true);
    handler.setDuration(12);
    handler.setAudioSha(new byte[] {1});
    handler.setFrames(9);
    handler.setMpegVer(2);
    handler.setAvgBitRate(321);

    handler.analyzeInit();

    assertEquals(0, handler.getBitRate());
    assertEquals(0, handler.getSampleRate());
    assertEquals(0, handler.getDuration());
    assertEquals(0, handler.getFrames());
    assertEquals(0, handler.getMpegVer());
    assertEquals(0, handler.getAvgBitRate());
    assertFalse(handler.isStereo());
    assertNull(handler.getAudioSha());
  }

  @Test
  void analyzeUpdate_andFinal_withConstantBitratePopulatesFields() {
    byte[] frame = createMpeg1Frame(/* bitrateIndex= */ 9, /* sampleRateIndex= */ 0, true);
    byte[] buffer = concat(prefix(10), frame, frame, frame, frame);

    handler.analyzeUpdate(buffer, buffer.length);
    handler.analyzeFinal();

    assertEquals(4, handler.getFrames());
    assertEquals(128, handler.getBitRate());
    assertEquals(44100, handler.getSampleRate());
    assertEquals(1, handler.getMpegVer());
    assertTrue(handler.isStereo());
    assertEquals(128, handler.getAvgBitRate());
    assertEquals(104, handler.getDuration()); // 4 * 1152 / (44100 / 1000)
    assertNotNull(handler.getAudioSha());
    assertEquals(Sha1.HASH_LENGTH, handler.getAudioSha().length);
  }

  @Test
  void analyzeUpdate_withVaryingBitrate_setsBitRateToZeroAndComputesAverage() {
    byte[] first = createMpeg1Frame(9, 0, true); // 128 kbps
    byte[] second = createMpeg1Frame(5, 0, true); // 64 kbps
    byte[] third = createMpeg1Frame(5, 0, true); // 64 kbps
    byte[] fourth = createMpeg1Frame(5, 0, true); // 64 kbps
    byte[] buffer = concat(first, second, third, fourth);

    handler.analyzeUpdate(buffer, buffer.length);
    handler.analyzeFinal();

    assertEquals(4, handler.getFrames());
    assertEquals(0, handler.getBitRate()); // marked as VBR
    assertEquals((128 + 64 + 64 + 64) / 4, handler.getAvgBitRate());
  }

  @Test
  void analyzeUpdate_withMonoFrames_setsStereoFalseAndKeepsSampleRate() {
    byte[] frame = createMpeg1Frame(9, 1, false); // 128 kbps, 48 kHz, mono
    byte[] buffer = concat(frame, frame, frame, frame);

    handler.analyzeUpdate(buffer, buffer.length);
    handler.analyzeFinal();

    assertEquals(4, handler.getFrames());
    assertEquals(48000, handler.getSampleRate());
    assertEquals(1, handler.getMpegVer());
    assertFalse(handler.isStereo());
    assertEquals(128, handler.getBitRate());
    assertEquals(96, handler.getDuration()); // 4 * 1152 / (48000 / 1000)
  }

  @Test
  void analyzeFinal_whenBadBytesExceedGood_resetsValues() {
    byte[] garbage = prefix(30);

    handler.analyzeUpdate(garbage, garbage.length);
    handler.analyzeFinal();

    assertEquals(0, handler.getBitRate());
    assertEquals(0, handler.getSampleRate());
    assertEquals(0, handler.getFrames());
    assertEquals(0, handler.getDuration());
    assertNull(handler.getAudioSha());
  }

  @Test
  void analyzeUpdate_whenHeaderSpansBuffers_processesAcrossBlocks() {
    byte[] frame = createMpeg1Frame(9, 0, true);
    byte[] splitFrame = createMpeg1Frame(9, 0, true);

    byte[] splitHeader = new byte[4];
    System.arraycopy(splitFrame, 0, splitHeader, 0, 4);

    byte[] part1 = concat(frame, frame, frame, slice(splitHeader, 0, 3));
    byte[] part2 = concat(slice(splitHeader, 3, 1), slice(splitFrame, 4, splitFrame.length - 4));

    handler.analyzeUpdate(part1, part1.length);

    assertEquals(3, handler.getFrames());

    handler.analyzeUpdate(part2, part2.length);
    handler.analyzeFinal();

    assertEquals(4, handler.getFrames());
    assertEquals(128, handler.getBitRate());
    assertEquals(44100, handler.getSampleRate());
  }

  private static byte[] createMpeg1Frame(int bitrateIndex, int sampleRateIndex, boolean stereo) {
    int bitrate = MPEG1_BITRATES[bitrateIndex];
    int sampleRate = MPEG1_SAMPLE_RATES[sampleRateIndex];

    byte[] header = new byte[4];
    header[0] = (byte) 0xFF;
    header[1] = (byte) 0xFB; // mpeg1, layer III, no protection
    header[2] = (byte) ((bitrateIndex << 4) | (sampleRateIndex << 2));
    header[3] = stereo ? (byte) 0x00 : (byte) 0xC0;

    int size = (144000 * bitrate) / sampleRate;
    byte[] frame = new byte[size];
    System.arraycopy(header, 0, frame, 0, header.length);
    // rest filled with zeros
    return frame;
  }

  private static byte[] prefix(int length) {
    return new byte[length];
  }

  private static byte[] concat(byte[]... arrays) {
    int total = 0;
    for (byte[] arr : arrays) {
      total += arr.length;
    }
    byte[] result = new byte[total];
    int pos = 0;
    for (byte[] arr : arrays) {
      System.arraycopy(arr, 0, result, pos, arr.length);
      pos += arr.length;
    }
    return result;
  }

  private static byte[] slice(byte[] source, int offset, int length) {
    byte[] result = new byte[length];
    System.arraycopy(source, offset, result, 0, length);
    return result;
  }
}
