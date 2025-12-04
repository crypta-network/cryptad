package org.sevenzip.compression.rangecoder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class EncoderTest {

  @Mock OutputStream mockStream;

  @Test
  void init_setsInitialState_expectDefaults() {
    Encoder encoder = new Encoder();

    encoder.init();

    assertEquals(0, encoder.position);
    assertEquals(0, encoder.low);
    assertEquals(-1, encoder.range);
    assertEquals(1, encoder.cacheSize);
    assertEquals(0, encoder.cache);
  }

  @Test
  void setStream_and_releaseStream_expectLifecycleUpdates() {
    Encoder encoder = new Encoder();
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    encoder.setStream(out);
    encoder.releaseStream();

    assertNull(encoder.stream);
  }

  @Test
  void flushStream_delegatesToUnderlyingStream() throws IOException {
    Encoder encoder = new Encoder();
    encoder.setStream(mockStream);

    encoder.flushStream();

    verify(mockStream).flush();
  }

  @Test
  void shiftLow_writesByte_whenLowBelowThreshold() throws IOException {
    Encoder encoder = new Encoder();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    encoder.setStream(out);
    encoder.init();

    encoder.shiftLow();

    assertEquals(1, encoder.position);
    assertEquals(1, encoder.cacheSize);
    assertEquals(0, encoder.cache);
    assertArrayEquals(new byte[] {(byte) 0x00}, out.toByteArray());
  }

  @Test
  void shiftLow_skipsWrite_whenLowAtBoundary() throws IOException {
    Encoder encoder = new Encoder();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    encoder.setStream(out);
    encoder.init();
    encoder.low = 0xFF000000L;

    encoder.shiftLow();

    assertEquals(0, encoder.position);
    assertEquals(2, encoder.cacheSize);
    assertEquals(0, out.size());
  }

  @Test
  void flushData_writesFiveZeroBytes() throws IOException {
    Encoder encoder = new Encoder();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    encoder.setStream(out);
    encoder.init();

    encoder.flushData();

    byte[] expected = new byte[] {0, 0, 0, 0, 0};
    assertArrayEquals(expected, out.toByteArray());
    assertEquals(5, encoder.position);
    assertEquals(1, encoder.cacheSize);
  }

  @Test
  void encode_updatesProbabilityAndRangeForZeroSymbol() throws IOException {
    Encoder encoder = new Encoder();
    encoder.init();
    short[] probs = {(short) 1024};

    encoder.encode(probs, 0, 0);

    assertEquals(0x7FFFFC00, encoder.range);
    assertEquals(0, encoder.low);
    assertEquals((short) 1056, probs[0]);
  }

  @Test
  void encode_updatesStateAndFlushesForOneSymbol_whenRangeBelowTopMask() throws IOException {
    Encoder encoder = new Encoder();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    encoder.setStream(out);
    encoder.init();
    encoder.range = 0x00FFFFFF;
    short[] probs = {(short) 1024};

    encoder.encode(probs, 0, 1);

    assertEquals(0x8003FF00, encoder.range);
    assertEquals(0x7FFC0000L, encoder.low);
    assertEquals((short) 992, probs[0]);
    assertArrayEquals(new byte[] {0}, out.toByteArray());
    assertEquals(1, encoder.position);
  }

  @Test
  void encodeDirectBits_writesExpectedBytes_forSixteenBitPattern() throws IOException {
    Encoder encoder = new Encoder();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    encoder.setStream(out);
    encoder.init();

    encoder.encodeDirectBits(0xAAAA, 16);

    assertArrayEquals(new byte[] {0, (byte) 0xAA}, out.toByteArray());
    assertEquals(0xFFFFFF00, encoder.range);
    assertEquals(0xFFFB5600L, encoder.low);
    assertEquals(2, encoder.position);
    assertEquals(0xA9, encoder.cache);
  }

  @Test
  void initBitModels_setsAllEntriesToMidpoint() {
    short[] probs = new short[4];
    Arrays.fill(probs, (short) 0);

    Encoder.initBitModels(probs);

    assertArrayEquals(new short[] {1024, 1024, 1024, 1024}, probs);
  }

  @Test
  void getProcessedSizeAdd_returnsSumOfCacheAndPositionPlusFour() {
    Encoder encoder = new Encoder();
    encoder.init();
    encoder.position = 3;
    encoder.cacheSize = 2;

    long processed = encoder.getProcessedSizeAdd();

    assertEquals(9, processed);
  }

  @Test
  void priceHelpers_returnExpectedValuesForKnownProbabilities() {
    int probMid = 1024;
    int probOff = 600;

    assertEquals(64, Encoder.getPrice0(probMid));
    assertEquals(117, Encoder.getPrice0(probOff));
    assertEquals(37, Encoder.getPrice1(probOff));
    assertEquals(117, Encoder.getPrice(probOff, 0));
    assertEquals(37, Encoder.getPrice(probOff, 1));
  }
}
