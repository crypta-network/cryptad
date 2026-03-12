package org.sevenzip.compression.rangecoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SuppressWarnings("java:S100")
class DecoderTest {

  @Test
  void init_whenStreamHasFiveBytes_setsRangeAndCode() throws IOException {
    byte[] seed = new byte[] {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    Decoder decoder = new Decoder();
    decoder.setStream(new ByteArrayInputStream(seed));

    decoder.init();

    assertEquals(-1, decoder.range);
    assertEquals(0x11223344, decoder.code);
    assertNotNull(decoder.stream);
  }

  @Test
  void decodeDirectBits_whenEncodedWithEncoder_returnsOriginalValue() throws IOException {
    int value = 0b101101;
    int bitCount = 6;
    byte[] encoded = encodeDirectBits(value, bitCount);

    Decoder decoder = new Decoder();
    decoder.setStream(new ByteArrayInputStream(encoded));
    decoder.init();

    int decoded = decoder.decodeDirectBits(bitCount);

    assertEquals(value, decoded);
  }

  @Test
  void decodeBit_whenRoundTrippedThroughEncoder_matchesSymbolsAndUpdatesProbabilities()
      throws IOException {
    List<Integer> symbols = List.of(0, 1, 0, 1, 1);
    byte[] encoded = encodeAdaptiveBits(symbols);

    short[] probabilities = new short[1];
    Decoder.initBitModels(probabilities);

    Decoder decoder = new Decoder();
    decoder.setStream(new ByteArrayInputStream(encoded));
    decoder.init();

    List<Integer> decoded = new ArrayList<>();
    for (var _ : symbols) {
      decoded.add(decoder.decodeBit(probabilities, 0));
    }

    assertEquals(symbols, decoded);
    assertEquals(expectedProbabilityAfter(symbols), probabilities[0]);
  }

  private static byte[] encodeDirectBits(int value, int bitCount) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Encoder encoder = new Encoder();
    encoder.setStream(out);
    encoder.init();
    encoder.encodeDirectBits(value, bitCount);
    encoder.flushData();
    encoder.flushStream();
    return out.toByteArray();
  }

  private static byte[] encodeAdaptiveBits(List<Integer> bits) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Encoder encoder = new Encoder();
    encoder.setStream(out);
    encoder.init();
    short[] probabilities = new short[1];
    Encoder.initBitModels(probabilities);
    for (int bit : bits) {
      encoder.encode(probabilities, 0, bit);
    }
    encoder.flushData();
    encoder.flushStream();
    return out.toByteArray();
  }

  private static short expectedProbabilityAfter(List<Integer> bits) {
    int prob = Decoder.BIT_MODEL_TOTAL >>> 1;
    for (int bit : bits) {
      if (bit == 0) {
        prob = prob + ((Decoder.BIT_MODEL_TOTAL - prob) >>> Decoder.NUM_MOVE_BITS);
      } else {
        prob = prob - (prob >>> Decoder.NUM_MOVE_BITS);
      }
    }
    return (short) prob;
  }
}
