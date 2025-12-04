package org.sevenzip.compression.lzma;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class DecoderTest {

  private static byte[] properties(int lc, int lp, int pb, int dictSize) {
    int remainder = lp + pb * 5;
    int val = lc + 9 * remainder;
    byte[] props = new byte[5];
    props[0] = (byte) val;
    props[1] = (byte) (dictSize & 0xFF);
    props[2] = (byte) ((dictSize >>> 8) & 0xFF);
    props[3] = (byte) ((dictSize >>> 16) & 0xFF);
    props[4] = (byte) ((dictSize >>> 24) & 0xFF);
    return props;
  }

  @Test
  void setDecoderProperties_whenTooShort_returnsFalse() {
    Decoder decoder = new Decoder();

    boolean result = decoder.setDecoderProperties(new byte[] {1, 2, 3, 4});

    assertFalse(result);
    assertEquals(-1, decoder.dictionarySize);
    assertEquals(-1, decoder.dictionarySizeCheck);
  }

  @Test
  void setDecoderProperties_whenPbExceedsLimit_returnsFalse() {
    Decoder decoder = new Decoder();
    // pb=5 exceeds Base.NUM_POS_STATES_BITS_MAX (4)
    byte[] props = properties(0, 0, Base.NUM_POS_STATES_BITS_MAX + 1, 64);

    boolean result = decoder.setDecoderProperties(props);

    assertFalse(result);
    assertEquals(-1, decoder.dictionarySize);
    assertEquals(-1, decoder.dictionarySizeCheck);
  }

  @Test
  void setDecoderProperties_withValidValues_initializesModels() {
    Decoder decoder = new Decoder();
    int dictSize = 8192;
    byte[] props = properties(3, 1, 2, dictSize);

    boolean result = decoder.setDecoderProperties(props);

    assertTrue(result);
    assertEquals(dictSize, decoder.dictionarySize);
    assertEquals(dictSize, decoder.dictionarySizeCheck);
    assertEquals(dictSize, (int) readObjectField(decoder.outWindow, "windowSize"));
    assertEquals((1 << 2) - 1, decoder.posStateMask);
    assertEquals(1 << 2, decoder.lenDecoder.numPosStates);
    assertEquals(1 << (3 + 1), decoder.literalDecoder.coders.length);
  }

  @Test
  void setDictionarySize_whenNegative_doesNotChangeExistingConfiguration() {
    Decoder decoder = new Decoder();
    decoder.setDictionarySize(4096);

    boolean result = decoder.setDictionarySize(-5);

    assertFalse(result);
    assertEquals(4096, decoder.dictionarySize);
    assertEquals(4096, (int) readObjectField(decoder.outWindow, "windowSize"));
  }

  @Test
  void setLcLpPb_whenLcExceedsLimit_returnsFalse() {
    Decoder decoder = new Decoder();

    boolean result = decoder.setLcLpPb(Base.NUM_LIT_CONTEXT_BITS_MAX + 1, /* lp= */ 0, /* pb= */ 0);

    assertFalse(result);
  }

  @Test
  void code_whenOutSizeZero_performsInitAndReturnsTrue() throws Exception {
    Decoder decoder = new Decoder();
    decoder.setDecoderProperties(properties(2, 0, 1, 4096));
    ByteArrayInputStream in = new ByteArrayInputStream(new byte[10]);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    boolean result = decoder.code(in, out, 0);

    assertTrue(result);
    assertEquals(0, out.size());
    assertNull(readObjectField(decoder.outWindow, "stream"));
    assertNull(readObjectField(decoder.rangeDecoder, "stream"));
  }

  private static Object readObjectField(Object target, String fieldName) {
    try {
      Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.get(target);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Failed to read field via reflection", e);
    }
  }
}
