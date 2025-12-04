package org.sevenzip.compression.lzma;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S100")
class EncoderTest {

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2})
  void setAlgorithm_withinRange_returnsTrue(int algorithm) {
    Encoder encoder = new Encoder();

    assertTrue(encoder.setAlgorithm(algorithm));
  }

  @Test
  void setAlgorithm_outOfRange_returnsFalse() {
    Encoder encoder = new Encoder();

    assertFalse(encoder.setAlgorithm(-1));
    assertFalse(encoder.setAlgorithm(3));
  }

  @Test
  void setDictionarySize_withinBounds_updatesDictionaryAndDistTable() {
    Encoder encoder = new Encoder();
    int newSize = 1 << 10;

    boolean updated = encoder.setDictionarySize(newSize);

    assertTrue(updated);
    assertEquals(newSize, encoder.dictionarySize);
    assertEquals(20, encoder.distTableSize);
  }

  @Test
  void setDictionarySize_aboveMax_rejectedAndStateUnchanged() {
    Encoder encoder = new Encoder();
    int originalSize = encoder.dictionarySize;
    int originalDistTable = encoder.distTableSize;

    boolean updated = encoder.setDictionarySize(1 << 30);

    assertFalse(updated);
    assertEquals(originalSize, encoder.dictionarySize);
    assertEquals(originalDistTable, encoder.distTableSize);
  }

  @Test
  void setNumFastBytes_enforcesBounds() {
    Encoder encoder = new Encoder();
    int original = encoder.numFastBytes;

    assertTrue(encoder.setNumFastBytes(16));
    assertEquals(16, encoder.numFastBytes);

    assertFalse(encoder.setNumFastBytes(4));
    assertEquals(16, encoder.numFastBytes);

    assertFalse(encoder.setNumFastBytes(Base.MATCH_MAX_LEN + 1));
    assertEquals(16, encoder.numFastBytes);
    // restore to original for isolation
    assertTrue(encoder.setNumFastBytes(original));
  }

  @Test
  void setMatchFinder_switchesTypeWhenValid() {
    Encoder encoder = new Encoder();

    boolean updated = encoder.setMatchFinder(Encoder.MATCH_FINDER_TYPE_BT2);

    assertTrue(updated);
    assertEquals(Encoder.MATCH_FINDER_TYPE_BT2, encoder.matchFinderType);
    // matchFinder stays null until create() is called
    assertNull(encoder.matchFinder);
    assertEquals(-1, encoder.dictionarySizePrev);
  }

  @Test
  void setMatchFinder_rejectsOutOfRangeValues() {
    Encoder encoder = new Encoder();

    boolean updated = encoder.setMatchFinder(5);

    assertFalse(updated);
    assertEquals(Encoder.MATCH_FINDER_TYPE_BT4, encoder.matchFinderType);
  }

  @Test
  void setLcLpPb_updatesInternalMasks() {
    Encoder encoder = new Encoder();

    boolean updated = encoder.setLcLpPb(1, 2, 3);

    assertTrue(updated);
    assertEquals(1, encoder.numLiteralContextBits);
    assertEquals(2, encoder.numLiteralPosStateBits);
    assertEquals(3, encoder.posStateBits);
    assertEquals((1 << 3) - 1, encoder.posStateMask);
  }

  @Test
  void setLcLpPb_rejectsInvalidParameters() {
    Encoder encoder = new Encoder();
    int originalLc = encoder.numLiteralContextBits;
    int originalLp = encoder.numLiteralPosStateBits;
    int originalPb = encoder.posStateBits;
    int originalMask = encoder.posStateMask;

    boolean updated = encoder.setLcLpPb(Base.NUM_LIT_CONTEXT_BITS_MAX + 1, 0, 0);

    assertFalse(updated);
    assertEquals(originalLc, encoder.numLiteralContextBits);
    assertEquals(originalLp, encoder.numLiteralPosStateBits);
    assertEquals(originalPb, encoder.posStateBits);
    assertEquals(originalMask, encoder.posStateMask);
  }

  @Test
  void writeCoderProperties_emitsExpectedByteLayout() throws IOException {
    Encoder encoder = new Encoder();
    encoder.setLcLpPb(1, 2, 3);
    encoder.setDictionarySize(0x00123456);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    encoder.writeCoderProperties(output);

    byte[] props = output.toByteArray();
    assertEquals(Encoder.PROP_SIZE, props.length);
    assertArrayEquals(new byte[] {(byte) 0x9A, 0x56, 0x34, 0x12, 0x00}, props);
  }

  @Test
  void setEndMarkerMode_togglesFlag() {
    Encoder encoder = new Encoder();
    assertFalse(encoder.writeEndMark);

    encoder.setEndMarkerMode(true);

    assertTrue(encoder.writeEndMark);
  }

  @Test
  void literalEncoder_getSubCoder_returnsConsistentInstance() {
    Encoder.LiteralEncoder literalEncoder = new Encoder.LiteralEncoder();
    literalEncoder.create(1, 2);

    Encoder.LiteralEncoder.Encoder2 coderA = literalEncoder.getSubCoder(3, (byte) 0x10);
    Encoder.LiteralEncoder.Encoder2 coderB = literalEncoder.getSubCoder(3, (byte) 0x10);
    Encoder.LiteralEncoder.Encoder2 coderC = literalEncoder.getSubCoder(2, (byte) 0x10);

    assertSame(coderA, coderB);
    assertNotSame(coderA, coderC);
  }

  @Test
  void literalEncoder_getPrice_matchAndLiteralAgreeForSameBytes() {
    Encoder.LiteralEncoder.Encoder2 coder = new Encoder.LiteralEncoder.Encoder2();
    coder.init();
    byte symbol = (byte) 0x5A;

    int literalPrice = coder.getPrice(false, (byte) 0x00, symbol);
    int matchedPrice = coder.getPrice(true, symbol, symbol);

    assertEquals(literalPrice, matchedPrice);
    assertTrue(matchedPrice > 0);
  }

  @Test
  void lenPriceTableEncoder_updateTables_resetsCounters() {
    Encoder.LenPriceTableEncoder lenPriceTableEncoder = new Encoder.LenPriceTableEncoder();
    lenPriceTableEncoder.setTableSize(4);
    lenPriceTableEncoder.init(4);

    lenPriceTableEncoder.updateTables(4);

    for (int posState = 0; posState < 4; posState++) {
      assertEquals(4, lenPriceTableEncoder.counters[posState]);
    }
  }
}
