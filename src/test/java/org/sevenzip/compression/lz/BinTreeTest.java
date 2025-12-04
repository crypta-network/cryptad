package org.sevenzip.compression.lz;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class BinTreeTest {

  @Test
  void setType_whenNumHashBytesLessOrEqualTo2_setsDirectMatchParams() {
    BinTree binTree = new BinTree();

    binTree.setType(2);

    assertAll(
        () -> assertFalse(binTree.hashArray),
        () -> assertEquals(2, binTree.kNumHashDirectBytes),
        () -> assertEquals(3, binTree.kMinMatchCheck),
        () -> assertEquals(0, binTree.kFixHashSize));
  }

  @Test
  void setType_whenNumHashBytesGreaterThan2_enablesHashArrayAndDefaults() {
    BinTree binTree = new BinTree();

    binTree.setType(4);

    assertAll(
        () -> assertTrue(binTree.hashArray),
        () -> assertEquals(0, binTree.kNumHashDirectBytes),
        () -> assertEquals(4, binTree.kMinMatchCheck),
        () -> assertEquals(BinTree.K_HASH2_SIZE + BinTree.K_HASH3_SIZE, binTree.kFixHashSize));
  }

  @Test
  void normalizeLinks_whenValuesBelowOrEqualSubValue_clearsAndShifts() {
    BinTree binTree = new BinTree();
    int[] values = {5, 6, 3};

    binTree.normalizeLinks(values, values.length, 5);

    assertArrayEquals(new int[] {0, 1, 0}, values);
  }

  @Test
  void normalize_whenOffsetsExceedCyclicBuffer_adjustsStateAndArrays() {
    BinTree binTree = new BinTree();
    binTree.cyclicBufferSize = 4;
    binTree.pos = 10;
    binTree.bufferOffset = 0;
    binTree.posLimit = 12;
    binTree.streamPos = 13;
    binTree.son = new int[] {6, 7, 8, 5, 12, 1, 9, 6};
    binTree.hashSizeSum = 4;
    binTree.hash = new int[] {10, 4, 7, 6};

    binTree.normalize();

    assertAll(
        () -> assertArrayEquals(new int[] {0, 1, 2, 0, 6, 0, 3, 0}, binTree.son),
        () -> assertArrayEquals(new int[] {4, 0, 1, 0}, binTree.hash),
        () -> assertEquals(4, binTree.pos),
        () -> assertEquals(6, binTree.bufferOffset),
        () -> assertEquals(6, binTree.posLimit),
        () -> assertEquals(7, binTree.streamPos));
  }

  @Test
  void getMatches_whenLookaheadInsufficient_returnsZeroAndAdvancesPosition() throws IOException {
    BinTree binTree = new BinTree();
    binTree.setType(4);
    binTree.createMatchFinder(8, 0, 16, 1);
    binTree.setStream(new ByteArrayInputStream(new byte[] {1, 2}));
    binTree.init();
    int[] distances = new int[4];

    int result = binTree.getMatches(distances);

    assertAll(() -> assertEquals(0, result), () -> assertEquals(2, binTree.pos));
  }

  @Test
  void getMatches_whenPatternRepeats_returnsLongestMatchAndDistance() throws IOException {
    BinTree binTree = new BinTree();
    binTree.setType(4);
    binTree.createMatchFinder(16, 0, 6, 1);
    binTree.setStream(new ByteArrayInputStream("abcabcabc".getBytes(StandardCharsets.US_ASCII)));
    binTree.init();
    int[] scratch = new int[20];
    for (int i = 0; i < 3; i++) {
      binTree.getMatches(scratch);
    }
    int[] distances = new int[20];

    int offset = binTree.getMatches(distances);

    boolean foundLongestRepeat = false;
    for (int i = 0; i < offset; i += 2) {
      if (distances[i] == 6 && distances[i + 1] == 2) {
        foundLongestRepeat = true;
        break;
      }
    }
    final boolean longestRepeatDetected = foundLongestRepeat;

    assertAll(
        () -> assertTrue(offset >= 2),
        () -> assertTrue(longestRepeatDetected),
        () -> assertEquals(5, binTree.pos));
  }

  @Test
  void skip_whenAdvancingMultiplePositions_updatesInternalPosition() throws IOException {
    BinTree binTree = new BinTree();
    binTree.setType(4);
    binTree.createMatchFinder(8, 0, 4, 1);
    binTree.setStream(new ByteArrayInputStream("aaaaaa".getBytes(StandardCharsets.US_ASCII)));
    binTree.init();

    binTree.skip(2);

    assertEquals(3, binTree.pos);
  }
}
