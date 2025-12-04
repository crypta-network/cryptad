package org.bitpedia.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.DigestException;
import java.util.Arrays;
import java.util.LinkedList;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Intentional method naming: method_whenCondition_expectOutcome
class TigerTreeTest {
  private static final int BLOCK_SIZE = 1024;
  private static final int HASH_SIZE = 24;

  @Test
  void digest_whenInputEmpty_matchesExpectedTigerTreeHash() {
    TigerTree tigerTree = new TigerTree();

    byte[] digest = tigerTree.digest();

    assertArrayEquals(computeExpectedTigerTree(new byte[0]), digest);
  }

  @Test
  void digest_whenInputExactlyOneBlock_usesLeafHashOnly() {
    byte[] data = buildSequentialBytes(BLOCK_SIZE);
    TigerTree tigerTree = new TigerTree();
    tigerTree.update(data);

    byte[] digest = tigerTree.digest();

    assertArrayEquals(computeExpectedTigerTree(data), digest);
  }

  @Test
  void digest_whenInputAcrossMultipleBlocks_constructsBalancedTree() {
    byte[] data = buildSequentialBytes(1500); // crosses one block boundary
    TigerTree tigerTree = new TigerTree();

    tigerTree.update(data, 0, 1200); // triggers internal block rollover
    tigerTree.update(data, 1200, 300);

    byte[] digest = tigerTree.digest();

    assertArrayEquals(computeExpectedTigerTree(data), digest);
  }

  @Test
  void digest_whenInputCoversPowerOfTwoBlocks_composesAllLevels() {
    byte[] data = buildSequentialBytes(4 * BLOCK_SIZE); // forces multiple composeNodes calls
    TigerTree tigerTree = new TigerTree();

    for (byte value : data) {
      tigerTree.update(value); // exercise single-byte update path
    }

    byte[] digest = tigerTree.digest();

    assertArrayEquals(computeExpectedTigerTree(data), digest);
  }

  @Test
  void digest_whenUsingOutputOffset_writesDigestAtRequestedPosition() throws DigestException {
    byte[] data = buildSequentialBytes(250);
    TigerTree tigerTree = new TigerTree();
    tigerTree.update(data);
    byte[] output = new byte[HASH_SIZE + 4];
    output[0] = (byte) 0x7F; // sentinel to verify untouched prefix

    int written = tigerTree.digest(output, 2, HASH_SIZE);

    assertEquals(HASH_SIZE, written);
    assertEquals((byte) 0x7F, output[0]);
    assertArrayEquals(computeExpectedTigerTree(data), Arrays.copyOfRange(output, 2, 2 + HASH_SIZE));
  }

  @Test
  void digest_whenBufferTooSmall_throwsDigestException() {
    TigerTree tigerTree = new TigerTree();
    byte[] tooSmall = new byte[HASH_SIZE - 1];

    assertThrows(DigestException.class, () -> tigerTree.digest(tooSmall, 0, tooSmall.length));
  }

  @Test
  void reset_whenCalledBeforeDigest_discardsBufferedInput() {
    TigerTree tigerTree = new TigerTree();
    tigerTree.update(new byte[] {1, 2, 3, 4});

    tigerTree.reset();
    byte[] data = new byte[] {9, 8, 7};
    tigerTree.update(data);
    byte[] digest = tigerTree.digest();

    assertArrayEquals(computeExpectedTigerTree(data), digest);
  }

  private static byte[] buildSequentialBytes(int size) {
    byte[] data = new byte[size];
    for (int i = 0; i < size; i++) {
      data[i] = (byte) (i & 0xFF);
    }
    return data;
  }

  private static byte[] computeExpectedTigerTree(byte[] data) {
    TigerDigest tiger = new TigerDigest();
    LinkedList<byte[]> nodes = new LinkedList<>();

    if (data.length == 0) {
      nodes.add(digestLeaf(tiger, new byte[0], 0, 0));
    } else {
      int offset = 0;
      long blockCount = 0;
      while (offset < data.length) {
        int remaining = Math.min(BLOCK_SIZE, data.length - offset);
        nodes.add(digestLeaf(tiger, data, offset, remaining));
        blockCount++;
        long interim = blockCount;
        while ((interim & 1) == 0) {
          composeNodes(tiger, nodes);
          interim >>= 1;
        }
        offset += remaining;
      }
    }

    while (nodes.size() > 1) {
      composeNodes(tiger, nodes);
    }
    return nodes.getFirst();
  }

  private static byte[] digestLeaf(TigerDigest tiger, byte[] data, int offset, int length) {
    tiger.reset();
    tiger.update((byte) 0);
    tiger.update(data, offset, length);
    byte[] out = new byte[HASH_SIZE];
    tiger.doFinal(out, 0);
    return out;
  }

  private static void composeNodes(TigerDigest tiger, LinkedList<byte[]> nodes) {
    byte[] right = nodes.removeLast();
    byte[] left = nodes.removeLast();
    tiger.reset();
    tiger.update((byte) 1);
    tiger.update(left, 0, left.length);
    tiger.update(right, 0, right.length);
    byte[] parent = new byte[HASH_SIZE];
    tiger.doFinal(parent, 0);
    nodes.add(parent);
  }
}
