package org.bitpedia.collider.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class KzTreeHandlerTest {

  private static final int BLOCK_SIZE = 32 * 1024;

  @Test
  void analyzeFinal_whenInputEmpty_returnsDoubleMd5OfEmpty() {
    KzTreeHandler handler = new KzTreeHandler();
    handler.analyzeInit();

    byte[] digest = handler.analyzeFinal();

    byte[] expected = md5(md5(new byte[0]));
    assertArrayEquals(expected, digest);
  }

  @Test
  void analyzeFinal_whenSingleShortBlock_returnsDoubleMd5OfData() {
    byte[] data = "hello world".getBytes(StandardCharsets.US_ASCII);
    KzTreeHandler handler = new KzTreeHandler();
    handler.analyzeInit();

    handler.analyzeUpdate(data, 0, data.length);
    byte[] digest = handler.analyzeFinal();

    byte[] expected = md5(md5(data));
    assertArrayEquals(expected, digest);
  }

  @Test
  void analyzeFinal_whenTwoFullBlocks_combinesBlockDigests() {
    byte[] block1 = filledBlock((byte) 0x11);
    byte[] block2 = filledBlock((byte) 0x22);
    KzTreeHandler handler = new KzTreeHandler();
    handler.analyzeInit();

    handler.analyzeUpdate(block1, 0, block1.length);
    handler.analyzeUpdate(block2, 0, block2.length);
    byte[] digest = handler.analyzeFinal();

    byte[] expected = md5(concat(md5(block1), md5(block2))); // parent = MD5(child1||child2)
    assertArrayEquals(expected, digest);
  }

  @Test
  void analyzeFinal_whenThreeBlocks_usesOddComposeRule() {
    byte[] block1 = filledBlock((byte) 0x33);
    byte[] block2 = filledBlock((byte) 0x44);
    byte[] block3 = filledBlock((byte) 0x55);
    KzTreeHandler handler = new KzTreeHandler();
    handler.analyzeInit();

    handler.analyzeUpdate(block1, 0, block1.length);
    handler.analyzeUpdate(block2, 0, block2.length);
    handler.analyzeUpdate(block3, 0, block3.length);
    byte[] digest = handler.analyzeFinal();

    byte[] m1 = md5(block1);
    byte[] m2 = md5(block2);
    byte[] m3 = md5(block3);
    byte[] parent12 = md5(concat(m1, m2));
    byte[] hashedThird = md5(m3); // odd compose re-hashes the lone child
    byte[] expectedRoot = md5(concat(parent12, hashedThird));

    assertArrayEquals(expectedRoot, digest);
  }

  @Test
  void analyzeUpdate_whenFedInChunks_matchesSinglePassDigest() {
    byte[] data = new byte[BLOCK_SIZE + 17];
    Arrays.fill(data, (byte) 0x7A);

    KzTreeHandler streaming = new KzTreeHandler();
    streaming.analyzeInit();
    streaming.analyzeUpdate(data, 0, 10);
    streaming.analyzeUpdate(data, 10, data.length - 10);
    byte[] streamingDigest = streaming.analyzeFinal();

    KzTreeHandler singlePass = new KzTreeHandler();
    singlePass.analyzeInit();
    singlePass.analyzeUpdate(data, 0, data.length);
    byte[] singlePassDigest = singlePass.analyzeFinal();

    assertArrayEquals(singlePassDigest, streamingDigest);
  }

  private static byte[] filledBlock(byte value) {
    byte[] block = new byte[BLOCK_SIZE];
    Arrays.fill(block, value);
    return block;
  }

  private static byte[] concat(byte[] left, byte[] right) {
    byte[] combined = new byte[left.length + right.length];
    System.arraycopy(left, 0, combined, 0, left.length);
    System.arraycopy(right, 0, combined, left.length, right.length);
    return combined;
  }

  private static byte[] md5(byte[] data) {
    try {
      MessageDigest digest = MessageDigest.getInstance("MD5");
      return digest.digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("MD5 algorithm missing", e);
    }
  }
}
