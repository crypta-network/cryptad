package org.bitpedia.collider.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class Md5HandlerTest {

  @Test
  void analyzeFinal_whenNoData_returnsMd5OfEmptyInput() {
    Md5Handler handler = new Md5Handler();
    handler.analyzeInit();

    byte[] digest = handler.analyzeFinal();

    assertArrayEquals(computeMd5(new byte[0], 0, 0), digest);
  }

  @Test
  void analyzeFinal_whenDataProvidedInSingleUpdate_returnsMd5OfData() {
    byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);
    Md5Handler handler = new Md5Handler();
    handler.analyzeInit();

    handler.analyzeUpdate(data, data.length);
    byte[] digest = handler.analyzeFinal();

    assertArrayEquals(computeMd5(data, 0, data.length), digest);
  }

  @Test
  void analyzeUpdate_whenOffsetAndLengthUsed_hashesOnlyRequestedSlice() {
    byte[] data = "prefix-target-suffix".getBytes(StandardCharsets.UTF_8);
    int offset = "prefix-".length();
    int length = "target".length();
    Md5Handler handler = new Md5Handler();
    handler.analyzeInit();

    handler.analyzeUpdate(data, offset, length);
    byte[] digest = handler.analyzeFinal();

    assertArrayEquals(computeMd5(data, offset, length), digest);
  }

  @Test
  void analyzeUpdate_whenDataArrivesInChunks_matchesSingleUpdateDigest() {
    byte[] first = "chunk-one-".getBytes(StandardCharsets.UTF_8);
    byte[] second = "chunk-two".getBytes(StandardCharsets.UTF_8);

    Md5Handler single = new Md5Handler();
    single.analyzeInit();
    single.analyzeUpdate(concat(first, second), first.length + second.length);
    byte[] singleDigest = single.analyzeFinal();

    Md5Handler chunked = new Md5Handler();
    chunked.analyzeInit();
    chunked.analyzeUpdate(first, first.length);
    chunked.analyzeUpdate(second, second.length);
    byte[] chunkedDigest = chunked.analyzeFinal();

    assertArrayEquals(singleDigest, chunkedDigest);
  }

  @Test
  void md5_staticMethodWithLength_onlyUsesFirstLenBytes() {
    byte[] data = "abcdef".getBytes(StandardCharsets.UTF_8);
    int len = 3;

    byte[] digest = Md5Handler.md5(data, len);

    assertArrayEquals(computeMd5(data, 0, len), digest);
  }

  @Test
  void md5_staticMethodWithOffsetAndLength_usesSpecifiedWindow() {
    byte[] data = "0123456789".getBytes(StandardCharsets.UTF_8);
    int offset = 2;
    int len = 5;

    byte[] digest = Md5Handler.md5(data, offset, len);

    assertArrayEquals(computeMd5(data, offset, len), digest);
  }

  @Test
  void analyzeUpdate_whenNotInitialized_throwsNullPointerException() {
    Md5Handler handler = new Md5Handler();

    assertThrows(NullPointerException.class, () -> handler.analyzeUpdate(new byte[1], 1));
  }

  private static byte[] computeMd5(byte[] data, int offset, int length) {
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(data, offset, length);
      return md.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("MD5 algorithm not available", e);
    }
  }

  private static byte[] concat(byte[] first, byte[] second) {
    byte[] combined = new byte[first.length + second.length];
    System.arraycopy(first, 0, combined, 0, first.length);
    System.arraycopy(second, 0, combined, first.length, second.length);
    return combined;
  }
}
