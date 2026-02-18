package org.bitpedia.collider.core;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class Md4HandlerTest {

  private Md4Handler handler;

  @BeforeEach
  void setUp() {
    handler = new Md4Handler();
    handler.analyzeInit();
  }

  @Test
  void analyzeFinal_whenNoInput_returnsMd4OfEmptyString() {
    byte[] digest = handler.analyzeFinal();

    assertEquals("31d6cfe0d16ae931b73c59d7e0c089c0", toHex(digest));
  }

  @Test
  void analyzeUpdate_whenSingleChunk_returnsMd4OfAbc() {
    byte[] data = "abc".getBytes(StandardCharsets.US_ASCII);

    handler.analyzeUpdate(data, data.length);
    byte[] digest = handler.analyzeFinal();

    assertEquals("a448017aaf21d8525fc10ae87aa6729d", toHex(digest));
  }

  @Test
  void analyzeUpdate_whenMultipleChunks_returnsMd4OfMessageDigest() {
    handler.analyzeUpdate("message ".getBytes(StandardCharsets.US_ASCII), 8);
    handler.analyzeUpdate("digest".getBytes(StandardCharsets.US_ASCII), 6);

    byte[] digest = handler.analyzeFinal();

    assertEquals("d9130a8164549fe818874806e1c7014b", toHex(digest));
  }

  @Test
  void analyzeUpdate_withOffsetUsesSpecifiedRange() {
    byte[] data = "xxabczz".getBytes(StandardCharsets.US_ASCII);

    handler.analyzeUpdate(data, 2, 3);
    byte[] digest = handler.analyzeFinal();

    assertEquals("a448017aaf21d8525fc10ae87aa6729d", toHex(digest));
  }

  @Test
  void analyzeUpdate_whenLengthExceedsSingleBlock_processesAllBlocks() {
    String message =
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    byte[] data = message.getBytes(StandardCharsets.US_ASCII);

    handler.analyzeUpdate(data, data.length);
    byte[] digest = handler.analyzeFinal();

    assertEquals("e33b4ddc9c38f2199c3e7b164fcc0536", toHex(digest));
  }

  @Test
  void analyzeFinal_whenInputRequiresExtendedPadding_usesCorrectDigest() {
    String message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    byte[] data = message.getBytes(StandardCharsets.US_ASCII);

    handler.analyzeUpdate(data, data.length);
    byte[] digest = handler.analyzeFinal();

    assertEquals("043f8582f241db351ce627e153e7f0e4", toHex(digest));
  }

  private static String toHex(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) {
      builder.append(String.format("%02x", value));
    }
    return builder.toString();
  }
}
