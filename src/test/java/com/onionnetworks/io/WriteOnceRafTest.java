package com.onionnetworks.io;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class WriteOnceRafTest {

  @TempDir Path tempDir;

  @Test
  void seekAndWrite_whenFirstWrite_writesAllBytesOnce() throws Exception {
    Path file = tempDir.resolve("first-write.dat");
    byte[] data = "hello".getBytes(StandardCharsets.US_ASCII);

    try (WriteOnceRaf raf = new WriteOnceRaf(new RAF(file.toFile(), "rw"))) {
      raf.seekAndWrite(0, data, 0, data.length);

      byte[] buffer = new byte[data.length];
      int read = raf.seekAndRead(0, buffer, 0, buffer.length);
      assertEquals(data.length, read);
      assertArrayEquals(data, buffer);
    }

    assertArrayEquals(data, Files.readAllBytes(file));
  }

  @Test
  void seekAndWrite_whenOverlappingWrite_skipsPreviouslyWrittenBytes() throws Exception {
    Path file = tempDir.resolve("overlap-write.dat");
    byte[] initial = "abcd".getBytes(StandardCharsets.US_ASCII);
    byte[] overlapping = "wxyz".getBytes(StandardCharsets.US_ASCII);

    try (WriteOnceRaf raf = new WriteOnceRaf(new RAF(file.toFile(), "rw"))) {
      raf.seekAndWrite(0, initial, 0, initial.length);
      raf.seekAndWrite(2, overlapping, 0, overlapping.length);
    }

    assertEquals(6, Files.size(file));
    assertArrayEquals("abcdyz".getBytes(StandardCharsets.US_ASCII), Files.readAllBytes(file));
  }

  @Test
  void seekAndWrite_whenEntireRangeAlreadyWritten_keepsOriginalData() throws Exception {
    Path file = tempDir.resolve("duplicate-write.dat");
    byte[] initial = "foo".getBytes(StandardCharsets.US_ASCII);
    byte[] duplicate = "bar".getBytes(StandardCharsets.US_ASCII);

    try (WriteOnceRaf raf = new WriteOnceRaf(new RAF(file.toFile(), "rw"))) {
      raf.seekAndWrite(0, initial, 0, initial.length);
      raf.seekAndWrite(0, duplicate, 0, duplicate.length);
    }

    assertEquals(initial.length, Files.size(file));
    assertArrayEquals(initial, Files.readAllBytes(file));
  }

  @Test
  void seekAndWrite_whenBridgingGap_writesOnlyUnwrittenMiddleSection() throws Exception {
    Path file = tempDir.resolve("gap-bridge.dat");
    byte[] prefix = "AB".getBytes(StandardCharsets.US_ASCII);
    byte[] suffix = "CD".getBytes(StandardCharsets.US_ASCII);
    byte[] bridge = "XYZ".getBytes(StandardCharsets.US_ASCII);

    try (WriteOnceRaf raf = new WriteOnceRaf(new RAF(file.toFile(), "rw"))) {
      raf.seekAndWrite(0, prefix, 0, prefix.length); // positions 0-1
      raf.seekAndWrite(3, suffix, 0, suffix.length); // positions 3-4, leaves a hole at 2
      raf.seekAndWrite(1, bridge, 0, bridge.length); // only unwritten index 2 should be filled
    }

    assertEquals(5, Files.size(file));
    assertArrayEquals("ABYCD".getBytes(StandardCharsets.US_ASCII), Files.readAllBytes(file));
  }

  @Test
  void seekAndWrite_whenLengthIsZero_leavesFileUnchanged() throws Exception {
    Path file = tempDir.resolve("zero-length.dat");
    byte[] data = "ignored".getBytes(StandardCharsets.US_ASCII);

    try (WriteOnceRaf raf = new WriteOnceRaf(new RAF(file.toFile(), "rw"))) {
      raf.seekAndWrite(0, data, 0, 0);
    }

    assertEquals(0, Files.size(file));
    assertArrayEquals(new byte[0], Files.readAllBytes(file));
  }
}
