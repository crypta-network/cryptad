package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("java:S100")
class ExceptionRAFTest {

  @Test
  void getMode_whenConstructed_returnsProvidedMode() throws IOException {
    IOException ioException = new IOException("boom");
    try (ExceptionRAF raf = new ExceptionRAF(ioException, "rw")) {
      assertEquals("rw", raf.getMode());
    }
  }

  @Test
  void seekAndWrite_whenInvoked_throwsProvidedException() throws IOException {
    IOException ioException = new IOException("write-error");
    byte[] data = new byte[] {1, 2, 3};

    try (ExceptionRAF raf = new ExceptionRAF(ioException, "rw")) {
      IOException thrown =
          assertThrows(IOException.class, () -> raf.seekAndWrite(0, data, 0, data.length));

      assertSame(ioException, thrown);
    }
  }

  @Test
  void seekAndReadFully_whenInvoked_throwsProvidedException() throws IOException {
    IOException ioException = new IOException("read-error");
    byte[] buffer = new byte[4];

    try (ExceptionRAF raf = new ExceptionRAF(ioException, "rw")) {
      IOException thrown =
          assertThrows(IOException.class, () -> raf.seekAndReadFully(0, buffer, 0, buffer.length));

      assertSame(ioException, thrown);
    }
  }

  @Test
  void renameTo_whenInvoked_throwsProvidedException(@TempDir Path tempDir) throws IOException {
    IOException ioException = new IOException("rename-error");
    File destination = tempDir.resolve("dest.dat").toFile();

    try (ExceptionRAF raf = new ExceptionRAF(ioException, "rw")) {
      IOException thrown = assertThrows(IOException.class, () -> raf.renameTo(destination));

      assertSame(ioException, thrown);
    }
  }

  @Test
  void setReadOnly_whenInvoked_throwsProvidedException() throws IOException {
    IOException ioException = new IOException("readonly-error");

    try (ExceptionRAF raf = new ExceptionRAF(ioException, "rw")) {
      IOException thrown = assertThrows(IOException.class, raf::setReadOnly);

      assertSame(ioException, thrown);
    }
  }

  @Test
  void setLength_whenInvoked_throwsProvidedException() throws IOException {
    IOException ioException = new IOException("length-error");

    try (ExceptionRAF raf = new ExceptionRAF(ioException, "rw")) {
      IOException thrown = assertThrows(IOException.class, () -> raf.setLength(10L));

      assertSame(ioException, thrown);
    }
  }

  @Test
  void close_whenInvoked_doesNotThrowAndLeavesClosedFlagFalse() throws IOException {
    try (ExceptionRAF raf = new ExceptionRAF(new IOException("close-error"), "rw")) {
      assertDoesNotThrow(raf::close);
      assertFalse(raf.isClosed());
    }
  }
}
