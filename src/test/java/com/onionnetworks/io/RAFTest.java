package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("java:S100")
class RAFTest {

  @TempDir Path tempDir;

  @Test
  void seekAndWriteAndRead_whenPositionsUsed_expectCorrectData() throws Exception {
    File file = tempDir.resolve("data.bin").toFile();
    byte[] toWrite = new byte[] {1, 2, 3, 4, 5};

    try (RAF raf = new RAF(file, "rw")) {
      raf.seekAndWrite(0, toWrite, 0, toWrite.length);

      byte[] buffer = new byte[5];
      int read = raf.seekAndRead(1, buffer, 0, 3);

      assertEquals(3, read);
      assertArrayEquals(new byte[] {2, 3, 4, 0, 0}, buffer);
    }
  }

  @Test
  void seekAndReadFully_whenInsufficientData_throwsEOFException() throws Exception {
    File file = tempDir.resolve("small.bin").toFile();
    Files.write(file.toPath(), new byte[] {9, 8});

    try (RAF raf = new RAF(file, "r")) {
      assertThrows(EOFException.class, () -> raf.seekAndReadFully(0, new byte[4], 0, 4));
    }
  }

  @Test
  void renameTo_whenClosed_throwsIOException() throws Exception {
    File file = tempDir.resolve("closed.bin").toFile();
    Files.write(file.toPath(), new byte[] {1});
    RAF raf = new RAF(file, "rw");
    raf.close();

    File dest = tempDir.resolve("closed-dest.bin").toFile();

    assertThrows(IOException.class, () -> raf.renameTo(dest));
  }

  @Test
  void renameTo_whenDestExists_replacesFileAndReopens() throws Exception {
    File source = tempDir.resolve("source.bin").toFile();
    File dest = tempDir.resolve("dest.bin").toFile();
    Files.write(source.toPath(), "source-data".getBytes());
    Files.write(dest.toPath(), "old".getBytes());

    try (RAF raf = new RAF(source, "rw")) {
      raf.renameTo(dest);

      assertFalse(source.exists());
      assertEquals(dest.getAbsoluteFile(), raf.getFile().getAbsoluteFile());
      assertEquals("source-data".length(), raf.length());
      assertEquals("source-data", Files.readString(dest.toPath()));
    }
  }

  @Test
  void renameTo_whenRenameFails_fallsBackToCopyAndDeletesSource() throws Exception {
    Path sourcePath = tempDir.resolve("nonrename.bin");
    Path destPath = tempDir.resolve("copy-dest.bin");
    Files.write(sourcePath, "copy-me".getBytes());

    File failingFile = new NonRenamingFile(sourcePath);
    try (RAF raf = new RAF(failingFile, "rw")) {
      raf.renameTo(destPath.toFile());

      assertFalse(sourcePath.toFile().exists());
      assertEquals(destPath.toFile().getAbsoluteFile(), raf.getFile().getAbsoluteFile());
      assertEquals("copy-me", Files.readString(destPath));
      assertEquals("copy-me".length(), raf.length());
    }
  }

  @Test
  void setReadOnly_whenClosed_throwsIOException() throws Exception {
    File file = tempDir.resolve("readonly-closed.bin").toFile();
    RAF raf = new RAF(file, "rw");
    raf.close();

    assertThrows(IOException.class, raf::setReadOnly);
  }

  @Test
  void setReadOnly_whenCalled_switchesModeAndPreventsWrite() throws Exception {
    File file = tempDir.resolve("readonly.bin").toFile();
    Files.write(file.toPath(), new byte[] {7, 7, 7});

    try (RAF raf = new RAF(file, "rw")) {
      raf.setReadOnly();

      assertEquals("r", raf.getMode());
      assertThrows(IOException.class, () -> raf.seekAndWrite(0, new byte[] {1}, 0, 1));
      byte[] buf = new byte[3];
      int read = raf.seekAndRead(0, buf, 0, buf.length);
      assertEquals(3, read);
      assertArrayEquals(new byte[] {7, 7, 7}, buf);
    }
  }

  @Test
  void deleteOnClose_whenSet_deletesFile() throws Exception {
    File file = tempDir.resolve("delete-on-close.bin").toFile();

    try (RAF raf = new RAF(file, "rw")) {
      raf.deleteOnClose();
    }

    assertFalse(file.exists());
  }

  @Test
  void deleteOnClose_whenAlreadyClosed_throwsIllegalStateException() throws Exception {
    File file = tempDir.resolve("delete-on-close-closed.bin").toFile();
    RAF raf = new RAF(file, "rw");
    raf.close();

    assertThrows(IllegalStateException.class, raf::deleteOnClose);
  }

  @Test
  void close_whenDeleteFails_throwsIOException() throws Exception {
    Path path = tempDir.resolve("cannot-delete.bin");
    Files.write(path, new byte[] {1, 2, 3});
    File nonDeletingFile = new NonDeletingFile(path);

    RAF raf = new RAF(nonDeletingFile, "rw");
    raf.deleteOnClose();

    IOException thrown = assertThrows(IOException.class, raf::close);
    assertEquals("Unable to delete file on close", thrown.getMessage());
    assertTrue(path.toFile().exists());
    assertTrue(raf.isClosed());

    assertTrue(path.toFile().delete());
  }

  @Test
  void setLength_whenInvoked_updatesFileSize() throws Exception {
    File file = tempDir.resolve("length.bin").toFile();

    try (RAF raf = new RAF(file, "rw")) {
      raf.setLength(10);
      assertEquals(10, raf.length());

      raf.setLength(2);
      assertEquals(2, raf.length());
    }
  }

  private static final class NonRenamingFile extends File {
    private NonRenamingFile(Path path) {
      super(path.toString());
    }

    @Override
    public boolean renameTo(File dest) {
      return false;
    }
  }

  private static final class NonDeletingFile extends File {
    private NonDeletingFile(Path path) {
      super(path.toString());
    }

    @Override
    public boolean delete() {
      return false;
    }
  }
}
