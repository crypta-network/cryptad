package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("java:S100")
class LazyRenameRAFTest {

  @TempDir Path tempDir;

  @Test
  void constructor_whenModeReadOnly_throwsIllegalStateException() throws IOException {
    Path file = Files.createTempFile(tempDir, "lazy-raf-", ".dat");
    Files.write(file, new byte[] {1, 2, 3});

    try (RAF readOnly = new RAF(file.toFile(), "r")) {
      assertThrows(IllegalStateException.class, () -> new LazyRenameRAF(readOnly));
    }
  }

  @Test
  void renameTo_whenReadWriteMode_usesTempFileAndKeepsDestPending() throws IOException {
    Path source = Files.createTempFile(tempDir, "lazy-raf-", ".dat");
    byte[] data = new byte[] {10, 20, 30, 40};
    RAF raf = new RAF(source.toFile(), "rw");

    try (LazyRenameRAF lazy = new LazyRenameRAF(raf)) {
      lazy.seekAndWrite(0, data, 0, data.length);
      Path destination = tempDir.resolve("final-destination.dat");

      lazy.renameTo(destination.toFile());

      File tempLocation = lazy.getFile();
      assertFalse(
          Files.exists(destination),
          "Final destination should not exist until setReadOnly is called");
      assertEquals(destination.getParent(), tempLocation.getParentFile().toPath());
      assertTrue(Files.exists(tempLocation.toPath()), "Intermediate temp file must exist");
      assertArrayEquals(data, Files.readAllBytes(tempLocation.toPath()));
    }
  }

  @Test
  void setReadOnly_afterRename_movesTempToDestination() throws IOException {
    Path source = Files.createTempFile(tempDir, "lazy-raf-", ".dat");
    byte[] data = new byte[] {5, 6, 7};
    RAF raf = new RAF(source.toFile(), "rw");

    try (LazyRenameRAF lazy = new LazyRenameRAF(raf)) {
      lazy.seekAndWrite(0, data, 0, data.length);
      Path destination = tempDir.resolve("final-readonly.dat");
      lazy.renameTo(destination.toFile());

      File tempLocation = lazy.getFile();
      lazy.setReadOnly();

      assertTrue(
          Files.exists(destination), "Destination should exist after setReadOnly promotes it");
      assertFalse(
          Files.exists(tempLocation.toPath()),
          "Temporary staging file should be moved to destination");
      assertArrayEquals(data, Files.readAllBytes(destination));
      assertEquals(
          destination.toFile().getCanonicalFile(),
          lazy.getFile().getCanonicalFile(),
          "RAF should now point to destination");
    }
  }

  @Test
  void renameTo_afterSetReadOnly_movesDirectlyToDestination() throws IOException {
    Path source = Files.createTempFile(tempDir, "lazy-raf-", ".dat");
    byte[] data = new byte[] {42, 43, 44, 45};
    RAF raf = new RAF(source.toFile(), "rw");

    try (LazyRenameRAF lazy = new LazyRenameRAF(raf)) {
      lazy.seekAndWrite(0, data, 0, data.length);
      lazy.setReadOnly();

      Path destination = tempDir.resolve("direct-move.dat");
      lazy.renameTo(destination.toFile());

      assertTrue(
          Files.exists(destination),
          "Destination should be created immediately when already read-only");
      assertFalse(Files.exists(source), "Original file should no longer exist after direct rename");
      assertArrayEquals(data, Files.readAllBytes(destination));
      assertEquals(
          destination.toFile().getCanonicalFile(),
          lazy.getFile().getCanonicalFile(),
          "RAF should track the final destination");
    }
  }
}
