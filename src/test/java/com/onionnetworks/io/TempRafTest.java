package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("java:S100")
class TempRafTest {

  @TempDir Path tempDir;

  @Test
  void close_whenKeepPolicyNever_deletesFile() throws IOException {
    Path file = Files.createTempFile(tempDir, "tempraf-", ".dat");

    try (TempRaf tempRaf = new TempRaf(new RAF(file.toFile(), "rw"), TempRaf.NEVER)) {
      tempRaf.seekAndWrite(0, new byte[] {1, 2, 3}, 0, 3);
    }

    assertFalse(Files.exists(file), "Temporary file should be removed when keepPolicy=NEVER");
  }

  @Test
  void close_whenKeepPolicyAlways_keepsFile() throws IOException {
    Path file = Files.createTempFile(tempDir, "tempraf-", ".dat");

    try (TempRaf tempRaf = new TempRaf(new RAF(file.toFile(), "rw"), TempRaf.ALWAYS)) {
      tempRaf.seekAndWrite(0, new byte[] {4, 5, 6, 7}, 0, 4);
    }

    assertTrue(Files.exists(file), "File should persist when keepPolicy=ALWAYS");
    assertTrue(Files.size(file) > 0, "File contents should remain intact after close");
  }

  @Test
  void close_whenKeepPolicyRenamedWithoutRename_deletesFile() throws IOException {
    Path file = Files.createTempFile(tempDir, "tempraf-", ".dat");

    try (TempRaf tempRaf = new TempRaf(new RAF(file.toFile(), "rw"), TempRaf.RENAMED)) {
      tempRaf.seekAndWrite(0, new byte[] {8}, 0, 1);
    }

    assertFalse(
        Files.exists(file), "File should be deleted when keepPolicy=RENAMED and no rename occurs");
  }

  @Test
  void close_whenKeepPolicyRenamedWithRename_keepsRenamedFile() throws IOException {
    Path original = Files.createTempFile(tempDir, "tempraf-", ".dat");
    Path renamed = tempDir.resolve("renamed-file.dat");

    try (TempRaf tempRaf = new TempRaf(new RAF(original.toFile(), "rw"), TempRaf.RENAMED)) {
      tempRaf.seekAndWrite(0, new byte[] {9, 10}, 0, 2);
      tempRaf.renameTo(renamed.toFile());
    }

    assertFalse(Files.exists(original), "Original file should be moved during rename");
    assertTrue(Files.exists(renamed), "Renamed file should persist with keepPolicy=RENAMED");
  }

  @Test
  void close_whenKeepPolicyRenamedAndDoneWritingWithoutReadOnly_deletesFile() throws IOException {
    Path original = Files.createTempFile(tempDir, "tempraf-", ".dat");
    Path renamed = tempDir.resolve("renamed-during-write.dat");

    try (TempRaf tempRaf =
        new TempRaf(new RAF(original.toFile(), "rw"), TempRaf.RENAMED_AND_DONE_WRITING)) {
      tempRaf.seekAndWrite(0, new byte[] {11}, 0, 1);
      tempRaf.renameTo(renamed.toFile());
    }

    assertFalse(Files.exists(original), "Original file should be removed after rename");
    assertFalse(
        Files.exists(renamed),
        "Renamed file should be deleted when not switched to read-only after rename");
  }

  @Test
  void close_whenKeepPolicyRenamedAndDoneWritingWithReadOnly_keepsRenamedFile() throws IOException {
    Path original = Files.createTempFile(tempDir, "tempraf-", ".dat");
    Path renamed = tempDir.resolve("renamed-final.dat");

    try (TempRaf tempRaf =
        new TempRaf(new RAF(original.toFile(), "rw"), TempRaf.RENAMED_AND_DONE_WRITING)) {
      tempRaf.seekAndWrite(0, new byte[] {12, 13}, 0, 2);
      tempRaf.renameTo(renamed.toFile());
      tempRaf.setReadOnly();
    }

    assertFalse(Files.exists(original), "Original file should not remain after rename");
    assertTrue(
        Files.exists(renamed),
        "Renamed file should persist when set to read-only after rename with"
            + " keepPolicy=RENAMED_AND_DONE_WRITING");
  }
}
