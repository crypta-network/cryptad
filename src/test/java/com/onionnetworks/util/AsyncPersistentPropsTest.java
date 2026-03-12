package com.onionnetworks.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AsyncPersistentPropsTest {

  @TempDir Path tempDir;

  private AsyncPersistentProps props;

  @AfterEach
  void tearDown() {
    if (props != null) {
      try {
        props.close();
      } catch (IOException _) {
        // Ignore to allow cleanup when the writer thread already failed.
      }
    }
  }

  @Test
  void setProperty_whenCalled_flushWritesToDisk() throws Exception {
    File file = tempDir.resolve("props.properties").toFile();
    props = new AsyncPersistentProps(file);

    props.setProperty("foo", "bar");
    props.flush();

    Properties loaded = load(file);
    assertEquals("bar", loaded.getProperty("foo"));
  }

  @Test
  void remove_whenKeyPresent_persistsRemoval() throws Exception {
    File file = tempDir.resolve("props.properties").toFile();
    props = new AsyncPersistentProps(file);
    props.setProperty("foo", "bar");
    props.setProperty("keep", "value");
    props.flush();

    Object removed = props.remove("foo");
    props.flush();

    Properties loaded = load(file);
    assertEquals("bar", removed);
    assertFalse(loaded.containsKey("foo"));
    assertEquals("value", loaded.getProperty("keep"));
  }

  @Test
  void clear_whenCalled_persistsEmptyState() throws Exception {
    File file = tempDir.resolve("props.properties").toFile();
    props = new AsyncPersistentProps(file);
    props.setProperty("foo", "bar");
    props.setProperty("baz", "qux");
    props.flush();

    props.clear();
    props.flush();

    Properties loaded = load(file);
    assertTrue(loaded.isEmpty());
  }

  @Test
  void close_whenClosed_preventsFurtherMutation() throws Exception {
    File file = tempDir.resolve("props.properties").toFile();
    props = new AsyncPersistentProps(file);
    props.setProperty("foo", "bar");
    props.flush();

    props.close();

    IllegalStateException ex =
        assertThrows(IllegalStateException.class, () -> props.setProperty("another", "value"));
    assertTrue(ex.getMessage().contains("closed"));
  }

  @Test
  void flush_whenWriteFails_throwsAndBlocksFurtherOps() throws Exception {
    File file = tempDir.resolve("props.properties").toFile();
    props = new AsyncPersistentProps(file);

    // Convert the target path into a non-empty directory to force deletion and write failure.
    Files.createDirectory(file.toPath());
    Files.createFile(file.toPath().resolve("blocker.txt"));

    props.setProperty("foo", "bar");
    assertThrows(IOException.class, props::flush);

    // After failure, further mutations must be rejected.
    assertThrows(IllegalStateException.class, () -> props.setProperty("afterFail", "x"));
  }

  private Properties load(File file) throws IOException {
    Properties loaded = new Properties();
    try (FileInputStream fis = new FileInputStream(file)) {
      loaded.load(fis);
    }
    return loaded;
  }
}
