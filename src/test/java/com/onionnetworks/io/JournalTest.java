package com.onionnetworks.io;

import com.onionnetworks.util.Range;
import com.onionnetworks.util.RangeSet;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("java:S100")
class JournalTest {

  @TempDir Path tempDir;

  @Test
  void constructor_withValidExistingProperties_loadsRangesAndTargetFile() throws Exception {
    File journalFile = tempDir.resolve("journal.properties").toFile();
    File target = tempDir.resolve("target.data").toFile();

    Properties props = new Properties();
    props.setProperty(Journal.BYTES_PROP, "1-3,5-6");
    props.setProperty(Journal.FILE_PROP, target.getAbsolutePath());
    storeProperties(journalFile, props);

    Journal journal = new Journal(journalFile);
    try {
      assertEquals(target.getAbsolutePath(), journal.getTargetFile().getAbsolutePath());
      assertEquals(RangeSet.parse("1-3,5-6"), journal.getByteRanges());
    } finally {
      journal.close();
    }
  }

  @Test
  void constructor_withoutBytesProperty_initializesEmptyRangeSet() throws Exception {
    File journalFile = tempDir.resolve("empty.properties").toFile();
    storeProperties(journalFile, new Properties());

    Journal journal = new Journal(journalFile);
    try {
      assertTrue(journal.getByteRanges().isEmpty());
      assertNull(journal.getTargetFile());
    } finally {
      journal.close();
    }
  }

  @Test
  void constructor_withCorruptBytesProperty_throwsIOException() throws Exception {
    File journalFile = tempDir.resolve("corrupt.properties").toFile();
    Properties props = new Properties();
    props.setProperty(Journal.BYTES_PROP, "not-a-range");
    storeProperties(journalFile, props);

    IOException exception = assertThrows(IOException.class, () -> new Journal(journalFile));
    assertEquals("Corrupt journal.", exception.getMessage());
  }

  @Test
  void addByteRange_whenAdded_persistsUpdatedRanges() throws Exception {
    File journalFile = tempDir.resolve("addRange.properties").toFile();
    Journal journal = new Journal(journalFile);
    try {
      journal.addByteRange(new Range(1, 3));
      journal.flush();

      Properties persisted = loadProperties(journalFile);
      assertEquals("1-3", persisted.getProperty(Journal.BYTES_PROP));
      assertEquals(RangeSet.parse("1-3"), journal.getByteRanges());
    } finally {
      journal.close();
    }
  }

  @Test
  void addByteRange_whenAdjacentRangeAdded_mergesAndPersists() throws Exception {
    File journalFile = tempDir.resolve("merge.properties").toFile();
    Properties props = new Properties();
    props.setProperty(Journal.BYTES_PROP, "1-3");
    storeProperties(journalFile, props);

    Journal journal = new Journal(journalFile);
    try {
      journal.addByteRange(new Range(4));
      journal.flush();

      Properties persisted = loadProperties(journalFile);
      assertEquals("1-4", persisted.getProperty(Journal.BYTES_PROP));
      assertEquals(RangeSet.parse("1-4"), journal.getByteRanges());
    } finally {
      journal.close();
    }
  }

  @Test
  void setTargetFile_whenCalled_updatesPropertyAndGetter() throws Exception {
    File journalFile = tempDir.resolve("targetFile.properties").toFile();
    Journal journal = new Journal(journalFile);
    File target = tempDir.resolve("data.bin").toFile();
    try {
      journal.setTargetFile(target);
      journal.flush();

      Properties persisted = loadProperties(journalFile);
      assertEquals(target.getAbsolutePath(), persisted.getProperty(Journal.FILE_PROP));
      assertEquals(target.getAbsolutePath(), journal.getTargetFile().getAbsolutePath());
    } finally {
      journal.close();
    }
  }

  private void storeProperties(File file, Properties properties) throws IOException {
    try (FileOutputStream out = new FileOutputStream(file)) {
      properties.store(out, null);
    }
  }

  private Properties loadProperties(File file) throws IOException {
    Properties properties = new Properties();
    try (FileInputStream in = new FileInputStream(file)) {
      properties.load(in);
    }
    return properties;
  }
}
