package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.onionnetworks.util.Range;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class JournalingRAFTest {

  @TempDir Path tempDir;

  @Mock RAF delegateRaf;

  @Mock Journal journal;

  private File defaultFile;

  @BeforeEach
  void setUp() throws Exception {
    defaultFile = Files.createFile(tempDir.resolve("default.dat")).toFile();
  }

  @Test
  void constructor_whenModeReadOnly_throwsIllegalStateException() {
    when(delegateRaf.getMode()).thenReturn("r");

    IllegalStateException ex =
        assertThrows(IllegalStateException.class, () -> new JournalingRAF(delegateRaf, journal));

    assertEquals("Can't create a journal for a read-only file.", ex.getMessage());
    verify(journal, never()).setTargetFile(any());
  }

  @Test
  void constructor_whenWritable_setsInitialTargetFile() throws Exception {
    JournalingRAF raf = newJournalingRaf(defaultFile);

    verify(journal).setTargetFile(defaultFile);
    // keep the instance reachable for further operations if needed
    raf.close();
  }

  @Test
  void seekAndWrite_whenCalled_recordsRangeAndDelegates() throws Exception {
    try (JournalingRAF raf = newJournalingRaf(defaultFile)) {
      byte[] data = new byte[] {1, 2, 3, 4};

      raf.seekAndWrite(5L, data, 1, 2);

      verify(delegateRaf).seekAndWrite(5L, data, 1, 2);
      ArgumentCaptor<Range> rangeCaptor = ArgumentCaptor.forClass(Range.class);
      verify(journal).addByteRange(rangeCaptor.capture());
      assertEquals(new Range(5L, 6L), rangeCaptor.getValue());
    }
  }

  @Test
  void renameTo_whenDelegateRenames_updatesJournalTargetAndFlushes() throws Exception {
    File dest = tempDir.resolve("renamed.dat").toFile();
    File original = defaultFile;
    when(delegateRaf.getMode()).thenReturn("rw");
    when(delegateRaf.getFile()).thenReturn(original, dest);
    try (JournalingRAF raf = new JournalingRAF(delegateRaf, journal)) {
      raf.renameTo(dest);

      verify(delegateRaf).renameTo(dest);
      verify(journal).setTargetFile(dest);
      verify(journal).flush();
    }
  }

  @Test
  void setReadOnly_whenInvoked_deletesJournalAndPreventsFurtherJournalClose() throws Exception {
    File journalFile = Files.createFile(tempDir.resolve("journal.props")).toFile();
    when(journal.getFile()).thenReturn(journalFile);
    JournalingRAF raf = newJournalingRaf(defaultFile);

    raf.setReadOnly();
    raf.close();

    assertFalse(journalFile.exists());
    verify(delegateRaf).setReadOnly();
    verify(journal, times(1)).close();
  }

  @Test
  void deleteOnClose_whenInvoked_closesJournalAndDeletesFileImmediately() throws Exception {
    File journalFile = Files.createFile(tempDir.resolve("delete.props")).toFile();
    when(journal.getFile()).thenReturn(journalFile);
    try (JournalingRAF raf = newJournalingRaf(defaultFile)) {
      raf.deleteOnClose();

      assertFalse(journalFile.exists());
      verify(delegateRaf).deleteOnClose();
      verify(journal).close();
    }
  }

  @Test
  void close_whenJournalPresent_closesDelegateAndJournal() throws Exception {
    JournalingRAF raf = newJournalingRaf(defaultFile);

    raf.close();

    verify(delegateRaf).close();
    verify(journal).close();
  }

  @Test
  void seekAndWrite_afterJournalRemoved_stillDelegatesWithoutRecordingRange() throws Exception {
    File journalFile = Files.createFile(tempDir.resolve("removed.props")).toFile();
    when(journal.getFile()).thenReturn(journalFile);
    try (JournalingRAF raf = newJournalingRaf(defaultFile)) {
      raf.deleteOnClose();

      byte[] data = new byte[] {9};
      raf.seekAndWrite(0L, data, 0, 1);

      verify(delegateRaf).seekAndWrite(0L, data, 0, 1);
      verify(journal, never()).addByteRange(any());
    }
  }

  private JournalingRAF newJournalingRaf(File initialFile) {
    when(delegateRaf.getMode()).thenReturn("rw");
    when(delegateRaf.getFile()).thenReturn(initialFile);
    return new JournalingRAF(delegateRaf, journal);
  }
}
