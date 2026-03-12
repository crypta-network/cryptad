package network.crypta.node;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PersisterTest {

  @Mock private Persistable persistable;
  @Mock private Ticker ticker;

  @TempDir File tempDir;

  private File tempFile;
  private File targetFile;

  @BeforeEach
  void setup() {
    tempFile = new File(tempDir, "throttle.tmp");
    targetFile = new File(tempDir, "throttle.dat");
  }

  @Test
  void run_whenPersistSucceeds_writesTargetAndQueuesNext() throws Exception {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("alpha", "42");
    sfs.putSingle("nested.value", "ok");
    when(persistable.persistThrottlesToFieldSet()).thenReturn(sfs);

    // No-op scheduler
    doAnswer(inv -> null)
        .when(ticker)
        .queueTimedJob(org.mockito.Mockito.any(Runnable.class), org.mockito.Mockito.anyLong());

    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    persister.run();

    // Assert: file was written via temp then moved to target and contains our data
    assertTrue(targetFile.isFile(), "persist target should exist");
    SimpleFieldSet readBack = SimpleFieldSet.readFrom(targetFile, false, true);
    assertEquals("42", readBack.get("alpha"));
    assertEquals("ok", readBack.get("nested.value"));

    // Assert: ticker received a rescheduling for the same persister with the configured period
    ArgumentCaptor<Runnable> rCap = ArgumentCaptor.forClass(Runnable.class);
    ArgumentCaptor<Long> lCap = ArgumentCaptor.forClass(Long.class);
    verify(ticker, times(1)).queueTimedJob(rCap.capture(), lCap.capture());
    assertEquals(Persister.PERIOD, lCap.getValue().longValue());
    assertEquals(persister, rCap.getValue());
  }

  @Test
  void run_whenParentDirectoryMissing_createsDirAndPersists() throws Exception {
    // Arrange: point persister to a nested directory that doesn't exist yet
    File missingDir = new File(tempDir, "nested/missing");
    File tmp = new File(missingDir, "throttle.tmp");
    File tgt = new File(missingDir, "throttle.dat");

    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("k", "v");
    when(persistable.persistThrottlesToFieldSet()).thenReturn(sfs);

    doAnswer(inv -> null)
        .when(ticker)
        .queueTimedJob(org.mockito.Mockito.any(Runnable.class), org.mockito.Mockito.anyLong());

    Persister persister = new Persister(persistable, tmp, tgt, ticker);

    // Act
    persister.run();

    // Assert: parent directory created, target written with expected content
    assertTrue(tgt.isFile(), "persist target should exist after creating missing parent dirs");
    SimpleFieldSet readBack = SimpleFieldSet.readFrom(tgt, false, true);
    assertEquals("v", readBack.get("k"));
  }

  @Test
  void run_whenTempIsDirectory_logsAndSkipsWriteAndQueuesNext() {
    // Arrange: make temp path a directory so FileOutputStream throws FileNotFoundException
    // ("Is a directory")
    assertTrue(tempFile.mkdir(), "should create temp dir");
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("x", "y");
    when(persistable.persistThrottlesToFieldSet()).thenReturn(sfs);

    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    persister.run();

    // Assert: no valid file created at target (a directory rename might occur on some platforms)
    assertFalse(
        targetFile.isFile(), "target should not be a regular file when temp is a directory");
    verify(ticker, times(1)).queueTimedJob(persister, Persister.PERIOD);
  }

  @Test
  void run_whenWriteThrows_deletesTempAndDoesNotMove() throws Exception {
    // Arrange: return a SimpleFieldSet that throws during write
    SimpleFieldSet throwing = mock(SimpleFieldSet.class);
    doThrow(new IOException("boom")).when(throwing).writeToBigBuffer(org.mockito.Mockito.any());
    when(persistable.persistThrottlesToFieldSet()).thenReturn(throwing);

    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    persister.run();

    // Assert: temp deleted in the IOException path, target not created
    assertFalse(tempFile.exists(), "temp should be deleted after write failure");
    assertFalse(targetFile.exists(), "target should not be created when write fails");
    verify(ticker, times(1)).queueTimedJob(persister, Persister.PERIOD);
  }

  @Test
  void read_whenTargetExists_returnsParsedFieldSet() throws Exception {
    // Arrange: write valid SFS to target directly
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("a", "b");
    try (FileOutputStream fos = new FileOutputStream(targetFile)) {
      sfs.writeToBigBuffer(fos);
    }
    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    SimpleFieldSet read = persister.read();

    // Assert
    assertNotNull(read);
    assertEquals("b", read.get("a"));
  }

  @Test
  void read_whenTargetUnreadableTempValid_returnsFromTemp() throws Exception {
    // Arrange: create an empty target file so parsing throws EOFException and triggers fallback
    assertTrue(targetFile.createNewFile(), "should create empty target file");
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("k", "v");
    try (FileOutputStream fos = new FileOutputStream(tempFile)) {
      sfs.writeToBigBuffer(fos);
    }
    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    SimpleFieldSet read = persister.read();

    // Assert: fallback to temp
    assertNotNull(read);
    assertEquals("v", read.get("k"));
  }

  @Test
  void read_whenBothMissing_returnsNull() {
    // Arrange
    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    SimpleFieldSet read = persister.read();

    // Assert
    assertNull(read);
  }

  @Test
  void read_whenBothUnreadable_returnsNull() throws Exception {
    // Arrange: create empty files so both reads throw EOFException and return null
    assertTrue(targetFile.createNewFile(), "should create empty target file");
    assertTrue(tempFile.createNewFile(), "should create empty temp file");
    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    SimpleFieldSet read = persister.read();

    // Assert
    assertNull(read);
  }

  @Test
  void run_whenFatalThrowableThrown_catchesAndQueuesNext() {
    // Arrange: simulate a fatal Error thrown during persistence
    doThrow(new LinkageError("simulated fatal error"))
        .when(persistable)
        .persistThrottlesToFieldSet();

    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act: should not propagate the Error; still schedules next run
    persister.run();

    // Assert: rescheduled even after fatal throwable
    verify(ticker, times(1)).queueTimedJob(persister, Persister.PERIOD);
    // And no target file created since write never happened
    assertFalse(targetFile.exists());
  }

  @Test
  void start_whenCalledTwice_onlySchedulesOnce() throws Exception {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("z", "1");
    when(persistable.persistThrottlesToFieldSet()).thenReturn(sfs);
    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act: first start performs persist and schedules; second start is a no-op
    persister.start();
    persister.start();

    // Assert: one schedule only; file exists with expected data
    verify(ticker, times(1)).queueTimedJob(persister, Persister.PERIOD);
    assertTrue(targetFile.exists(), "persist should have executed once");
    SimpleFieldSet readBack = SimpleFieldSet.readFrom(targetFile, false, true);
    assertEquals("1", readBack.get("z"));
  }
}
