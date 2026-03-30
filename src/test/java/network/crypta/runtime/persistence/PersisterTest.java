package network.crypta.runtime.persistence;

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

    doAnswer(inv -> null)
        .when(ticker)
        .queueTimedJob(org.mockito.Mockito.any(Runnable.class), org.mockito.Mockito.anyLong());

    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    persister.run();

    // Assert
    assertTrue(targetFile.isFile(), "persist target should exist");
    SimpleFieldSet readBack = SimpleFieldSet.readFrom(targetFile, false, true);
    assertEquals("42", readBack.get("alpha"));
    assertEquals("ok", readBack.get("nested.value"));

    ArgumentCaptor<Runnable> rCap = ArgumentCaptor.forClass(Runnable.class);
    ArgumentCaptor<Long> lCap = ArgumentCaptor.forClass(Long.class);
    verify(ticker, times(1)).queueTimedJob(rCap.capture(), lCap.capture());
    assertEquals(Persister.PERIOD, lCap.getValue().longValue());
    assertEquals(persister, rCap.getValue());
  }

  @Test
  void run_whenParentDirectoryMissing_createsDirAndPersists() throws Exception {
    // Arrange
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

    // Assert
    assertTrue(tgt.isFile(), "persist target should exist after creating missing parent dirs");
    SimpleFieldSet readBack = SimpleFieldSet.readFrom(tgt, false, true);
    assertEquals("v", readBack.get("k"));
  }

  @Test
  void run_whenTempIsDirectory_logsAndSkipsWriteAndQueuesNext() {
    // Arrange
    assertTrue(tempFile.mkdir(), "should create temp dir");
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("x", "y");
    when(persistable.persistThrottlesToFieldSet()).thenReturn(sfs);

    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    persister.run();

    // Assert
    assertFalse(
        targetFile.isFile(), "target should not be a regular file when temp is a directory");
    verify(ticker, times(1)).queueTimedJob(persister, Persister.PERIOD);
  }

  @Test
  void run_whenWriteThrows_deletesTempAndDoesNotMove() throws Exception {
    // Arrange
    SimpleFieldSet throwing = mock(SimpleFieldSet.class);
    doThrow(new IOException("boom")).when(throwing).writeToBigBuffer(org.mockito.Mockito.any());
    when(persistable.persistThrottlesToFieldSet()).thenReturn(throwing);

    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    persister.run();

    // Assert
    assertFalse(tempFile.exists(), "temp should be deleted after write failure");
    assertFalse(targetFile.exists(), "target should not be created when write fails");
    verify(ticker, times(1)).queueTimedJob(persister, Persister.PERIOD);
  }

  @Test
  void read_whenTargetExists_returnsParsedFieldSet() throws Exception {
    // Arrange
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
    // Arrange
    assertTrue(targetFile.createNewFile(), "should create empty target file");
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("k", "v");
    try (FileOutputStream fos = new FileOutputStream(tempFile)) {
      sfs.writeToBigBuffer(fos);
    }
    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    SimpleFieldSet read = persister.read();

    // Assert
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
    // Arrange
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
    // Arrange
    doThrow(new LinkageError("simulated fatal error"))
        .when(persistable)
        .persistThrottlesToFieldSet();

    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    persister.run();

    // Assert
    verify(ticker, times(1)).queueTimedJob(persister, Persister.PERIOD);
    assertFalse(targetFile.exists());
  }

  @Test
  void start_whenCalledTwice_onlySchedulesOnce() throws Exception {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(false);
    sfs.putSingle("z", "1");
    when(persistable.persistThrottlesToFieldSet()).thenReturn(sfs);
    Persister persister = new Persister(persistable, tempFile, targetFile, ticker);

    // Act
    persister.start();
    persister.start();

    // Assert
    verify(ticker, times(1)).queueTimedJob(persister, Persister.PERIOD);
    assertTrue(targetFile.exists(), "persist should have executed once");
    SimpleFieldSet readBack = SimpleFieldSet.readFrom(targetFile, false, true);
    assertEquals("1", readBack.get("z"));
  }
}
