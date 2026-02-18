package network.crypta.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming style: method_whenCondition_expectOutcome
class FreenetFilePersistentConfigTest {

  @TempDir Path tmp;

  private Path configFile;
  private Path tempFile;

  @Mock private Ticker ticker;

  @BeforeEach
  void setUp() throws IOException {
    configFile = tmp.resolve("cryptad.ini");
    tempFile = Path.of(configFile + ".tmp");
    // Ensure clean state
    Files.deleteIfExists(configFile);
    Files.deleteIfExists(tempFile);
  }

  @AfterEach
  void tearDown() throws IOException {
    Files.deleteIfExists(configFile);
    Files.deleteIfExists(tempFile);
  }

  @Test
  void store_whenNotFinishedInit_defersUntilFinishedAndNodeStarted_writesFile() throws Exception {
    FreenetFilePersistentConfig cfg =
        new FreenetFilePersistentConfig(/* set= */ null, configFile.toFile(), tempFile.toFile());

    // Act: call store() before finishedInit() → should defer
    cfg.store();

    // Assert: nothing written yet and ticker untouched
    assertFalse(Files.exists(configFile), "config file must not be created before init");
    verifyNoInteractions(ticker);

    // Finish init with a ticker; deferred store should schedule the job immediately
    cfg.finishedInit(ticker);

    // Capture the scheduled runnable and execute it after signaling that the node has started
    ArgumentCaptor<Runnable> jobCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(ticker, times(1)).queueTimedJob(jobCaptor.capture(), eq(0L));

    // Allow the background job to proceed without waiting
    cfg.setHasNodeStarted();
    jobCaptor.getValue().run();

    // Verify file was written atomically: main exists, temp was moved
    assertTrue(Files.exists(configFile), "expected persisted config file");
    assertFalse(Files.exists(tempFile), "temp file should have been moved to final path");

    List<String> lines = Files.readAllLines(configFile, StandardCharsets.UTF_8);
    // First non-empty line should be the header written by FreenetFilePersistentConfig
    assertTrue(
        lines.stream().anyMatch(l -> l.contains("Crypta shuts down")),
        "header from FreenetFilePersistentConfig should be present");
    // File should end with an End marker produced by SimpleFieldSet serialization
    assertEquals("End", lines.getLast());
  }

  @Test
  void store_whenTickerIsNull_doesNothing() throws Exception {
    FreenetFilePersistentConfig cfg =
        new FreenetFilePersistentConfig(/* set= */ null, configFile.toFile(), tempFile.toFile());

    // Complete init but do not provide a ticker
    cfg.finishedInit(/* ticker= */ null);

    // Act: attempt to store; expected to be refused due to null ticker
    cfg.setHasNodeStarted(); // even if node is started, lack of ticker prevents scheduling
    cfg.store();

    // Assert: no file written and no ticker interactions
    assertFalse(Files.exists(configFile), "no file should be created without a ticker");
    verifyNoInteractions(ticker);
  }

  @Test
  void store_whenAlreadyWriting_ignoresConcurrentRequest_thenAllowsSubsequent() throws Exception {
    FreenetFilePersistentConfig cfg =
        new FreenetFilePersistentConfig(/* set= */ null, configFile.toFile(), tempFile.toFile());
    cfg.finishedInit(ticker);
    cfg.setHasNodeStarted();

    // First store schedules one job
    cfg.store();
    ArgumentCaptor<Runnable> jobCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(ticker, times(1)).queueTimedJob(jobCaptor.capture(), anyLong());

    // A second store while write is pending should be ignored (no additional schedule)
    cfg.store();
    verify(ticker, times(1)).queueTimedJob(eq(jobCaptor.getValue()), anyLong());

    // Complete the first write
    jobCaptor.getValue().run();
    assertTrue(Files.exists(configFile), "first scheduled write should persist the file");

    // After completion, another store should schedule a new job
    cfg.store();
    verify(ticker, times(2)).queueTimedJob(jobCaptor.capture(), anyLong());
  }

  @Test
  void store_whenInterruptedBeforeNodeStart_bailsAndDoesNotPersist_thenAllowsLaterStore()
      throws Exception {
    FreenetFilePersistentConfig cfg =
        new FreenetFilePersistentConfig(/* set= */ null, configFile.toFile(), tempFile.toFile());
    cfg.finishedInit(ticker);

    // Schedule write while node has not started yet (will wait inside the job).
    cfg.store();
    ArgumentCaptor<Runnable> jobCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(ticker, times(1)).queueTimedJob(jobCaptor.capture(), anyLong());

    // Run the job on a separate thread and interrupt immediately. If the interrupt flag is set
    // before the first wait(), Java will throw InterruptedException on entering wait(), so we do
    // not need to sleep or poll here.
    Thread t = new Thread(jobCaptor.getValue(), "cfg-writer-test");
    t.start();
    t.interrupt();
    t.join(2000);

    // The job should have aborted without persisting.
    assertFalse(Files.exists(configFile), "config file must not be written on interrupt");

    // Now mark node as started and try again; the previous write flag must have been reset.
    cfg.setHasNodeStarted();
    cfg.store();
    verify(ticker, times(2)).queueTimedJob(jobCaptor.capture(), anyLong());

    // Execute the newly scheduled job; this time it should persist.
    jobCaptor.getValue().run();
    assertTrue(Files.exists(configFile), "config file should be written after startup");
  }
}
