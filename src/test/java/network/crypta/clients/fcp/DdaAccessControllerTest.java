package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.io.FileUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DdaAccessControllerTest {

  @Mock private FCPServer server;
  @Mock private Logger log;
  @Mock private RuntimePorts runtimePorts;
  @Mock private RandomnessPort randomnessPort;

  @TempDir private Path tempDir;

  private DdaAccessController controller;
  private Random random;

  @BeforeEach
  void setUp() {
    controller = new DdaAccessController(server, log);
    random = new Random(42L);
  }

  @AfterEach
  void tearDown() {
    controller.freeDDAJobs();
  }

  private void stubRandomAccess() {
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.randomness()).thenReturn(randomnessPort);
    when(randomnessPort.fastWeakRandom()).thenReturn(random);
  }

  @Test
  void allowDDAFrom_whenWriteRequestAndNoEntry_usesServerDownloadFlag() throws IOException {
    File testFile = Files.createFile(tempDir.resolve("write.bin")).toFile();
    when(server.isDownloadDDAAlwaysAllowed()).thenReturn(false);

    boolean allowed = controller.allowDDAFrom(testFile, true);

    assertFalse(allowed);
  }

  @Test
  void allowDDAFrom_whenReadRequestAndNoEntry_usesServerUploadFlag() throws IOException {
    File testFile = Files.createFile(tempDir.resolve("read.bin")).toFile();
    when(server.isUploadDDAAlwaysAllowed()).thenReturn(true);

    boolean allowed = controller.allowDDAFrom(testFile, false);

    assertTrue(allowed);
  }

  @Test
  void allowDDAFrom_whenDirectoryRegistered_returnsStoredReadFlag() throws IOException {
    Path directory = Files.createDirectory(tempDir.resolve("registered-read"));
    String canonicalPath = FileUtil.getCanonicalFile(directory.toFile()).getPath();
    controller.registerTestDDAResult(canonicalPath, false, true);
    File file = Files.createFile(directory.resolve("child.bin")).toFile();

    boolean allowed = controller.allowDDAFrom(file, false);

    assertFalse(allowed);
  }

  @Test
  void allowDDAFrom_whenDirectoryRegistered_returnsStoredWriteFlag() throws IOException {
    Path directory = Files.createDirectory(tempDir.resolve("registered-write"));
    String canonicalPath = FileUtil.getCanonicalFile(directory.toFile()).getPath();
    controller.registerTestDDAResult(canonicalPath, true, false);
    File file = Files.createFile(directory.resolve("child.bin")).toFile();

    boolean allowed = controller.allowDDAFrom(file, true);

    assertFalse(allowed);
  }

  @Test
  void enqueueDDACheck_whenDirectoryMissing_throwsIllegalArgumentException() {
    String missingPath = tempDir.resolve("missing").toString();

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class,
            () -> controller.enqueueDDACheck(missingPath, true, false));

    assertTrue(thrown.getMessage().contains("directory"));
  }

  @Test
  void enqueueDDACheck_whenJobAlreadyInProgress_throwsIllegalArgumentException()
      throws IOException {
    Path directory = Files.createDirectory(tempDir.resolve("duplicate"));
    stubRandomAccess();
    String directoryPath = directory.toString();
    controller.enqueueDDACheck(directoryPath, false, false);

    Runnable duplicateCheck = () -> controller.enqueueDDACheck(directoryPath, true, true);
    assertThrows(IllegalArgumentException.class, duplicateCheck::run);
  }

  @Test
  void enqueueDDACheck_whenReadRequested_createsReadChallengeFile() throws IOException {
    Path directory = Files.createDirectory(tempDir.resolve("read"));
    stubRandomAccess();

    DdaCheckJob job = controller.enqueueDDACheck(directory.toString(), true, false);

    assertNotNull(job.readFilename);
    assertTrue(job.readFilename.exists());
    String content = Files.readString(job.readFilename.toPath());
    assertEquals(job.readContent, content);
  }

  @Test
  void enqueueDDACheck_whenWriteRequested_generatesWriteFileUnderDirectory() throws IOException {
    Path directory = Files.createDirectory(tempDir.resolve("write"));
    stubRandomAccess();

    DdaCheckJob job = controller.enqueueDDACheck(directory.toString(), false, true);

    assertNotNull(job.writeFilename);
    assertEquals(directory.toFile(), job.writeFilename.getParentFile());
    assertTrue(job.writeFilename.getName().startsWith("DDACheck-"));
    assertTrue(job.writeFilename.getName().endsWith(".tmp"));
  }

  @Test
  void popDDACheck_whenDirectoryMissing_throwsIllegalArgumentException() {
    String missingPath = tempDir.resolve("missing-pop").toString();

    assertThrows(IllegalArgumentException.class, () -> controller.popDDACheck(missingPath));
  }

  @Test
  void popDDACheck_whenJobExists_returnsAndRemovesJob() throws IOException {
    Path directory = Files.createDirectory(tempDir.resolve("pop"));
    stubRandomAccess();
    DdaCheckJob job = controller.enqueueDDACheck(directory.toString(), true, false);

    DdaCheckJob popped = controller.popDDACheck(directory.toString());

    assertSame(job, popped);
    assertNull(controller.popDDACheck(directory.toString()));
  }

  @Test
  void freeDDAJobs_whenReadFilePresent_deletesIt() throws IOException {
    Path directory = Files.createDirectory(tempDir.resolve("cleanup"));
    stubRandomAccess();
    DdaCheckJob job = controller.enqueueDDACheck(directory.toString(), true, false);
    assertTrue(job.readFilename.exists());

    controller.freeDDAJobs();

    assertFalse(job.readFilename.exists());
  }
}
