package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Random;
import network.crypta.node.Node;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class TestDdaCompleteMessageTest {

  @TempDir File tempDir;

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Test
  void getName_whenInvoked_returnsConstantName() {
    DdaCheckJob job = new DdaCheckJob(new Random(1L), tempDir, null, null);
    TestDdaCompleteMessage message = new TestDdaCompleteMessage(handler, job, job.readContent);

    assertEquals(TestDdaCompleteMessage.NAME, message.getName());
    verifyNoMoreInteractions(handler);
  }

  @Test
  void getFieldSet_whenReadAndWriteValid_expectFlagsTrueAndReadFileDeleted() throws IOException {
    File readFile = new File(tempDir, "read.txt");
    Files.writeString(readFile.toPath(), "placeholder", StandardCharsets.UTF_8);

    File writeFile = new File(tempDir, "write.txt");

    DdaCheckJob job = new DdaCheckJob(new Random(2L), tempDir, readFile, writeFile);
    Files.writeString(writeFile.toPath(), job.writeContent, StandardCharsets.UTF_8);

    TestDdaCompleteMessage message = new TestDdaCompleteMessage(handler, job, job.readContent);

    var fieldSet = message.getFieldSet();

    assertEquals(tempDir.toString(), fieldSet.get(TestDdaRequestMessage.DIRECTORY));
    assertEquals("true", fieldSet.get(TestDdaCompleteMessage.READ_ALLOWED));
    assertEquals("true", fieldSet.get(TestDdaCompleteMessage.WRITE_ALLOWED));
    assertFalse(readFile.exists(), "read marker file should be cleaned up");

    verify(handler).registerTestDDAResult(tempDir.toString(), true, true);
    verifyNoMoreInteractions(handler);
  }

  @Test
  void getFieldSet_whenReadContentMismatch_expectReadDisallowedAndFileDeleted() {
    File readFile = new File(tempDir, "read-mismatch.txt");

    DdaCheckJob job = new DdaCheckJob(new Random(3L), tempDir, readFile, null);

    TestDdaCompleteMessage message = new TestDdaCompleteMessage(handler, job, "different-content");

    var fieldSet = message.getFieldSet();

    assertEquals("false", fieldSet.get(TestDdaCompleteMessage.READ_ALLOWED));
    assertFalse(readFile.exists(), "read marker file should be removed even on mismatch");

    verify(handler).registerTestDDAResult(tempDir.toString(), false, false);
    verifyNoMoreInteractions(handler);
  }

  @Test
  void getFieldSet_whenWriteFileMissing_expectWriteDisallowed() {
    File writeFile = new File(tempDir, "missing-write.txt");
    DdaCheckJob job = new DdaCheckJob(new Random(4L), tempDir, null, writeFile);

    TestDdaCompleteMessage message = new TestDdaCompleteMessage(handler, job, job.readContent);

    var fieldSet = message.getFieldSet();

    assertEquals(tempDir.toString(), fieldSet.get(TestDdaRequestMessage.DIRECTORY));
    assertEquals("false", fieldSet.get(TestDdaCompleteMessage.WRITE_ALLOWED));

    verify(handler).registerTestDDAResult(tempDir.toString(), false, false);
    verifyNoMoreInteractions(handler);
  }

  @Test
  void getFieldSet_whenWriteContentMismatch_expectWriteDisallowed() throws IOException {
    File writeFile = new File(tempDir, "write-mismatch.txt");
    DdaCheckJob job = new DdaCheckJob(new Random(5L), tempDir, null, writeFile);
    Files.writeString(writeFile.toPath(), "unexpected", StandardCharsets.UTF_8);

    TestDdaCompleteMessage message = new TestDdaCompleteMessage(handler, job, job.readContent);

    var fieldSet = message.getFieldSet();

    assertEquals("false", fieldSet.get(TestDdaCompleteMessage.WRITE_ALLOWED));

    verify(handler).registerTestDDAResult(tempDir.toString(), false, false);
    verifyNoMoreInteractions(handler);
  }

  @Test
  void run_whenCalled_throwsMessageInvalidException() {
    DdaCheckJob job = new DdaCheckJob(new Random(6L), tempDir, null, null);
    TestDdaCompleteMessage message = new TestDdaCompleteMessage(handler, job, job.readContent);

    assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    verifyNoMoreInteractions(handler);
  }
}
