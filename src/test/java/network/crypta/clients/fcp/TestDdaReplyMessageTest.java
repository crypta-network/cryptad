package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.util.Random;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class TestDdaReplyMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Test
  void getFieldSet_whenReadAndWriteProvided_containsDirectoryReadWriteAndContent() {
    File directory = new File("/tmp/dda");
    File readFile = new File("read.dat");
    File writeFile = new File("write.dat");
    DdaCheckJob job = new DdaCheckJob(new Random(42L), directory, readFile, writeFile);
    TestDdaReplyMessage message = new TestDdaReplyMessage(job);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals(directory.toString(), result.get(TestDdaRequestMessage.DIRECTORY));
    assertEquals(readFile.toString(), result.get(TestDdaReplyMessage.READ_FILENAME));
    assertEquals(writeFile.toString(), result.get(TestDdaReplyMessage.WRITE_FILENAME));
    assertEquals(job.writeContent, result.get(TestDdaReplyMessage.CONTENT_TO_WRITE));
  }

  @Test
  void getFieldSet_whenOnlyReadProvided_omitsWriteFieldsAndContent() {
    File directory = new File("/tmp/dda");
    File readFile = new File("read.dat");
    DdaCheckJob job = new DdaCheckJob(new Random(84L), directory, readFile, null);
    TestDdaReplyMessage message = new TestDdaReplyMessage(job);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals(directory.toString(), result.get(TestDdaRequestMessage.DIRECTORY));
    assertEquals(readFile.toString(), result.get(TestDdaReplyMessage.READ_FILENAME));
    assertNull(result.get(TestDdaReplyMessage.WRITE_FILENAME));
    assertNull(result.get(TestDdaReplyMessage.CONTENT_TO_WRITE));
  }

  @Test
  void getFieldSet_whenNoReadOrWriteProvided_containsOnlyDirectory() {
    File directory = new File("/tmp/dda");
    DdaCheckJob job = new DdaCheckJob(new Random(126L), directory, null, null);
    TestDdaReplyMessage message = new TestDdaReplyMessage(job);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals(directory.toString(), result.get(TestDdaRequestMessage.DIRECTORY));
    assertNull(result.get(TestDdaReplyMessage.READ_FILENAME));
    assertNull(result.get(TestDdaReplyMessage.WRITE_FILENAME));
    assertNull(result.get(TestDdaReplyMessage.CONTENT_TO_WRITE));
  }

  @Test
  void getName_whenInvoked_returnsTestDDAReplyConstant() {
    DdaCheckJob job = new DdaCheckJob(new Random(168L), new File("/tmp/dda"), null, null);
    TestDdaReplyMessage message = new TestDdaReplyMessage(job);

    String result = message.getName();

    assertEquals(TestDdaReplyMessage.NAME, result);
  }

  @Test
  void run_whenCalled_throwsMessageInvalidExceptionWithProtocolError() {
    DdaCheckJob job =
        new DdaCheckJob(
            new Random(210L), new File("/tmp/dda"), new File("read"), new File("write"));
    TestDdaReplyMessage message = new TestDdaReplyMessage(job);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(TestDdaReplyMessage.NAME, exception.ident);
    assertFalse(exception.global);
    assertEquals(
        TestDdaReplyMessage.NAME + " goes from server to client not the other way around",
        exception.getMessage());
  }
}
