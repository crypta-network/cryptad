package network.crypta.clients.fcp;

import java.io.File;
import java.util.Random;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class TestDdaResponseMessageTest {

  private static final String DIRECTORY = "/tmp/dir";

  @Mock private FCPConnectionHandler handler;

  @Test
  void constructor_whenDirectoryMissing_throwsMessageInvalidException() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new TestDdaResponseMessage(sfs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("No Directory given!", exception.getMessage());
  }

  @Test
  void constructor_whenDirectoryEmpty_throwsMessageInvalidException() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle(TestDdaRequestMessage.DIRECTORY, "");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new TestDdaResponseMessage(sfs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("The specified Directory can't be empty!", exception.getMessage());
  }

  @Test
  void run_whenHandlerThrowsIllegalArgument_wrapsInMessageInvalidException() throws Exception {
    SimpleFieldSet sfs = createFieldSet(null);
    TestDdaResponseMessage message = new TestDdaResponseMessage(sfs);
    when(handler.popDDACheck(DIRECTORY))
        .thenThrow(new IllegalArgumentException("unsupported directory"));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals("unsupported directory", exception.getMessage());
    assertEquals(DIRECTORY, exception.ident);
  }

  @Test
  void run_whenJobUnknown_throwsInvalidMessage() throws Exception {
    SimpleFieldSet sfs = createFieldSet(null);
    TestDdaResponseMessage message = new TestDdaResponseMessage(sfs);
    when(handler.popDDACheck(DIRECTORY)).thenReturn(null);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertTrue(exception.getMessage().contains(DIRECTORY));
  }

  @Test
  void run_whenReadRequestedButNoContent_throwsMissingField() throws Exception {
    SimpleFieldSet sfs = createFieldSet(null);
    TestDdaResponseMessage message = new TestDdaResponseMessage(sfs);
    DdaCheckJob job =
        new DdaCheckJob(new Random(0), new File(DIRECTORY), new File(DIRECTORY + "/read"), null);
    when(handler.popDDACheck(DIRECTORY)).thenReturn(job);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertTrue(exception.getMessage().contains(TestDdaResponseMessage.READ_CONTENT));
  }

  @Test
  void run_whenJobPresent_sendsCompleteMessage() throws Exception {
    DdaCheckJob job =
        new DdaCheckJob(new Random(1), new File(DIRECTORY), new File(DIRECTORY + "/read"), null);
    SimpleFieldSet sfs = createFieldSet(job.readContent);
    TestDdaResponseMessage message = new TestDdaResponseMessage(sfs);
    when(handler.popDDACheck(DIRECTORY)).thenReturn(job);
    ArgumentCaptor<TestDdaCompleteMessage> captor =
        ArgumentCaptor.forClass(TestDdaCompleteMessage.class);

    message.run(handler);

    verify(handler, times(1)).popDDACheck(DIRECTORY);
    verify(handler).send(captor.capture());

    TestDdaCompleteMessage completeMessage = captor.getValue();
    assertEquals(job, completeMessage.checkJob);
    assertEquals(job.readContent, completeMessage.readContentFromClient);
  }

  private static SimpleFieldSet createFieldSet(String readContent) {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle(TestDdaRequestMessage.DIRECTORY, DIRECTORY);
    if (readContent != null) {
      sfs.putSingle(TestDdaResponseMessage.READ_CONTENT, readContent);
    }
    return sfs;
  }
}
