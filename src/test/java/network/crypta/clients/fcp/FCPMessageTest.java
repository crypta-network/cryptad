package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link FCPMessage}.
 *
 * @author <a href="mailto:david.roden@bietr.de">David Roden</a>
 */
class FCPMessageTest {

  private static final String LIST_REQUEST_IDENTIFIER = "ListRequestIdentifier";
  private static final String IDENTIFIER = "identifier";
  private static final String MESSAGE_NAME = "SomeMessage";
  private static final String END_STRING = "End";

  private final FCPMessage originalMessage = mock(FCPMessage.class);

  @Test
  void wrappingNullReturnsNull() {
    //noinspection ConstantValue
    assertThat(FCPMessage.withListRequestIdentifier(null, LIST_REQUEST_IDENTIFIER), nullValue());
  }

  @Test
  void wrappingMessageAddsIdentifier() {
    when(originalMessage.getFieldSet()).thenReturn(new SimpleFieldSet(true));
    FCPMessage wrappedMessage = FCPMessage.withListRequestIdentifier(originalMessage, IDENTIFIER);
    assertThat(wrappedMessage.getFieldSet().get(LIST_REQUEST_IDENTIFIER), is(IDENTIFIER));
  }

  @Test
  void messageIsNotWrappedIfListRequestIdentifierIsNull() {
    assertThat(
        FCPMessage.withListRequestIdentifier(originalMessage, null), sameInstance(originalMessage));
  }

  @Test
  void wrappedMessageDelegatesName() {
    when(originalMessage.getName()).thenReturn(MESSAGE_NAME);
    FCPMessage wrappedMessage = FCPMessage.withListRequestIdentifier(originalMessage, IDENTIFIER);
    assertThat(wrappedMessage.getName(), is(MESSAGE_NAME));
    verify(originalMessage).getName();
  }

  @Test
  void wrappedMessageDelegatesRun() throws MessageInvalidException {
    FCPMessage wrappedMessage = FCPMessage.withListRequestIdentifier(originalMessage, IDENTIFIER);
    FCPConnectionHandler connectionHandler = mock(FCPConnectionHandler.class);
    wrappedMessage.run(connectionHandler);
    verify(originalMessage).run(connectionHandler);
  }

  @Test
  void wrappedMessageDelegatesEndString() {
    FCPMessage wrappedMessage = FCPMessage.withListRequestIdentifier(originalMessage, IDENTIFIER);
    when(originalMessage.getEndString()).thenReturn(END_STRING);
    assertThat(wrappedMessage.getEndString(), is(END_STRING));
    verify(originalMessage).getEndString();
  }

  @Test
  void wrappedMessageDelegatesSend() throws IOException {
    FCPMessage wrappedMessage = FCPMessage.withListRequestIdentifier(originalMessage, IDENTIFIER);
    OutputStream outputStream = mock(OutputStream.class);
    wrappedMessage.send(outputStream);
    verify(originalMessage).send(outputStream);
  }

  @Test
  void create_whenUnsupportedFcpPluginMessageCarriesData_drainsPayload() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(FCPMessage.IDENTIFIER, IDENTIFIER);
    fs.put("DataLength", 4L);
    fs.setEndMarker("Data");

    FCPMessage message = FCPMessage.create("FCPPluginMessage", fs, null, null);
    BaseDataCarryingMessage dataMessage = assertInstanceOf(BaseDataCarryingMessage.class, message);
    BucketFactory bucketFactory = mock(BucketFactory.class);
    FCPServer server = mock(FCPServer.class);

    ByteArrayInputStream stream =
        new ByteArrayInputStream(new byte[] {1, 2, 3, 4, (byte) 'N', (byte) 'e', (byte) 'x'});
    dataMessage.readFrom(stream, bucketFactory, server);

    assertEquals('N', stream.read());
  }

  @Test
  void create_whenNonDataUnsupportedPluginMessageUsesDataFraming_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(FCPMessage.IDENTIFIER, IDENTIFIER);
    fs.put("DataLength", 1L);
    fs.setEndMarker("Data");

    assertThrows(
        MessageInvalidException.class, () -> FCPMessage.create("GetPluginInfo", fs, null, null));
  }
}
