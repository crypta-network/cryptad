package network.crypta.clients.fcp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SendTextMessageTest {

  private static final String IDENTIFIER = "test-identifier";
  private static final String NODE_IDENTIFIER = "peer-node-1";

  @Mock private FcpDarknetPeerHandle darknetPeerNode;
  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;
  @Mock private FcpMessageRuntimeSupport messageRuntimeSupport;

  @Test
  void getName_whenCalled_returnsSendText() throws MessageInvalidException {
    SendTextMessage message = new SendTextMessage(baseFieldSet());

    assertEquals(SendTextMessage.NAME, message.getName());
  }

  @Test
  void handleFeed_whenDataPresent_sendsUtf8PayloadToPeer() throws Exception {
    String text = "Grüße €";
    byte[] payload = text.getBytes(StandardCharsets.UTF_8);
    SendTextMessage message = new SendTextMessage(baseFieldSetWithLength(payload.length));
    message.bucket = new ArrayBucket(payload);
    Mockito.when(darknetPeerNode.sendTextFeed(text)).thenReturn(123);

    int status = message.handleFeed(darknetPeerNode);

    assertEquals(123, status);
    verify(darknetPeerNode).sendTextFeed(text);
  }

  @Test
  void handleFeed_whenDataLengthNonPositive_throwsMessageInvalidException() throws Exception {
    SendTextMessage message = new SendTextMessage(baseFieldSetWithLength(0));

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.handleFeed(darknetPeerNode));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, ex.protocolCode);
    assertEquals("Invalid data length", ex.getMessage());
    verify(darknetPeerNode, never()).sendTextFeed(Mockito.anyString());
  }

  @Test
  void handleFeed_whenBucketReadFails_wrapsIOException() throws Exception {
    SendTextMessage message = new SendTextMessage(baseFieldSetWithLength(1));
    Bucket bucket = Mockito.mock(Bucket.class);
    message.bucket = bucket;
    Mockito.when(bucket.size()).thenReturn(1L);
    Mockito.when(bucket.getInputStreamUnbuffered()).thenThrow(new IOException("boom"));

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.handleFeed(darknetPeerNode));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, ex.protocolCode);
    assertEquals("", ex.getMessage());
    verify(darknetPeerNode, never()).sendTextFeed(Mockito.anyString());
  }

  @Test
  void run_whenPeerUnknown_sendsUnknownNodeIdentifierMessage() throws Exception {
    SendTextMessage message = new SendTextMessage(baseFieldSet());
    when(handler.getServer()).thenReturn(server);
    when(server.messageRuntimeSupport()).thenReturn(messageRuntimeSupport);
    when(messageRuntimeSupport.findPeer(NODE_IDENTIFIER)).thenReturn(FcpPeerLookupResult.unknown());
    ArgumentCaptor<FCPMessage> sentCaptor = ArgumentCaptor.forClass(FCPMessage.class);

    message.run(handler);

    verify(handler).send(sentCaptor.capture());
    UnknownNodeIdentifierMessage sent =
        assertInstanceOf(UnknownNodeIdentifierMessage.class, sentCaptor.getValue());
    assertEquals(NODE_IDENTIFIER, sent.getFieldSet().get("NodeIdentifier"));
    assertEquals(IDENTIFIER, sent.getFieldSet().get("Identifier"));
  }

  @Test
  void run_whenPeerIsNotDarknet_throwsDarknetOnly() throws Exception {
    SendTextMessage message = new SendTextMessage(baseFieldSet());
    when(handler.getServer()).thenReturn(server);
    when(server.messageRuntimeSupport()).thenReturn(messageRuntimeSupport);
    when(messageRuntimeSupport.findPeer(NODE_IDENTIFIER))
        .thenReturn(FcpPeerLookupResult.nonDarknet());

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.DARKNET_ONLY, ex.protocolCode);
    assertEquals("SendText only available for darknet peers", ex.getMessage());
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(Mockito.any());
  }

  @Test
  void run_whenDarknetPeerResolved_sendsSentPeerMessage() throws Exception {
    String text = "hello peer";
    byte[] payload = text.getBytes(StandardCharsets.UTF_8);
    SendTextMessage message = new SendTextMessage(baseFieldSetWithLength(payload.length));
    message.bucket = new ArrayBucket(payload);
    when(handler.getServer()).thenReturn(server);
    when(server.messageRuntimeSupport()).thenReturn(messageRuntimeSupport);
    when(messageRuntimeSupport.findPeer(NODE_IDENTIFIER))
        .thenReturn(FcpPeerLookupResult.darknet(darknetPeerNode));
    when(darknetPeerNode.sendTextFeed(text)).thenReturn(123);
    ArgumentCaptor<FCPMessage> sentCaptor = ArgumentCaptor.forClass(FCPMessage.class);

    message.run(handler);

    verify(handler).send(sentCaptor.capture());
    SentPeerMessage sent = assertInstanceOf(SentPeerMessage.class, sentCaptor.getValue());
    assertEquals(IDENTIFIER, sent.clientIdentifier);
    assertEquals(123, sent.nodeStatus);
  }

  private SimpleFieldSet baseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("NodeIdentifier", NODE_IDENTIFIER);
    return fs;
  }

  private SimpleFieldSet baseFieldSetWithLength(long dataLength) {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("DataLength", dataLength);
    return fs;
  }
}
