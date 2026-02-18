package network.crypta.node.subsystem;

import java.util.stream.Stream;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.NodeToNodeMessageListener;
import network.crypta.node.PeerNode;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeMessagingSubsystemTest {
  private NodeMessagingSubsystem subsystem;

  @BeforeEach
  void setUp() {
    subsystem = new NodeMessagingSubsystem();
  }

  @Test
  void receivedNodeToNodeMessage_whenMessageWrapper_expectListenerInvokedWithPayload() {
    NodeToNodeMessageListener listener = mock(NodeToNodeMessageListener.class);
    PeerNode source = mock(PeerNode.class);
    Message message = mock(Message.class);
    byte[] payload = new byte[] {1, 2, 3};
    ShortBuffer buffer = new ShortBuffer(payload);
    int type = 42;

    subsystem.registerNodeToNodeMessageListener(type, listener);
    when(message.getObject(DMT.NODE_TO_NODE_MESSAGE_TYPE)).thenReturn(type);
    when(message.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA)).thenReturn(buffer);

    subsystem.receivedNodeToNodeMessage(message, source);

    ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(listener).handleMessage(dataCaptor.capture(), eq(false), same(source), eq(type));
    assertArrayEquals(payload, dataCaptor.getValue());
  }

  @Test
  void receivedNodeToNodeMessage_whenListenerMissing_expectListenerNotInvoked() {
    NodeToNodeMessageListener listener = mock(NodeToNodeMessageListener.class);
    PeerNode source = mock(PeerNode.class);
    ShortBuffer buffer = new ShortBuffer(new byte[] {9});

    subsystem.registerNodeToNodeMessageListener(1, listener);
    subsystem.receivedNodeToNodeMessage(source, 2, buffer, false);

    verifyNoInteractions(listener);
  }

  @Test
  void receivedNodeToNodeMessage_whenFromDarknet_expectFromDarknetTrue() {
    NodeToNodeMessageListener listener = mock(NodeToNodeMessageListener.class);
    DarknetPeerNode source = mock(DarknetPeerNode.class);
    ShortBuffer buffer = new ShortBuffer(new byte[] {7, 8});
    int type = 7;

    subsystem.registerNodeToNodeMessageListener(type, listener);

    subsystem.receivedNodeToNodeMessage(source, type, buffer, true);

    verify(listener).handleMessage(buffer.getData(), true, source, type);
  }

  @Test
  void handleNodeToNodeTextMessageSimpleFieldSet_whenMissingOverallType_expectThrows() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    DarknetPeerNode source = mock(DarknetPeerNode.class);

    assertThrows(
        FSParseException.class,
        () -> subsystem.handleNodeToNodeTextMessageSimpleFieldSet(fs, source, 3));
  }

  @Test
  void handleNodeToNodeTextMessageSimpleFieldSet_whenFproxyMissingSubtype_expectThrows() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    DarknetPeerNode source = mock(DarknetPeerNode.class);

    fs.put(Node.N2N_TYPE_KEY, Node.N2N_MESSAGE_TYPE_FPROXY);

    assertThrows(
        FSParseException.class,
        () -> subsystem.handleNodeToNodeTextMessageSimpleFieldSet(fs, source, 4));
  }

  @ParameterizedTest
  @MethodSource("fproxyMessageTypes")
  void handleNodeToNodeTextMessageSimpleFieldSet_whenFproxySubtype_expectDelegates(
      int fproxyType, String handlerName) throws FSParseException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    DarknetPeerNode source = mock(DarknetPeerNode.class);
    int fileNumber = 5;

    fs.put(Node.N2N_TYPE_KEY, Node.N2N_MESSAGE_TYPE_FPROXY);
    fs.put("type", fproxyType);

    subsystem.handleNodeToNodeTextMessageSimpleFieldSet(fs, source, fileNumber);

    assertNull(fs.get(Node.N2N_TYPE_KEY));
    switch (handlerName) {
      case "handleFproxyN2NTM" -> verify(source).handleFproxyN2NTM(fs, fileNumber);
      case "handleFproxyFileOffer" -> verify(source).handleFproxyFileOffer(fs, fileNumber);
      case "handleFproxyFileOfferAccepted" ->
          verify(source).handleFproxyFileOfferAccepted(fs, fileNumber);
      case "handleFproxyFileOfferRejected" ->
          verify(source).handleFproxyFileOfferRejected(fs, fileNumber);
      case "handleFproxyBookmarkFeed" -> verify(source).handleFproxyBookmarkFeed(fs, fileNumber);
      case "handleFproxyDownloadFeed" -> verify(source).handleFproxyDownloadFeed(fs, fileNumber);
      default -> throw new IllegalStateException("Unhandled handler: " + handlerName);
    }
    verifyNoMoreInteractions(source);
  }

  @Test
  void handleNodeToNodeTextMessageSimpleFieldSet_whenUnknownOverallType_expectNoDelegation()
      throws FSParseException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    DarknetPeerNode source = mock(DarknetPeerNode.class);

    fs.put(Node.N2N_TYPE_KEY, Node.N2N_MESSAGE_TYPE_DIFFNODEREF);

    subsystem.handleNodeToNodeTextMessageSimpleFieldSet(fs, source, 9);

    assertNull(fs.get(Node.N2N_TYPE_KEY));
    verify(source, never()).handleFproxyN2NTM(fs, 9);
    verify(source, never()).handleFproxyFileOffer(fs, 9);
    verify(source, never()).handleFproxyFileOfferAccepted(fs, 9);
    verify(source, never()).handleFproxyFileOfferRejected(fs, 9);
    verify(source, never()).handleFproxyBookmarkFeed(fs, 9);
    verify(source, never()).handleFproxyDownloadFeed(fs, 9);
  }

  private static Stream<Arguments> fproxyMessageTypes() {
    return Stream.of(
        Arguments.of(Node.N2N_TEXT_MESSAGE_TYPE_USERALERT, "handleFproxyN2NTM"),
        Arguments.of(Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER, "handleFproxyFileOffer"),
        Arguments.of(
            Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED, "handleFproxyFileOfferAccepted"),
        Arguments.of(
            Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED, "handleFproxyFileOfferRejected"),
        Arguments.of(Node.N2N_TEXT_MESSAGE_TYPE_BOOKMARK, "handleFproxyBookmarkFeed"),
        Arguments.of(Node.N2N_TEXT_MESSAGE_TYPE_DOWNLOAD, "handleFproxyDownloadFeed"));
  }
}
