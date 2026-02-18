package network.crypta.node;

import java.util.stream.Stream;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeSwapMessageHandlerTest {

  @Mock private Node node;
  @Mock private NodeNetworkSubsystem networkSubsystem;
  @Mock private LocationManager locationManager;
  @Mock private Message message;
  @Mock private PeerNode peerNode;

  private NodeSwapMessageHandler handler;

  @BeforeEach
  void setUp() {
    handler = new NodeSwapMessageHandler(node);
  }

  @Test
  void handle_whenSwapRequest_expectTrueAndDelegates() {
    // Arrange
    when(message.getSpec()).thenReturn(DMT.FNPSwapRequest);
    stubLocationManager();

    // Act
    boolean result = handler.handle(message, peerNode);

    // Assert
    assertTrue(result);
    verify(locationManager).handleSwapRequest(message, peerNode);
    verify(node).network();
    verify(networkSubsystem).locationManager();
    verifyNoMoreInteractions(locationManager, networkSubsystem, node);
  }

  @ParameterizedTest
  @MethodSource("swapActions")
  void handle_whenSwapAction_expectDelegatedResult(SwapAction action, boolean delegateResult) {
    // Arrange
    when(message.getSpec()).thenReturn(action.spec);
    stubLocationManager();
    action.stub(locationManager, message, peerNode, delegateResult);

    // Act
    boolean result = handler.handle(message, peerNode);

    // Assert
    assertEquals(delegateResult, result);
    action.verifyCall(locationManager, message, peerNode);
    verify(node).network();
    verify(networkSubsystem).locationManager();
    verifyNoMoreInteractions(locationManager, networkSubsystem, node);
  }

  @Test
  void handle_whenSwapCommitThrows_expectPropagates() {
    // Arrange
    when(message.getSpec()).thenReturn(DMT.FNPSwapCommit);
    stubLocationManager();
    RuntimeException failure = new RuntimeException("boom");
    doThrow(failure).when(locationManager).handleSwapCommit(message, peerNode);

    // Act + Assert
    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> handler.handle(message, peerNode));
    assertEquals("boom", thrown.getMessage());
    verify(locationManager).handleSwapCommit(message, peerNode);
    verify(node).network();
    verify(networkSubsystem).locationManager();
    verifyNoMoreInteractions(locationManager, networkSubsystem, node);
  }

  @Test
  void handle_whenUnknownSpec_expectFalseAndNoDelegation() {
    // Arrange
    MessageType unknownSpec = mock(MessageType.class);
    when(message.getSpec()).thenReturn(unknownSpec);

    // Act
    boolean result = handler.handle(message, peerNode);

    // Assert
    assertFalse(result);
    verifyNoInteractions(node, networkSubsystem, locationManager);
  }

  private void stubLocationManager() {
    when(node.network()).thenReturn(networkSubsystem);
    when(networkSubsystem.locationManager()).thenReturn(locationManager);
  }

  private static Stream<Arguments> swapActions() {
    return Stream.of(SwapAction.values())
        .flatMap(action -> Stream.of(Arguments.of(action, true), Arguments.of(action, false)));
  }

  @SuppressWarnings("ImmutableEnumChecker")
  private enum SwapAction {
    REPLY(DMT.FNPSwapReply) {
      @Override
      void stub(LocationManager manager, Message message, PeerNode peerNode, boolean result) {
        when(manager.handleSwapReply(message, peerNode)).thenReturn(result);
      }

      @Override
      void verifyCall(LocationManager manager, Message message, PeerNode peerNode) {
        org.mockito.Mockito.verify(manager).handleSwapReply(message, peerNode);
      }
    },
    REJECTED(DMT.FNPSwapRejected) {
      @Override
      void stub(LocationManager manager, Message message, PeerNode peerNode, boolean result) {
        when(manager.handleSwapRejected(message, peerNode)).thenReturn(result);
      }

      @Override
      void verifyCall(LocationManager manager, Message message, PeerNode peerNode) {
        org.mockito.Mockito.verify(manager).handleSwapRejected(message, peerNode);
      }
    },
    COMMIT(DMT.FNPSwapCommit) {
      @Override
      void stub(LocationManager manager, Message message, PeerNode peerNode, boolean result) {
        when(manager.handleSwapCommit(message, peerNode)).thenReturn(result);
      }

      @Override
      void verifyCall(LocationManager manager, Message message, PeerNode peerNode) {
        org.mockito.Mockito.verify(manager).handleSwapCommit(message, peerNode);
      }
    },
    COMPLETE(DMT.FNPSwapComplete) {
      @Override
      void stub(LocationManager manager, Message message, PeerNode peerNode, boolean result) {
        when(manager.handleSwapComplete(message, peerNode)).thenReturn(result);
      }

      @Override
      void verifyCall(LocationManager manager, Message message, PeerNode peerNode) {
        org.mockito.Mockito.verify(manager).handleSwapComplete(message, peerNode);
      }
    };

    private final MessageType spec;

    SwapAction(MessageType spec) {
      this.spec = spec;
    }

    abstract void stub(LocationManager manager, Message message, PeerNode peerNode, boolean result);

    abstract void verifyCall(LocationManager manager, Message message, PeerNode peerNode);
  }
}
