package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.concurrent.atomic.AtomicReference;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Probe;
import network.crypta.node.probe.Type;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeProbeHandlerTest {

  @Test
  void constructor_whenCreated_expectProbeConstructedWithNode() {
    Node node = mock(Node.class);
    AtomicReference<Object> constructorArg = new AtomicReference<>();

    try (var _ =
        Mockito.mockConstruction(
            Probe.class, (_, context) -> constructorArg.set(context.arguments().getFirst()))) {
      new NodeProbeHandler(node);

      assertEquals(node, constructorArg.get());
    }
  }

  @Test
  void handle_whenProbeRequest_expectDelegatesAndReturnsTrue() {
    Node node = mock(Node.class);
    Message message = mock(Message.class);
    PeerNode source = mock(PeerNode.class);
    when(message.getSpec()).thenReturn(DMT.ProbeRequest);

    try (MockedConstruction<Probe> mocked = Mockito.mockConstruction(Probe.class)) {
      NodeProbeHandler handler = new NodeProbeHandler(node);
      Probe probe = mocked.constructed().getFirst();

      boolean result = handler.handle(message, source);

      assertTrue(result);
      verify(probe).request(message, source);
      verifyNoMoreInteractions(probe);
    }
  }

  @Test
  void handle_whenNotProbeRequest_expectReturnsFalseAndDoesNotDelegate() {
    Node node = mock(Node.class);
    Message message = mock(Message.class);
    PeerNode source = mock(PeerNode.class);
    MessageType otherType = mock(MessageType.class);
    when(message.getSpec()).thenReturn(otherType);

    try (MockedConstruction<Probe> mocked = Mockito.mockConstruction(Probe.class)) {
      NodeProbeHandler handler = new NodeProbeHandler(node);
      Probe probe = mocked.constructed().getFirst();

      boolean result = handler.handle(message, source);

      assertFalse(result);
      verifyNoInteractions(probe);
    }
  }

  @Test
  void startProbe_whenCalled_expectDelegatesToProbe() {
    Node node = mock(Node.class);
    Listener listener = mock(Listener.class);

    try (MockedConstruction<Probe> mocked = Mockito.mockConstruction(Probe.class)) {
      NodeProbeHandler handler = new NodeProbeHandler(node);
      Probe probe = mocked.constructed().getFirst();

      handler.startProbe((byte) 7, 1234L, Type.BANDWIDTH, listener);

      verify(probe).start((byte) 7, 1234L, Type.BANDWIDTH, listener);
      verifyNoMoreInteractions(probe);
    }
  }
}
