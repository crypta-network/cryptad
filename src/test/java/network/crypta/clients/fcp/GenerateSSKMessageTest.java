package network.crypta.clients.fcp;

import java.util.concurrent.atomic.AtomicReference;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.node.Node;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class GenerateSSKMessageTest {

  @Test
  void getFieldSet_withIdentifier_returnsIdentifier() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "id-123");
    GenerateSSKMessage message = new GenerateSSKMessage(fs);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("id-123", result.get("Identifier"));
  }

  @Test
  void getFieldSet_withoutIdentifier_omitsIdentifier() {
    GenerateSSKMessage message = new GenerateSSKMessage(new SimpleFieldSet(true));

    SimpleFieldSet result = message.getFieldSet();

    assertNull(result.get("Identifier"));
  }

  @Test
  void getName_always_returnsWireName() {
    GenerateSSKMessage message = new GenerateSSKMessage(new SimpleFieldSet(true));

    assertEquals("GenerateSSK", message.getName());
  }

  @Test
  void run_whenIdentifierPresent_sendsKeypairMessageWithIdentifier() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "client-1");
    GenerateSSKMessage message = new GenerateSSKMessage(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FCPServer server = mock(FCPServer.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    RandomnessPort randomnessPort = mock(RandomnessPort.class);
    Node node = mock(Node.class);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.randomness()).thenReturn(randomnessPort);

    FreenetURI insertUri =
        new FreenetURI("SSK", "insert", new byte[] {1, 2}, new byte[32], new byte[] {3});
    FreenetURI requestUri =
        new FreenetURI("SSK", "request", new byte[] {4, 5}, new byte[32], new byte[] {6});

    InsertableClientSSK generatedKey = mock(InsertableClientSSK.class);
    when(generatedKey.getInsertURI()).thenReturn(insertUri);
    when(generatedKey.getURI()).thenReturn(requestUri);
    AtomicReference<RandomSource> randomAdapterRef = new AtomicReference<>();

    try (MockedStatic<InsertableClientSSK> mocked = mockStatic(InsertableClientSSK.class)) {
      mocked
          .when(() -> InsertableClientSSK.createRandom(any(RandomSource.class), eq("")))
          .thenAnswer(
              invocation -> {
                RandomSource randomSource = invocation.getArgument(0);
                randomAdapterRef.set(randomSource);
                randomSource.nextBytes(new byte[16]);
                return generatedKey;
              });

      message.run(handler, node);

      mocked.verify(
          () -> InsertableClientSSK.createRandom(any(RandomSource.class), eq("")), times(1));
      assertNotNull(randomAdapterRef.get());
      verify(randomnessPort, times(1)).fillSecureRandom(any(byte[].class));
      verify(runtimePorts, times(1)).randomness();

      ArgumentCaptor<SSKKeypairMessage> captor = ArgumentCaptor.forClass(SSKKeypairMessage.class);
      verify(handler, times(1)).send(captor.capture());
      SimpleFieldSet sentFieldSet = captor.getValue().getFieldSet();

      assertEquals(insertUri.toString(), sentFieldSet.get("InsertURI"));
      assertEquals(requestUri.toString(), sentFieldSet.get("RequestURI"));
      assertEquals("client-1", sentFieldSet.get("Identifier"));
    }
  }

  @Test
  void run_whenIdentifierMissing_sendsKeypairMessageWithoutIdentifier() throws Exception {
    GenerateSSKMessage message = new GenerateSSKMessage(new SimpleFieldSet(true));

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FCPServer server = mock(FCPServer.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    RandomnessPort randomnessPort = mock(RandomnessPort.class);
    Node node = mock(Node.class);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.randomness()).thenReturn(randomnessPort);

    FreenetURI insertUri =
        new FreenetURI("SSK", "insert", new byte[] {7, 8}, new byte[32], new byte[] {9});
    FreenetURI requestUri =
        new FreenetURI("SSK", "request", new byte[] {10, 11}, new byte[32], new byte[] {12});

    InsertableClientSSK generatedKey = mock(InsertableClientSSK.class);
    when(generatedKey.getInsertURI()).thenReturn(insertUri);
    when(generatedKey.getURI()).thenReturn(requestUri);

    try (MockedStatic<InsertableClientSSK> mocked = mockStatic(InsertableClientSSK.class)) {
      mocked
          .when(() -> InsertableClientSSK.createRandom(any(RandomSource.class), eq("")))
          .thenAnswer(
              invocation -> {
                RandomSource randomSource = invocation.getArgument(0);
                randomSource.nextBytes(new byte[16]);
                return generatedKey;
              });

      message.run(handler, node);

      verify(randomnessPort, times(1)).fillSecureRandom(any(byte[].class));

      ArgumentCaptor<SSKKeypairMessage> captor = ArgumentCaptor.forClass(SSKKeypairMessage.class);
      verify(handler, times(1)).send(captor.capture());
      SimpleFieldSet sentFieldSet = captor.getValue().getFieldSet();

      assertEquals(insertUri.toString(), sentFieldSet.get("InsertURI"));
      assertEquals(requestUri.toString(), sentFieldSet.get("RequestURI"));
      assertNull(sentFieldSet.get("Identifier"));
    }
  }
}
