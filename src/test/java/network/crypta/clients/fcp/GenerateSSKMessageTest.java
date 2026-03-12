package network.crypta.clients.fcp;

import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    RandomSource randomSource = mock(RandomSource.class);
    when(node.bootstrap().random()).thenReturn(randomSource);

    FreenetURI insertUri =
        new FreenetURI("SSK", "insert", new byte[] {1, 2}, new byte[32], new byte[] {3});
    FreenetURI requestUri =
        new FreenetURI("SSK", "request", new byte[] {4, 5}, new byte[32], new byte[] {6});

    InsertableClientSSK generatedKey = mock(InsertableClientSSK.class);
    when(generatedKey.getInsertURI()).thenReturn(insertUri);
    when(generatedKey.getURI()).thenReturn(requestUri);

    try (MockedStatic<InsertableClientSSK> mocked = mockStatic(InsertableClientSSK.class)) {
      mocked
          .when(() -> InsertableClientSSK.createRandom(randomSource, ""))
          .thenReturn(generatedKey);

      message.run(handler, node);

      mocked.verify(() -> InsertableClientSSK.createRandom(randomSource, ""), times(1));
      verify(node.bootstrap(), times(1)).random();

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
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    RandomSource randomSource = mock(RandomSource.class);
    when(node.bootstrap().random()).thenReturn(randomSource);

    FreenetURI insertUri =
        new FreenetURI("SSK", "insert", new byte[] {7, 8}, new byte[32], new byte[] {9});
    FreenetURI requestUri =
        new FreenetURI("SSK", "request", new byte[] {10, 11}, new byte[32], new byte[] {12});

    InsertableClientSSK generatedKey = mock(InsertableClientSSK.class);
    when(generatedKey.getInsertURI()).thenReturn(insertUri);
    when(generatedKey.getURI()).thenReturn(requestUri);

    try (MockedStatic<InsertableClientSSK> mocked = mockStatic(InsertableClientSSK.class)) {
      mocked
          .when(() -> InsertableClientSSK.createRandom(randomSource, ""))
          .thenReturn(generatedKey);

      message.run(handler, node);

      ArgumentCaptor<SSKKeypairMessage> captor = ArgumentCaptor.forClass(SSKKeypairMessage.class);
      verify(handler, times(1)).send(captor.capture());
      SimpleFieldSet sentFieldSet = captor.getValue().getFieldSet();

      assertEquals(insertUri.toString(), sentFieldSet.get("InsertURI"));
      assertEquals(requestUri.toString(), sentFieldSet.get("RequestURI"));
      assertNull(sentFieldSet.get("Identifier"));
    }
  }
}
