package network.crypta.clients.fcp;

import java.io.IOException;
import java.util.function.Consumer;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginNotFoundException;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FCPPluginClientMessageTest {

  private static final String IDENTIFIER = "request-1";
  private static final String PLUGIN_NAME = "plugins.Demo";

  @Test
  void constructor_whenIdentifierMissing_expectMissingField() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putOverwrite("PluginName", PLUGIN_NAME);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new FCPPluginClientMessage(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertNull(ex.ident);
  }

  @Test
  void constructor_whenPluginNameMissing_expectMissingField() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putOverwrite("Identifier", IDENTIFIER);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new FCPPluginClientMessage(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
  }

  @Test
  void constructor_whenNonDataHasDataLength_expectInvalidField() {
    SimpleFieldSet fs = minimalFieldSet();
    fs.putOverwrite("DataLength", "42");

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new FCPPluginClientMessage(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
  }

  @Test
  void constructor_whenDataMessageWithoutLength_expectMissingField() {
    SimpleFieldSet fs = minimalFieldSet();
    fs.setEndMarker("Data");

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new FCPPluginClientMessage(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
  }

  @Test
  void constructor_whenDataLengthNotNumeric_expectErrorParsingNumber() {
    SimpleFieldSet fs = minimalFieldSet();
    fs.setEndMarker("Data");
    fs.putOverwrite("DataLength", "NaN");

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new FCPPluginClientMessage(fs));

    assertEquals(ProtocolErrorMessage.ERROR_PARSING_NUMBER, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
  }

  @Test
  void constructor_whenSuccessNotBoolean_expectInvalidField() {
    SimpleFieldSet fs = minimalFieldSet();
    fs.putOverwrite("Success", "certainly");

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new FCPPluginClientMessage(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
  }

  @Test
  void constructFCPPluginMessage_whenSuccessFalse_populatesErrorInformation()
      throws MessageInvalidException {
    SimpleFieldSet params = createParamsSubset();
    FCPPluginClientMessage message =
        createMessage(
            fs -> {
              fs.put("Param", params);
              fs.putOverwrite("Success", "false");
              fs.putOverwrite("ErrorCode", "Problem");
              fs.putOverwrite("ErrorMessage", "Failure");
            });
    Bucket bucket = Mockito.mock(Bucket.class);
    message.bucket = bucket;

    FCPPluginMessage pluginMessage = message.constructFCPPluginMessage();

    assertSame(params, pluginMessage.params);
    assertSame(bucket, pluginMessage.data);
    assertFalse(pluginMessage.success);
    assertEquals("Problem", pluginMessage.errorCode);
    assertEquals("Failure", pluginMessage.errorMessage);
  }

  @Test
  void accessors_whenNoData_returnProtocolDefaults() throws MessageInvalidException {
    FCPPluginClientMessage message = createMessage(null);

    assertEquals(IDENTIFIER, message.getIdentifier());
    assertEquals(-1, message.dataLength());
    assertFalse(message.isGlobal());
    assertEquals(FCPPluginClientMessage.NAME, message.getName());
    assertNull(message.getFieldSet());
  }

  @Test
  void dataLength_whenDataPresent_matchesParsedLength() throws MessageInvalidException {
    FCPPluginClientMessage message =
        createMessage(
            fs -> {
              fs.setEndMarker("Data");
              fs.put("DataLength", 64L);
            });

    assertEquals(64L, message.dataLength());
  }

  @Test
  void run_whenPluginConnectionAvailable_sendsMessageOnce() throws Exception {
    SimpleFieldSet params = createParamsSubset();
    FCPPluginClientMessage message = createMessage(fs -> fs.put("Param", params));
    Bucket bucket = Mockito.mock(Bucket.class);
    message.bucket = bucket;

    try (FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class)) {
      FCPPluginConnection connection = Mockito.mock(FCPPluginConnection.class);
      FCPServer server = Mockito.mock(FCPServer.class);
      PluginConnectionRegistry registry = Mockito.mock(PluginConnectionRegistry.class);
      Mockito.when(handler.getServer()).thenReturn(server);
      Mockito.when(handler.pluginConnectionRegistry()).thenReturn(registry);
      Mockito.when(registry.get(PLUGIN_NAME, server, handler)).thenReturn(connection);
      Node node = Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

      message.run(handler, node);

      ArgumentCaptor<FCPPluginMessage> messageCaptor =
          ArgumentCaptor.forClass(FCPPluginMessage.class);
      Mockito.verify(connection).send(Mockito.eq(SendDirection.TO_SERVER), messageCaptor.capture());

      FCPPluginMessage captured = messageCaptor.getValue();
      assertEquals(IDENTIFIER, captured.identifier);
      assertSame(params, captured.params);
      assertSame(bucket, captured.data);
      assertFalse(captured.isReplyMessage());
    }
  }

  @Test
  void run_whenPluginConnectionSendFails_wrapsIOException() throws Exception {
    FCPPluginClientMessage message = createMessage(null);
    try (FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class)) {
      FCPPluginConnection connection = Mockito.mock(FCPPluginConnection.class);
      FCPServer server = Mockito.mock(FCPServer.class);
      PluginConnectionRegistry registry = Mockito.mock(PluginConnectionRegistry.class);
      Mockito.when(handler.getServer()).thenReturn(server);
      Mockito.when(handler.pluginConnectionRegistry()).thenReturn(registry);
      Mockito.when(registry.get(PLUGIN_NAME, server, handler)).thenReturn(connection);
      Mockito.doThrow(new IOException("boom"))
          .when(connection)
          .send(Mockito.eq(SendDirection.TO_SERVER), Mockito.any());
      Node node = Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

      MessageInvalidException ex =
          assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

      assertEquals(ProtocolErrorMessage.NO_SUCH_PLUGIN, ex.protocolCode);
      assertEquals(IDENTIFIER, ex.ident);
    }
  }

  @Test
  void run_whenHandlerThrowsPluginNotFound_throwsMessageInvalid() throws Exception {
    FCPPluginClientMessage message = createMessage(null);
    try (FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class)) {
      FCPServer server = Mockito.mock(FCPServer.class);
      PluginConnectionRegistry registry = Mockito.mock(PluginConnectionRegistry.class);
      Mockito.when(handler.getServer()).thenReturn(server);
      Mockito.when(handler.pluginConnectionRegistry()).thenReturn(registry);
      Mockito.when(registry.get(PLUGIN_NAME, server, handler))
          .thenThrow(new PluginNotFoundException());

      Node node = Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

      MessageInvalidException ex =
          assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

      assertEquals(ProtocolErrorMessage.NO_SUCH_PLUGIN, ex.protocolCode);
      assertEquals(IDENTIFIER, ex.ident);
    }
  }

  private FCPPluginClientMessage createMessage(Consumer<SimpleFieldSet> customizer)
      throws MessageInvalidException {
    SimpleFieldSet fs = minimalFieldSet();
    if (customizer != null) {
      customizer.accept(fs);
    }
    return new FCPPluginClientMessage(fs);
  }

  private static SimpleFieldSet minimalFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putOverwrite("Identifier", IDENTIFIER);
    fs.putOverwrite("PluginName", PLUGIN_NAME);
    return fs;
  }

  private static SimpleFieldSet createParamsSubset() {
    SimpleFieldSet params = new SimpleFieldSet(true);
    params.putOverwrite("Key", "value");
    return params;
  }
}
