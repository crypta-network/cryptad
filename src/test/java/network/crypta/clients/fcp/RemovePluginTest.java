package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings({"java:S100", "java:S2095"})
@ExtendWith(MockitoExtension.class)
class RemovePluginTest {

  private static final String IDENTIFIER = "identifier-123";
  private static final String PLUGIN_NAME = "ExamplePlugin";

  @Test
  void constructor_whenIdentifierMissing_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("PluginName", PLUGIN_NAME);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new RemovePlugin(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Must contain an Identifier field", exception.getMessage());
    assertNull(exception.ident);
  }

  @Test
  void constructor_whenPluginNameMissing_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new RemovePlugin(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Must contain a PluginName field", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
  }

  @Test
  void getName_whenCalled_returnsRemovePluginConstant() throws MessageInvalidException {
    RemovePlugin removePlugin = new RemovePlugin(minimalFieldSet());

    assertEquals(RemovePlugin.NAME, removePlugin.getName());
  }

  @Test
  void getFieldSet_whenCalled_returnsEmptyFieldSet() throws MessageInvalidException {
    RemovePlugin removePlugin = new RemovePlugin(minimalFieldSet());

    SimpleFieldSet result = removePlugin.getFieldSet();

    assertNotNull(result);
    assertNull(result.get("Identifier"));
    assertNull(result.get("PluginName"));
  }

  @Test
  void run_whenHandlerHasNoFullAccess_throwsAccessDenied() throws MessageInvalidException {
    RemovePlugin removePlugin = new RemovePlugin(minimalFieldSet());
    @SuppressWarnings("resource")
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    org.mockito.Mockito.when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> removePlugin.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("LoadPlugin requires full access", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
    verifyNoInteractions(node);
  }

  @Test
  void run_whenPluginNotFound_sendsProtocolError() throws MessageInvalidException {
    RemovePlugin removePlugin = new RemovePlugin(minimalFieldSet());
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    PluginManager pluginManager = mock(PluginManager.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);

    org.mockito.Mockito.when(handler.hasFullAccess()).thenReturn(true);
    org.mockito.Mockito.when(node.network()).thenReturn(network);
    org.mockito.Mockito.when(network.executor()).thenReturn(executor);
    org.mockito.Mockito.when(node.services()).thenReturn(services);
    org.mockito.Mockito.when(services.pluginManager()).thenReturn(pluginManager);
    org.mockito.Mockito.when(pluginManager.findPluginByIdentifier(PLUGIN_NAME)).thenReturn(null);
    doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());

    removePlugin.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    ProtocolErrorMessage message = (ProtocolErrorMessage) captor.getValue();

    assertEquals(ProtocolErrorMessage.NO_SUCH_PLUGIN, message.getCode());
    assertEquals(
        "Plugin '" + PLUGIN_NAME + "' does not exist or is not a FCP plugin", message.extra);
    assertEquals(IDENTIFIER, message.ident);
    verify(pluginManager, never()).removeCachedCopy(anyString());
  }

  @Test
  void run_whenPluginFoundWithoutPurge_stopsPluginAndSendsRemoved() throws MessageInvalidException {
    SimpleFieldSet fs = minimalFieldSet();
    fs.put("MaxWaitTime", 15);
    RemovePlugin removePlugin = new RemovePlugin(fs);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    PluginManager pluginManager = mock(PluginManager.class);
    PluginInfoWrapper pluginInfoWrapper = mock(PluginInfoWrapper.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);

    org.mockito.Mockito.when(handler.hasFullAccess()).thenReturn(true);
    org.mockito.Mockito.when(node.network()).thenReturn(network);
    org.mockito.Mockito.when(network.executor()).thenReturn(executor);
    org.mockito.Mockito.when(node.services()).thenReturn(services);
    org.mockito.Mockito.when(services.pluginManager()).thenReturn(pluginManager);
    org.mockito.Mockito.when(pluginManager.findPluginByIdentifier(PLUGIN_NAME))
        .thenReturn(pluginInfoWrapper);
    doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), eq("Remove Plugin"));

    removePlugin.run(handler, node);

    verify(pluginInfoWrapper).stopPlugin(pluginManager, 15, false);
    verify(pluginManager, never()).removeCachedCopy(anyString());

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    PluginRemovedMessage message = (PluginRemovedMessage) captor.getValue();
    SimpleFieldSet fieldSet = message.getFieldSet();
    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertEquals(PLUGIN_NAME, fieldSet.get("PluginName"));
  }

  @Test
  void run_whenPurgeTrue_removesCachedCopyAfterStopping() throws MessageInvalidException {
    SimpleFieldSet fs = minimalFieldSet();
    fs.put("Purge", true);
    RemovePlugin removePlugin = new RemovePlugin(fs);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    PluginManager pluginManager = mock(PluginManager.class);
    PluginInfoWrapper pluginInfoWrapper = mock(PluginInfoWrapper.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);

    org.mockito.Mockito.when(handler.hasFullAccess()).thenReturn(true);
    org.mockito.Mockito.when(node.network()).thenReturn(network);
    org.mockito.Mockito.when(network.executor()).thenReturn(executor);
    org.mockito.Mockito.when(node.services()).thenReturn(services);
    org.mockito.Mockito.when(services.pluginManager()).thenReturn(pluginManager);
    org.mockito.Mockito.when(pluginManager.findPluginByIdentifier(PLUGIN_NAME))
        .thenReturn(pluginInfoWrapper);
    org.mockito.Mockito.when(pluginInfoWrapper.getFilename()).thenReturn("plugin-file.jar");
    doAnswer(
            invocation -> {
              Runnable runnable = invocation.getArgument(0);
              runnable.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());

    removePlugin.run(handler, node);

    verify(pluginInfoWrapper).stopPlugin(pluginManager, 0, false);
    verify(pluginManager).removeCachedCopy("plugin-file.jar");
    verify(handler).send(any(PluginRemovedMessage.class));
  }

  private SimpleFieldSet minimalFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("PluginName", PLUGIN_NAME);
    return fs;
  }
}
