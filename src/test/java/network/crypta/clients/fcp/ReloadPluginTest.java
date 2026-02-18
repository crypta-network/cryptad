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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "resource"})
@ExtendWith(MockitoExtension.class)
class ReloadPluginTest {

  private static final String IDENTIFIER = "reload-ident";
  private static final String PLUGIN_NAME = "TestPlugin";

  @Test
  void constructor_whenIdentifierMissing_throwsMissingFieldException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("PluginName", PLUGIN_NAME);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ReloadPlugin(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Must contain an Identifier field", exception.getMessage());
    assertNull(exception.ident);
  }

  @Test
  void constructor_whenPluginNameMissing_throwsMissingFieldException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ReloadPlugin(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Must contain a PluginName field", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
  }

  @Test
  void getName_whenCalled_returnsReloadPluginConstant() throws MessageInvalidException {
    ReloadPlugin reloadPlugin = new ReloadPlugin(minimalFieldSet());

    assertEquals(ReloadPlugin.NAME, reloadPlugin.getName());
  }

  @Test
  void getFieldSet_whenCalled_returnsNewEmptyFieldSet() throws MessageInvalidException {
    ReloadPlugin reloadPlugin = new ReloadPlugin(minimalFieldSet());

    SimpleFieldSet fieldSet = reloadPlugin.getFieldSet();

    assertNotNull(fieldSet);
    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void run_whenHandlerHasNoFullAccess_throwsAccessDenied() throws MessageInvalidException {
    ReloadPlugin reloadPlugin = new ReloadPlugin(minimalFieldSet());
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(false);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> reloadPlugin.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("LoadPlugin requires full access", exception.getMessage());
    assertEquals(IDENTIFIER, exception.ident);
    verifyNoMoreInteractions(node);
  }

  @Test
  void run_whenPluginNotFound_sendsNoSuchPluginError() throws MessageInvalidException {
    ReloadPlugin reloadPlugin = new ReloadPlugin(minimalFieldSet());
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    PriorityAwareExecutor executor = inlineExecutor();
    PluginManager pluginManager = mock(PluginManager.class);
    when(pluginManager.findPluginByIdentifier(PLUGIN_NAME)).thenReturn(null);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);

    reloadPlugin.run(handler, node);

    ArgumentCaptor<ProtocolErrorMessage> captor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(captor.capture());
    ProtocolErrorMessage errorMessage = captor.getValue();
    int code = Integer.parseInt(errorMessage.getFieldSet().get("Code"));
    assertEquals(ProtocolErrorMessage.NO_SUCH_PLUGIN, code);
    assertEquals(
        "Plugin '" + PLUGIN_NAME + "' does not exist or is not a FCP plugin", errorMessage.extra);
    assertEquals(IDENTIFIER, errorMessage.ident);
    verify(pluginManager).findPluginByIdentifier(PLUGIN_NAME);
    verify(pluginManager, never()).startPluginAuto(anyString(), anyBoolean());
  }

  @Test
  void run_whenStartPluginAutoReturnsNull_sendsErrorAfterStoppingAndPurging()
      throws MessageInvalidException {
    SimpleFieldSet fs = minimalFieldSet();
    fs.put("Purge", true);
    fs.put("MaxWaitTime", 42);
    ReloadPlugin reloadPlugin = new ReloadPlugin(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    PriorityAwareExecutor executor = inlineExecutor();
    PluginManager pluginManager = mock(PluginManager.class);
    PluginInfoWrapper existingPlugin = mock(PluginInfoWrapper.class);
    when(existingPlugin.getFilename()).thenReturn("plugin.jar");
    when(pluginManager.findPluginByIdentifier(PLUGIN_NAME)).thenReturn(existingPlugin);
    when(pluginManager.startPluginAuto("plugin.jar", false)).thenReturn(null);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);

    reloadPlugin.run(handler, node);

    verify(existingPlugin).stopPlugin(pluginManager, 42, true);
    verify(pluginManager).removeCachedCopy("plugin.jar");
    ArgumentCaptor<ProtocolErrorMessage> captor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(captor.capture());
    ProtocolErrorMessage errorMessage = captor.getValue();
    int code = Integer.parseInt(errorMessage.getFieldSet().get("Code"));
    assertEquals(ProtocolErrorMessage.NO_SUCH_PLUGIN, code);
    assertEquals(IDENTIFIER, errorMessage.ident);
  }

  @Test
  void run_whenPluginReloadSucceeds_sendsPluginInfoMessage() throws MessageInvalidException {
    SimpleFieldSet fs = minimalFieldSet();
    fs.put("Store", true);
    fs.put("MaxWaitTime", 7);
    ReloadPlugin reloadPlugin = new ReloadPlugin(fs);

    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    when(handler.hasFullAccess()).thenReturn(true);

    PriorityAwareExecutor executor = inlineExecutor();
    PluginManager pluginManager = mock(PluginManager.class);
    PluginInfoWrapper existingPlugin = mock(PluginInfoWrapper.class);
    when(existingPlugin.getFilename()).thenReturn("plugin.jar");
    when(pluginManager.findPluginByIdentifier(PLUGIN_NAME)).thenReturn(existingPlugin);

    PluginInfoWrapper reloadedPlugin = mock(PluginInfoWrapper.class);
    when(reloadedPlugin.getPluginClassName()).thenReturn("example.Plugin");
    when(reloadedPlugin.getFilename()).thenReturn("plugin.jar");
    when(reloadedPlugin.getStarted()).thenReturn(123L);
    when(reloadedPlugin.isFCPServerPlugin()).thenReturn(false);
    when(reloadedPlugin.getPluginLongVersion()).thenReturn(1L);
    when(reloadedPlugin.getPluginVersion()).thenReturn("1.0.0");
    when(pluginManager.startPluginAuto("plugin.jar", true)).thenReturn(reloadedPlugin);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);

    reloadPlugin.run(handler, node);

    verify(existingPlugin).stopPlugin(pluginManager, 7, true);
    verify(pluginManager, never()).removeCachedCopy(anyString());
    verify(pluginManager).startPluginAuto("plugin.jar", true);

    ArgumentCaptor<PluginInfoMessage> captor = ArgumentCaptor.forClass(PluginInfoMessage.class);
    verify(handler).send(captor.capture());
    PluginInfoMessage infoMessage = captor.getValue();
    SimpleFieldSet result = infoMessage.getFieldSet();
    assertEquals(IDENTIFIER, result.get("Identifier"));
    assertEquals("example.Plugin", result.get("PluginName"));
  }

  private static SimpleFieldSet minimalFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("PluginName", PLUGIN_NAME);
    return fs;
  }

  private static PriorityAwareExecutor inlineExecutor() {
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    doAnswer(
            invocation -> {
              Runnable job = invocation.getArgument(0);
              job.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());
    return executor;
  }
}
