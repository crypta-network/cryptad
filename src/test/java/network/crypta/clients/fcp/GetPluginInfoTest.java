package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GetPluginInfoTest {

  private static final String IDENTIFIER = "id-123";
  private static final String PLUGIN_NAME = "plugin.Class";

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PluginManager pluginManager;
  @Mock private PluginInfoWrapper pluginInfoWrapper;

  @Test
  void constructor_whenIdentifierMissing_throwsMessageInvalidException() {
    SimpleFieldSet fs = createFieldSet(null, PLUGIN_NAME, null);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new GetPluginInfo(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertNull(ex.ident);
    assertEquals("GetPluginInfo must contain an Identifier field", ex.getMessage());
  }

  @Test
  void constructor_whenPluginNameMissing_throwsMessageInvalidException() {
    SimpleFieldSet fs = createFieldSet(IDENTIFIER, null, null);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new GetPluginInfo(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    assertEquals("GetPluginInfo must contain a PluginName field", ex.getMessage());
  }

  @Test
  void run_whenDetailedAndNoFullAccess_throwsAccessDenied() throws Exception {
    SimpleFieldSet fs = createFieldSet(IDENTIFIER, PLUGIN_NAME, Boolean.TRUE);
    GetPluginInfo message = new GetPluginInfo(fs);
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler).hasFullAccess();
    verifyNoInteractions(node);
  }

  @Test
  void run_whenPluginNotFound_sendsProtocolErrorMessage() throws Exception {
    SimpleFieldSet fs = createFieldSet(IDENTIFIER, PLUGIN_NAME, Boolean.FALSE);
    GetPluginInfo message = new GetPluginInfo(fs);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);
    when(pluginManager.findPluginByIdentifier(PLUGIN_NAME)).thenReturn(null);

    message.run(handler, node);

    ArgumentCaptor<ProtocolErrorMessage> captor =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(captor.capture());
    ProtocolErrorMessage sent = captor.getValue();

    assertEquals(ProtocolErrorMessage.NO_SUCH_PLUGIN, sent.getCode());
    assertFalse(sent.fatal);
    assertFalse(sent.global);
    assertEquals(IDENTIFIER, sent.ident);
    assertEquals("Plugin '" + PLUGIN_NAME + "' does not exist or is not a FCP plugin", sent.extra);
    verify(pluginManager).findPluginByIdentifier(PLUGIN_NAME);
    verify(handler, never()).hasFullAccess();
  }

  @Test
  void run_whenPluginFoundWithoutDetails_sendsPluginInfoWithBasicFields() throws Exception {
    SimpleFieldSet fs = createFieldSet(IDENTIFIER, PLUGIN_NAME, Boolean.FALSE);
    GetPluginInfo message = new GetPluginInfo(fs);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);
    mockPluginInfo(true, 42L, "1.0.0", "plugin.jar", 123L, false);
    when(pluginManager.findPluginByIdentifier(PLUGIN_NAME)).thenReturn(pluginInfoWrapper);

    message.run(handler, node);

    ArgumentCaptor<PluginInfoMessage> captor = ArgumentCaptor.forClass(PluginInfoMessage.class);
    verify(handler).send(captor.capture());
    PluginInfoMessage sent = captor.getValue();
    SimpleFieldSet fieldSet = sent.getFieldSet();

    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertEquals(PLUGIN_NAME, fieldSet.get("PluginName"));
    assertEquals("true", fieldSet.get("IsTalkable"));
    assertEquals("42", fieldSet.get("LongVersion"));
    assertEquals("1.0.0", fieldSet.get("Version"));
    assertNull(fieldSet.get("OriginUri"));
    assertNull(fieldSet.get("Started"));
    verify(handler, never()).hasFullAccess();
  }

  @Test
  void run_whenPluginFoundWithDetails_sendsPluginInfoWithDetailedFields() throws Exception {
    SimpleFieldSet fs = createFieldSet(IDENTIFIER, PLUGIN_NAME, Boolean.TRUE);
    GetPluginInfo message = new GetPluginInfo(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);
    mockPluginInfo(true, 99L, "2.3.4", "origin.jar", 9876L, true);
    when(pluginManager.findPluginByIdentifier(PLUGIN_NAME)).thenReturn(pluginInfoWrapper);

    message.run(handler, node);

    ArgumentCaptor<PluginInfoMessage> captor = ArgumentCaptor.forClass(PluginInfoMessage.class);
    verify(handler).send(captor.capture());
    PluginInfoMessage sent = captor.getValue();
    SimpleFieldSet fieldSet = sent.getFieldSet();

    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertEquals("origin.jar", fieldSet.get("OriginUri"));
    assertEquals("9876", fieldSet.get("Started"));
    assertEquals("true", fieldSet.get("IsTalkable"));
    assertEquals("99", fieldSet.get("LongVersion"));
    assertEquals("2.3.4", fieldSet.get("Version"));
    verify(handler).hasFullAccess();
  }

  private SimpleFieldSet createFieldSet(String identifier, String pluginName, Boolean detailed) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    if (identifier != null) {
      fs.putSingle("Identifier", identifier);
    }
    if (pluginName != null) {
      fs.putSingle("PluginName", pluginName);
    }
    if (detailed != null) {
      fs.put("Detailed", detailed);
    }
    return fs;
  }

  private void mockPluginInfo(
      boolean isFcpServerPlugin,
      long longVersion,
      String version,
      String filename,
      long started,
      boolean includeDetails) {
    when(pluginInfoWrapper.getPluginClassName()).thenReturn(PLUGIN_NAME);
    when(pluginInfoWrapper.isFCPServerPlugin()).thenReturn(isFcpServerPlugin);
    when(pluginInfoWrapper.getPluginLongVersion()).thenReturn(longVersion);
    when(pluginInfoWrapper.getPluginVersion()).thenReturn(version);
    if (includeDetails) {
      when(pluginInfoWrapper.getFilename()).thenReturn(filename);
      when(pluginInfoWrapper.getStarted()).thenReturn(started);
    }
  }
}
