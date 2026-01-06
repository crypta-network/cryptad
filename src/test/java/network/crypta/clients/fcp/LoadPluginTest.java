package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.node.Node;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LoadPluginTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PluginManager pluginManager;
  @Mock private PriorityAwareExecutor executor;

  @BeforeEach
  void setUp() {
    lenient().when(handler.hasFullAccess()).thenReturn(true);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    lenient().when(node.services()).thenReturn(services);
    lenient().when(node.network()).thenReturn(network);
    lenient().when(services.pluginManager()).thenReturn(pluginManager);
    lenient().when(network.executor()).thenReturn(executor);
    lenient().when(pluginManager.isEnabled()).thenReturn(true);

    lenient()
        .doAnswer(
            invocation -> {
              Runnable job = invocation.getArgument(0);
              job.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class), anyString());
  }

  @Test
  void constructor_whenIdentifierMissing_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("PluginURL", "plugin.jar");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new LoadPlugin(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Must contain an Identifier field", exception.getMessage());
    assertNull(exception.ident);
    assertFalse(exception.global);
  }

  @Test
  void constructor_whenPluginUrlMissing_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new LoadPlugin(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Must contain a PluginURL field", exception.getMessage());
    assertEquals("abc", exception.ident);
    assertFalse(exception.global);
  }

  @Test
  void constructor_whenUrlTypeUnknown_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");
    fs.putSingle("PluginURL", "plugin.jar");
    fs.putSingle("URLType", "invalid");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new LoadPlugin(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals("Unknown URL type: 'invalid'", exception.getMessage());
    assertEquals("abc", exception.ident);
  }

  @Test
  void run_whenAccessDenied_throwsAccessDeniedError() throws Exception {
    when(handler.hasFullAccess()).thenReturn(false);

    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");
    fs.putSingle("PluginURL", "plugin.jar");
    LoadPlugin loadPlugin = new LoadPlugin(fs);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> loadPlugin.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("abc", exception.ident);
    verifyNoInteractions(pluginManager);
  }

  @Test
  void run_whenPluginsDisabled_sendsDisabledProtocolError() throws Exception {
    when(pluginManager.isEnabled()).thenReturn(false);

    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");
    fs.putSingle("PluginURL", "plugin.jar");
    LoadPlugin loadPlugin = new LoadPlugin(fs);

    loadPlugin.run(handler, node);

    ArgumentCaptor<ProtocolErrorMessage> message =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(message.capture());
    assertEquals(ProtocolErrorMessage.PLUGINS_DISABLED, message.getValue().getCode());
    assertEquals("Plugins disabled", message.getValue().extra);
    assertEquals("abc", message.getValue().ident);
    verifyNoInteractions(executor);
  }

  @Test
  void run_whenAutoDetectFails_sendsInvalidFieldError() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");
    fs.putSingle("PluginURL", "notAValidKey");
    LoadPlugin loadPlugin = new LoadPlugin(fs);

    loadPlugin.run(handler, node);

    ArgumentCaptor<ProtocolErrorMessage> message =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(message.capture());
    assertEquals(ProtocolErrorMessage.INVALID_FIELD, message.getValue().getCode());
    assertNotNull(message.getValue().extra);
    assertTrue(message.getValue().extra.contains("Was not able to guess"));
    verify(pluginManager, never()).startPluginOfficial(anyString(), anyBoolean());
    verify(pluginManager, never()).startPluginFile(anyString(), anyBoolean());
    verify(pluginManager, never()).startPluginFreenet(anyString(), anyBoolean());
    verify(pluginManager, never()).startPluginURL(anyString(), anyBoolean());
  }

  @Test
  void run_whenAutoDetectsOfficialPlugin_startsOfficialAndSendsInfo() throws Exception {
    String pluginName = "TestPlugin";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");
    fs.putSingle("PluginURL", pluginName);
    LoadPlugin loadPlugin = new LoadPlugin(fs);

    OfficialPluginDescription description = mock(OfficialPluginDescription.class);
    when(pluginManager.isOfficialPlugin(pluginName)).thenReturn(description);

    PluginInfoWrapper pluginInfo = mock(PluginInfoWrapper.class);
    when(pluginInfo.getPluginClassName()).thenReturn("com.example.Plugin");
    when(pluginInfo.getFilename()).thenReturn(pluginName);
    when(pluginInfo.getStarted()).thenReturn(42L);
    when(pluginInfo.isFCPServerPlugin()).thenReturn(true);
    when(pluginInfo.getPluginLongVersion()).thenReturn(3L);
    when(pluginInfo.getPluginVersion()).thenReturn("1.0");
    when(pluginManager.startPluginOfficial(pluginName, false)).thenReturn(pluginInfo);

    loadPlugin.run(handler, node);

    verify(pluginManager).startPluginOfficial(pluginName, false);
    ArgumentCaptor<PluginInfoMessage> sent = ArgumentCaptor.forClass(PluginInfoMessage.class);
    verify(handler).send(sent.capture());

    SimpleFieldSet fieldSet = sent.getValue().getFieldSet();
    assertEquals("abc", fieldSet.get("Identifier"));
    assertEquals("com.example.Plugin", fieldSet.get("PluginName"));
    assertTrue(fieldSet.getBoolean("IsTalkable", false));
    assertEquals("1.0", fieldSet.get("Version"));
  }

  @Test
  void run_whenAutoDetectsLocalFile_startsFromFile(@TempDir Path tempDir) throws Exception {
    Path pluginFile = Files.createFile(tempDir.resolve("local-plugin.jar"));
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");
    fs.putSingle("PluginURL", pluginFile.toString());
    LoadPlugin loadPlugin = new LoadPlugin(fs);

    PluginInfoWrapper pluginInfo = mock(PluginInfoWrapper.class);
    when(pluginInfo.getPluginClassName()).thenReturn("com.example.LocalPlugin");
    when(pluginInfo.getFilename()).thenReturn(pluginFile.toString());
    when(pluginInfo.getStarted()).thenReturn(21L);
    when(pluginInfo.isFCPServerPlugin()).thenReturn(true);
    when(pluginInfo.getPluginLongVersion()).thenReturn(7L);
    when(pluginInfo.getPluginVersion()).thenReturn("2.1");
    when(pluginManager.startPluginFile(pluginFile.toString(), false)).thenReturn(pluginInfo);

    loadPlugin.run(handler, node);

    verify(pluginManager).startPluginFile(pluginFile.toString(), false);
    ArgumentCaptor<PluginInfoMessage> sent = ArgumentCaptor.forClass(PluginInfoMessage.class);
    verify(handler).send(sent.capture());
    assertEquals("com.example.LocalPlugin", sent.getValue().getFieldSet().get("PluginName"));
  }

  @Test
  void run_whenExplicitUrlTypeIsUrl_sendsNoSuchPluginError() throws Exception {
    String pluginUrl = "http://example.com/plugin.jar";
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "abc");
    fs.putSingle("PluginURL", pluginUrl);
    fs.putSingle("URLType", "url");
    fs.putSingle("Store", "true");
    LoadPlugin loadPlugin = new LoadPlugin(fs);

    when(pluginManager.startPluginURL(pluginUrl, true)).thenReturn(null);

    loadPlugin.run(handler, node);

    verify(pluginManager).startPluginURL(pluginUrl, true);
    ArgumentCaptor<ProtocolErrorMessage> message =
        ArgumentCaptor.forClass(ProtocolErrorMessage.class);
    verify(handler).send(message.capture());
    assertEquals(ProtocolErrorMessage.NO_SUCH_PLUGIN, message.getValue().getCode());
    assertEquals("abc", message.getValue().ident);
  }
}
