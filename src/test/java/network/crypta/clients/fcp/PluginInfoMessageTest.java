package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import network.crypta.node.Node;
import network.crypta.pluginmanager.FredPlugin;
import network.crypta.pluginmanager.PluginInfoWrapper;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PluginInfoMessageTest {

  @Mock private PluginInfoWrapper pluginInfoWrapper;

  @Test
  void getFieldSet_whenDetailedFalse_expectBasicFieldsOnly() {
    when(pluginInfoWrapper.getPluginClassName()).thenReturn("network.crypta.plugins.TestPlugin");
    when(pluginInfoWrapper.getFilename()).thenReturn("test-plugin.jar");
    when(pluginInfoWrapper.getStarted()).thenReturn(123L);
    when(pluginInfoWrapper.getPlugin()).thenReturn(mock(FredPlugin.class));
    when(pluginInfoWrapper.isFCPServerPlugin()).thenReturn(true);
    when(pluginInfoWrapper.getPluginLongVersion()).thenReturn(5L);
    when(pluginInfoWrapper.getPluginVersion()).thenReturn("5.0.0");

    PluginInfoMessage message = new PluginInfoMessage(pluginInfoWrapper, "id-123", false);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("id-123", fieldSet.get("Identifier"));
    assertEquals("network.crypta.plugins.TestPlugin", fieldSet.get("PluginName"));
    assertEquals("5", fieldSet.get("LongVersion"));
    assertEquals("5.0.0", fieldSet.get("Version"));
    assertTrue(Boolean.parseBoolean(fieldSet.get("IsTalkable")));
    assertNull(fieldSet.get("OriginUri"));
    assertNull(fieldSet.get("Started"));
  }

  @Test
  void getFieldSet_whenDetailedTrueAndNoIdentifier_expectDetailedFieldsWithoutIdentifier() {
    when(pluginInfoWrapper.getPluginClassName()).thenReturn("network.crypta.plugins.DetailPlugin");
    when(pluginInfoWrapper.getFilename()).thenReturn("detail-plugin.jar");
    when(pluginInfoWrapper.getStarted()).thenReturn(9876L);
    when(pluginInfoWrapper.getPlugin()).thenReturn(mock(FredPlugin.class));
    when(pluginInfoWrapper.isFCPServerPlugin()).thenReturn(false);
    when(pluginInfoWrapper.getPluginLongVersion()).thenReturn(9L);
    when(pluginInfoWrapper.getPluginVersion()).thenReturn("9.1");

    PluginInfoMessage message = new PluginInfoMessage(pluginInfoWrapper, null, true);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNull(fieldSet.get("Identifier"));
    assertEquals("network.crypta.plugins.DetailPlugin", fieldSet.get("PluginName"));
    assertEquals("detail-plugin.jar", fieldSet.get("OriginUri"));
    assertEquals("9876", fieldSet.get("Started"));
    assertEquals("9", fieldSet.get("LongVersion"));
    assertEquals("9.1", fieldSet.get("Version"));
    assertFalse(Boolean.parseBoolean(fieldSet.get("IsTalkable")));
  }

  @Test
  void getName_whenCalled_returnsPluginInfo() {
    when(pluginInfoWrapper.getPluginClassName()).thenReturn("network.crypta.plugins.NamePlugin");
    when(pluginInfoWrapper.getFilename()).thenReturn("name-plugin.jar");
    when(pluginInfoWrapper.getStarted()).thenReturn(1L);
    when(pluginInfoWrapper.getPlugin()).thenReturn(mock(FredPlugin.class));
    when(pluginInfoWrapper.isFCPServerPlugin()).thenReturn(false);
    when(pluginInfoWrapper.getPluginLongVersion()).thenReturn(1L);
    when(pluginInfoWrapper.getPluginVersion()).thenReturn("1.0");

    PluginInfoMessage message = new PluginInfoMessage(pluginInfoWrapper, "identifier", false);

    assertEquals("PluginInfo", message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    when(pluginInfoWrapper.getPluginClassName()).thenReturn("network.crypta.plugins.RunPlugin");
    when(pluginInfoWrapper.getFilename()).thenReturn("run-plugin.jar");
    when(pluginInfoWrapper.getStarted()).thenReturn(10L);
    when(pluginInfoWrapper.getPlugin()).thenReturn(mock(FredPlugin.class));
    when(pluginInfoWrapper.isFCPServerPlugin()).thenReturn(false);
    when(pluginInfoWrapper.getPluginLongVersion()).thenReturn(2L);
    when(pluginInfoWrapper.getPluginVersion()).thenReturn("2.0");

    PluginInfoMessage message = new PluginInfoMessage(pluginInfoWrapper, "run-id", false);

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class,
            () -> message.run(mock(FCPConnectionHandler.class), mock(Node.class)));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "PluginInfo goes from server to client not the other way around", exception.getMessage());
    assertFalse(exception.global);
    assertNull(exception.ident);
  }
}
