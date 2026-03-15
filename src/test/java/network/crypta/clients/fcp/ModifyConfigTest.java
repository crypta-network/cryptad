package network.crypta.clients.fcp;

import java.util.EnumSet;
import java.util.Map;
import network.crypta.node.Node;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ModifyConfigTest {

  @Mock FCPConnectionHandler handler;

  @Mock Node node;

  @Mock FCPServer server;

  @Mock RuntimePorts runtimePorts;

  @Mock ConfigPort configPort;

  @Test
  void constructor_whenIdentifierPresent_storesItAndRemovesFromFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "id-42");

    ModifyConfig modifyConfig = new ModifyConfig(fs);

    assertEquals("id-42", modifyConfig.requestIdentifier);
    assertNull(fs.get("Identifier"));
  }

  @Test
  void getFieldSet_whenCalled_returnsEmptySimpleFieldSet() {
    ModifyConfig modifyConfig = new ModifyConfig(new SimpleFieldSet(true));

    SimpleFieldSet result = modifyConfig.getFieldSet();

    assertNotNull(result);
    assertTrue(result.isEmpty());
  }

  @Test
  void getName_whenCalled_returnsConstantName() {
    ModifyConfig modifyConfig = new ModifyConfig(new SimpleFieldSet(true));

    assertEquals("ModifyConfig", modifyConfig.getName());
  }

  @Test
  void run_whenHandlerLacksFullAccess_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "blocked-id");
    ModifyConfig modifyConfig = new ModifyConfig(fs);
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> modifyConfig.run(handler));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, thrown.protocolCode);
    assertEquals("blocked-id", thrown.ident);
    assertEquals("ModifyConfig requires full access", thrown.getMessage());
    assertFalse(thrown.global);
    verify(handler, never()).send(any(FCPMessage.class));
    verifyNoInteractions(server, runtimePorts, configPort, node);
  }

  @Test
  @SuppressWarnings("unchecked")
  void run_whenHandlerHasFullAccess_appliesOverridesPersistsExportsCurrentAndSendsReply()
      throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "cfg-1");
    fs.putSingle("node.maxPeers", "10");
    fs.putSingle("ui.theme", "light");
    ModifyConfig modifyConfig = new ModifyConfig(fs);
    ConfigSnapshot snapshot =
        new ConfigSnapshot(
            Map.of(ConfigSection.CURRENT, new ConfigFieldSet(Map.of("enabled", "true"), Map.of())));
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.config()).thenReturn(configPort);
    when(configPort.export(EnumSet.of(ConfigSection.CURRENT))).thenReturn(snapshot);

    modifyConfig.run(handler);

    InOrder order = inOrder(configPort, handler);
    ArgumentCaptor<Map<String, String>> overridesCaptor = ArgumentCaptor.forClass(Map.class);
    order.verify(configPort).applyOverrides(overridesCaptor.capture());
    assertEquals(Map.of("node.maxPeers", "10", "ui.theme", "light"), overridesCaptor.getValue());
    order.verify(configPort).persist();
    order.verify(configPort).export(EnumSet.of(ConfigSection.CURRENT));
    ArgumentCaptor<ConfigData> responseCaptor = ArgumentCaptor.forClass(ConfigData.class);
    order.verify(handler).send(responseCaptor.capture());

    ConfigData sent = responseCaptor.getValue();
    assertEquals(snapshot, sent.snapshot);
    assertEquals("cfg-1", sent.requestIdentifier);
    verifyNoInteractions(node);
  }
}
