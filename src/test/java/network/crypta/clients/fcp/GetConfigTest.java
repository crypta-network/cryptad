package network.crypta.clients.fcp;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class GetConfigTest {

  @Mock FCPConnectionHandler handler;

  @Mock Node node;

  @Mock FCPServer server;

  @Mock RuntimePorts runtimePorts;

  @Mock ConfigPort configPort;

  @Test
  void constructor_whenFieldsPresent_setsFlagsAndIdentifierAndRemovesIdentifierFromSource() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("WithCurrent", "true");
    fs.putSingle("WithDefaults", "false");
    fs.putSingle("WithSortOrder", "true");
    fs.putSingle("WithExpertFlag", "false");
    fs.putSingle("WithForceWriteFlag", "true");
    fs.putSingle("WithShortDescription", "false");
    fs.putSingle("WithLongDescription", "true");
    fs.putSingle("Identifier", "test-id");

    GetConfig getConfig = new GetConfig(fs);

    assertTrue(getConfig.withCurrent);
    assertFalse(getConfig.withDefaults);
    assertTrue(getConfig.withSortOrder);
    assertFalse(getConfig.withExpertFlag);
    assertTrue(getConfig.withForceWriteFlag);
    assertFalse(getConfig.withShortDescription);
    assertTrue(getConfig.withLongDescription);
    assertEquals("test-id", getConfig.requestIdentifier);
    assertNull(fs.get("Identifier"));
  }

  @Test
  void getFieldSet_whenCalled_returnsEmptyFieldSet() {
    GetConfig getConfig = new GetConfig(new SimpleFieldSet(true));

    SimpleFieldSet fieldSet = getConfig.getFieldSet();

    assertNotNull(fieldSet);
    assertTrue(fieldSet.isEmpty());
  }

  @Test
  void getName_whenCalled_returnsConstantName() {
    GetConfig getConfig = new GetConfig(new SimpleFieldSet(true));

    assertEquals("GetConfig", getConfig.getName());
  }

  @Test
  void run_whenHandlerLacksFullAccess_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "req-123");
    GetConfig getConfig = new GetConfig(fs);
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> getConfig.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, thrown.protocolCode);
    assertEquals("req-123", thrown.ident);
    assertEquals("GetConfig requires full access", thrown.getMessage());
    assertFalse(thrown.global);
    verify(handler, never()).send(any(FCPMessage.class));
    verifyNoInteractions(server, runtimePorts, configPort, node);
  }

  @Test
  @SuppressWarnings("unchecked")
  void run_whenHandlerHasFullAccess_exportsMatchingSectionsAndSendsConfigData() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("WithCurrent", "true");
    fs.putSingle("WithDefaults", "true");
    fs.putSingle("WithSortOrder", "false");
    fs.putSingle("WithExpertFlag", "true");
    fs.putSingle("WithForceWriteFlag", "false");
    fs.putSingle("WithShortDescription", "true");
    fs.putSingle("WithLongDescription", "false");
    fs.putSingle("WithDataTypes", "true");
    fs.putSingle("Identifier", "cfg-7");
    GetConfig getConfig = new GetConfig(fs);
    ConfigSnapshot snapshot =
        new ConfigSnapshot(
            Map.of(ConfigSection.CURRENT, new ConfigFieldSet(Map.of("enabled", "true"), Map.of())));
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.config()).thenReturn(configPort);
    when(configPort.export(any())).thenReturn(snapshot);

    getConfig.run(handler, node);

    ArgumentCaptor<Set<ConfigSection>> sectionsCaptor = ArgumentCaptor.forClass(Set.class);
    verify(configPort).export(sectionsCaptor.capture());
    assertEquals(
        EnumSet.of(
            ConfigSection.CURRENT,
            ConfigSection.DEFAULTS,
            ConfigSection.EXPERT_FLAG,
            ConfigSection.SHORT_DESCRIPTION,
            ConfigSection.DATA_TYPES),
        sectionsCaptor.getValue());

    ArgumentCaptor<ConfigData> captor = ArgumentCaptor.forClass(ConfigData.class);
    verify(handler).send(captor.capture());
    ConfigData sent = captor.getValue();

    assertEquals(snapshot, sent.snapshot);
    assertEquals("cfg-7", sent.requestIdentifier);
    verifyNoInteractions(node);
  }
}
