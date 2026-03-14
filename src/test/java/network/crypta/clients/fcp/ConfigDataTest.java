package network.crypta.clients.fcp;

import java.util.EnumMap;
import java.util.Map;
import network.crypta.node.Node;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ConfigDataTest {

  @Mock private FCPConnectionHandler connectionHandler;

  @Mock private Node node;

  @Test
  void getFieldSet_whenAllSectionsRequested_expectCorrespondingSubsets() {
    EnumMap<ConfigSection, ConfigFieldSet> sections = new EnumMap<>(ConfigSection.class);
    sections.put(
        ConfigSection.CURRENT,
        new ConfigFieldSet(
            Map.of("enabled", "true"),
            Map.of("node", new ConfigFieldSet(Map.of("name", "alpha"), Map.of()))));
    sections.put(ConfigSection.DEFAULTS, new ConfigFieldSet(Map.of("enabled", "false"), Map.of()));
    sections.put(ConfigSection.SORT_ORDER, new ConfigFieldSet(Map.of("enabled", "10"), Map.of()));
    sections.put(ConfigSection.EXPERT_FLAG, new ConfigFieldSet(Map.of("enabled", "yes"), Map.of()));
    sections.put(
        ConfigSection.FORCE_WRITE_FLAG, new ConfigFieldSet(Map.of("enabled", "confirm"), Map.of()));
    sections.put(
        ConfigSection.SHORT_DESCRIPTION, new ConfigFieldSet(Map.of("enabled", "short"), Map.of()));
    sections.put(
        ConfigSection.LONG_DESCRIPTION, new ConfigFieldSet(Map.of("enabled", "long"), Map.of()));
    sections.put(
        ConfigSection.DATA_TYPES, new ConfigFieldSet(Map.of("enabled", "boolean"), Map.of()));
    ConfigData configData = new ConfigData(new ConfigSnapshot(sections), "request-42");

    SimpleFieldSet result = configData.getFieldSet();

    Map<String, SimpleFieldSet> subsets = result.directSubsets();
    assertEquals(8, subsets.size());
    assertEquals("true", result.get("current.enabled"));
    assertEquals("alpha", result.get("current.node.name"));
    assertEquals("false", result.get("default.enabled"));
    assertEquals("10", result.get("sortOrder.enabled"));
    assertEquals("yes", result.get("expertFlag.enabled"));
    assertEquals("confirm", result.get("forceWriteFlag.enabled"));
    assertEquals("short", result.get("shortDescription.enabled"));
    assertEquals("long", result.get("longDescription.enabled"));
    assertEquals("boolean", result.get("dataType.enabled"));
    assertEquals("request-42", result.get("Identifier"));
  }

  @Test
  void getFieldSet_whenSnapshotEmpty_expectEmptyResult() {
    ConfigData configData = new ConfigData(ConfigSnapshot.empty(), null);

    SimpleFieldSet result = configData.getFieldSet();

    assertTrue(result.directSubsets().isEmpty());
    assertNull(result.get("Identifier"));
  }

  @Test
  void getFieldSet_whenSubsetIsEmpty_expectSubsetOmitted() {
    ConfigSnapshot snapshot =
        new ConfigSnapshot(
            Map.of(
                ConfigSection.SHORT_DESCRIPTION,
                new ConfigFieldSet(
                    Map.of("visible", "value"), Map.of("empty", ConfigFieldSet.empty()))));
    ConfigData configData = new ConfigData(snapshot, "id");

    SimpleFieldSet result = configData.getFieldSet();

    assertEquals("value", result.get("shortDescription.visible"));
    assertNull(result.subset("shortDescription.empty"));
    assertEquals("id", result.get("Identifier"));
  }

  @Test
  void getName_whenCalled_returnsStaticName() {
    ConfigData configData = new ConfigData(ConfigSnapshot.empty(), null);

    assertEquals("ConfigData", configData.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    ConfigData configData = new ConfigData(ConfigSnapshot.empty(), null);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> configData.run(connectionHandler, node));
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "ConfigData goes from server to client not the other way around", exception.getMessage());
    assertNull(exception.ident);
  }
}
