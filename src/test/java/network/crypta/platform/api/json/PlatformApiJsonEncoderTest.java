package network.crypta.platform.api.json;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class PlatformApiJsonEncoderTest {

  @Test
  void encodeNodeReference_whenNestedFieldSetPresent_expectMergedObjectPreservingEncounterOrder() {
    LinkedHashMap<String, String> directValues = LinkedHashMap.newLinkedHashMap(2);
    directValues.put("identity", "alpha");
    directValues.put("version", "42");

    LinkedHashMap<String, NodeFieldSet> nestedSubsets = LinkedHashMap.newLinkedHashMap(1);
    nestedSubsets.put(
        "child",
        new NodeFieldSet(
            Map.of("name", "value"),
            Map.of("volatile", new NodeFieldSet(Map.of("enabled", "true"), Map.of()))));

    LinkedHashMap<String, NodeFieldSet> directSubsets = LinkedHashMap.newLinkedHashMap(1);
    directSubsets.put("physical", new NodeFieldSet(Map.of("host", "127.0.0.1"), nestedSubsets));

    NodeReferenceSnapshot snapshot =
        new NodeReferenceSnapshot(new NodeFieldSet(directValues, directSubsets));

    assertEquals(
        "{\"identity\":\"alpha\",\"version\":\"42\",\"physical\":{\"host\":\"127.0.0.1\",\"child\":{\"name\":\"value\",\"volatile\":{\"enabled\":\"true\"}}}}",
        PlatformApiJsonEncoder.encodeNodeReference(snapshot));
  }

  @Test
  void encodeConfig_whenSectionsPresent_expectSectionKeysAndNestedObjects() {
    EnumMap<ConfigSection, ConfigFieldSet> sections = new EnumMap<>(ConfigSection.class);
    sections.put(
        ConfigSection.CURRENT,
        new ConfigFieldSet(
            Map.of("enabled", "true"),
            Map.of("node", new ConfigFieldSet(Map.of("name", "alpha"), Map.of()))));
    sections.put(
        ConfigSection.DATA_TYPES, new ConfigFieldSet(Map.of("enabled", "boolean"), Map.of()));

    ConfigSnapshot snapshot = new ConfigSnapshot(sections);

    assertEquals(
        "{\"CURRENT\":{\"enabled\":\"true\",\"node\":{\"name\":\"alpha\"}},\"DATA_TYPES\":{\"enabled\":\"boolean\"}}",
        PlatformApiJsonEncoder.encodeConfig(snapshot));
  }

  @Test
  void encodeError_whenCalled_expectStandardErrorShape() {
    assertEquals(
        "{\"error\":{\"code\":\"unknown_peer\",\"message\":\"Peer not found.\"}}",
        PlatformApiJsonEncoder.encodeError("unknown_peer", "Peer not found."));
  }

  @Test
  void write_whenStringContainsEscapes_expectEscapedJson() {
    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(2);
    object.put("quoted", "\"slash\\line\n\t");
    object.put("control", "\u0001");

    assertEquals(
        "{\"quoted\":\"\\\"slash\\\\line\\n\\t\",\"control\":\"\\u0001\"}",
        PlatformApiJsonWriter.write(object));
  }

  @Test
  void write_whenSupportedValueTypesPresent_expectSerializeScalarsEnumsAndArrays() {
    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(6);
    object.put("flag", true);
    object.put("count", 3L);
    object.put("ratio", 1.5d);
    object.put("view", NodeReferenceView.OPENNET_PRIVATE);
    object.put("items", java.util.Arrays.asList("alpha", 2, null));
    object.put("missing", null);

    assertEquals(
        "{\"flag\":true,\"count\":3,\"ratio\":1.5,\"view\":\"OPENNET_PRIVATE\",\"items\":[\"alpha\",2,null],\"missing\":null}",
        PlatformApiJsonWriter.write(object));
  }

  @Test
  void write_whenFloatingPointNotFinite_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> PlatformApiJsonWriter.write(Double.NaN));
  }

  @Test
  void write_whenObjectKeyNotString_expectIllegalArgumentException() {
    Map<Integer, String> invalidObject = Map.of(1, "value");

    assertThrows(IllegalArgumentException.class, () -> PlatformApiJsonWriter.write(invalidObject));
  }
}
