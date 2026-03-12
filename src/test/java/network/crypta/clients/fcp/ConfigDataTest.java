package network.crypta.clients.fcp;

import java.util.EnumSet;
import java.util.Map;
import network.crypta.config.Config.RequestType;
import network.crypta.config.PersistentConfig;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ConfigDataTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PersistentConfig config;
  @Mock private FCPConnectionHandler connectionHandler;

  @Test
  void getFieldSet_whenAllSectionsRequested_expectCorrespondingSubsets() {
    when(node.getConfig()).thenReturn(config);
    SimpleFieldSet current = nonEmptyFieldSet("Current", "true");
    SimpleFieldSet defaults = nonEmptyFieldSet("Default", "42");
    SimpleFieldSet sort = nonEmptyFieldSet("Sort", "10");
    SimpleFieldSet expert = nonEmptyFieldSet("Expert", "yes");
    SimpleFieldSet forceWrite = nonEmptyFieldSet("Force", "confirm");
    SimpleFieldSet shortDesc = nonEmptyFieldSet("Short", "sh");
    SimpleFieldSet longDesc = nonEmptyFieldSet("Long", "loooooong");
    SimpleFieldSet dataTypes = nonEmptyFieldSet("Type", "string");

    when(config.exportFieldSet(RequestType.CURRENT_SETTINGS, true)).thenReturn(current);
    when(config.exportFieldSet(RequestType.DEFAULT_SETTINGS, false)).thenReturn(defaults);
    when(config.exportFieldSet(RequestType.SORT_ORDER, false)).thenReturn(sort);
    when(config.exportFieldSet(RequestType.EXPERT_FLAG, false)).thenReturn(expert);
    when(config.exportFieldSet(RequestType.FORCE_WRITE_FLAG, false)).thenReturn(forceWrite);
    when(config.exportFieldSet(RequestType.SHORT_DESCRIPTION, false)).thenReturn(shortDesc);
    when(config.exportFieldSet(RequestType.LONG_DESCRIPTION, false)).thenReturn(longDesc);
    when(config.exportFieldSet(RequestType.DATA_TYPE, false)).thenReturn(dataTypes);

    ConfigData configData =
        new ConfigData(node, EnumSet.allOf(ConfigData.Section.class), "request-42");

    SimpleFieldSet result = configData.getFieldSet();

    Map<String, SimpleFieldSet> subsets = result.directSubsets();
    assertEquals(8, subsets.size());
    assertSame(current, subsets.get("current"));
    assertSame(defaults, subsets.get("default"));
    assertSame(sort, subsets.get("sortOrder"));
    assertSame(expert, subsets.get("expertFlag"));
    assertSame(forceWrite, subsets.get("forceWriteFlag"));
    assertSame(shortDesc, subsets.get("shortDescription"));
    assertSame(longDesc, subsets.get("longDescription"));
    assertSame(dataTypes, subsets.get("dataType"));
    assertEquals("request-42", result.get("Identifier"));
  }

  @Test
  void getFieldSet_whenNoFlagsEnabled_expectEmptyResultAndNoConfigAccess() {
    ConfigData configData = new ConfigData(node, EnumSet.noneOf(ConfigData.Section.class), null);

    SimpleFieldSet result = configData.getFieldSet();

    assertTrue(result.directSubsets().isEmpty());
    assertNull(result.get("Identifier"));
    verify(node, never()).getConfig();
    verifyNoInteractions(config);
  }

  @Test
  void getFieldSet_whenExportReturnsEmptySubset_expectSubsetOmitted() {
    when(node.getConfig()).thenReturn(config);
    when(config.exportFieldSet(RequestType.SHORT_DESCRIPTION, false))
        .thenReturn(new SimpleFieldSet(true));

    ConfigData configData =
        new ConfigData(node, EnumSet.of(ConfigData.Section.SHORT_DESCRIPTION), "id");

    SimpleFieldSet result = configData.getFieldSet();

    assertTrue(result.directSubsets().isEmpty());
    assertEquals("id", result.get("Identifier"));
    verify(config).exportFieldSet(RequestType.SHORT_DESCRIPTION, false);
  }

  @Test
  void getName_whenCalled_returnsStaticName() {
    ConfigData configData = new ConfigData(node, EnumSet.noneOf(ConfigData.Section.class), null);

    assertEquals("ConfigData", configData.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    ConfigData configData = new ConfigData(node, EnumSet.noneOf(ConfigData.Section.class), null);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> configData.run(connectionHandler, node));
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "ConfigData goes from server to client not the other way around", exception.getMessage());
    assertNull(exception.ident);
  }

  private static SimpleFieldSet nonEmptyFieldSet(String key, String value) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(key, value);
    return fs;
  }
}
