package network.crypta.runtime.core;

import java.util.EnumSet;
import java.util.Map;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.StringCallback;
import network.crypta.config.StringOption;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyConfigPortTest {

  @Mock private Node node;

  @Mock private NodeClientCore core;

  @Mock private PersistentConfig config;

  @Test
  void export_whenSectionRequested_mapsSimpleFieldSetToSnapshot() {
    LegacyConfigPort port = new LegacyConfigPort(node, core);
    SimpleFieldSet current = new SimpleFieldSet(true);
    current.putSingle("enabled", "true");
    SimpleFieldSet nested = new SimpleFieldSet(true);
    nested.putSingle("name", "alpha");
    current.put("node", nested);
    when(node.getConfig()).thenReturn(config);
    when(config.exportFieldSet(network.crypta.config.Config.RequestType.CURRENT_SETTINGS, true))
        .thenReturn(current);

    ConfigSnapshot snapshot = port.export(EnumSet.of(ConfigSection.CURRENT));

    assertEquals(
        new ConfigSnapshot(
            Map.of(
                ConfigSection.CURRENT,
                new ConfigFieldSet(
                    Map.of("enabled", "true"),
                    Map.of("node", new ConfigFieldSet(Map.of("name", "alpha"), Map.of()))))),
        snapshot);
  }

  @Test
  void persist_whenCalled_delegatesToClientCoreStoreConfig() {
    LegacyConfigPort port = new LegacyConfigPort(node, core);

    port.persist();

    verify(core).storeConfig();
  }

  @Test
  void applyOverrides_whenChangedUnchangedInvalidAndUnknown_expectLegacySemanticsPreserved() {
    LegacyConfigPort port = new LegacyConfigPort(node, core);
    PersistentConfig persistentConfig = new PersistentConfig(null);
    SubConfig nodeConfig = persistentConfig.createSubConfig("node");
    CountingStringCallback maxPeersCallback = new CountingStringCallback("5");
    StringOption maxPeers =
        new StringOption(
            nodeConfig,
            "maxPeers",
            "5",
            new Option.Meta(0, false, false, null, null),
            maxPeersCallback);
    nodeConfig.register(maxPeers);

    SubConfig uiConfig = persistentConfig.createSubConfig("ui");
    CountingStringCallback themeCallback = new CountingStringCallback("light");
    StringOption theme =
        new StringOption(
            uiConfig,
            "theme",
            "light",
            new Option.Meta(0, false, false, null, null),
            themeCallback);
    uiConfig.register(theme);

    SubConfig netConfig = persistentConfig.createSubConfig("net");
    ThrowingStringCallback portCallback = new ThrowingStringCallback("8080");
    StringOption portOption =
        new StringOption(
            netConfig, "port", "8080", new Option.Meta(0, false, false, null, null), portCallback);
    netConfig.register(portOption);

    when(node.getConfig()).thenReturn(persistentConfig);

    port.applyOverrides(
        Map.of(
            "node.maxPeers", "10",
            "ui.theme", "light",
            "net.port", "9090",
            "missing.value", "ignored"));

    assertEquals(1, maxPeersCallback.getSetCount());
    assertEquals("10", maxPeers.getValueString());
    assertEquals("10", maxPeersCallback.getCurrentValue());
    assertEquals(0, themeCallback.getSetCount());
    assertEquals("light", theme.getValueString());
    assertEquals("8080", portOption.getValueString());
  }

  private static final class CountingStringCallback extends StringCallback {
    private int setCount;
    private String currentValue;

    CountingStringCallback(String initialValue) {
      this.currentValue = initialValue;
    }

    @Override
    public String get() {
      return currentValue;
    }

    @Override
    public void set(String val) {
      setCount++;
      currentValue = val;
    }

    int getSetCount() {
      return setCount;
    }

    String getCurrentValue() {
      return currentValue;
    }
  }

  private static final class ThrowingStringCallback extends StringCallback {
    private final String currentValue;

    ThrowingStringCallback(String currentValue) {
      this.currentValue = currentValue;
    }

    @Override
    public String get() {
      return currentValue;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      throw new InvalidConfigValueException("boom");
    }
  }
}
