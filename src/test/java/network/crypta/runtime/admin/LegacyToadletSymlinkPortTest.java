package network.crypta.runtime.admin;

import java.util.List;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.StringArrCallback;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.ToadletSymlinkEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyToadletSymlinkPortTest {
  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private PersistentConfig config;
  @Mock private SubConfig subConfig;

  @BeforeEach
  void setUp() {
    when(node.getConfig()).thenReturn(config);
    when(config.createSubConfig("toadletsymlinker")).thenReturn(subConfig);
  }

  @Test
  void loadConfiguredSymlinks_whenEntriesConfigured_expectParsesValidEntriesOnly() {
    when(subConfig.getStringArr("symlinks"))
        .thenReturn(
            new String[] {
              "/one/#/target/", "missing", "/two/#", "/three#bad#target", "/ok/#/again/"
            });

    LegacyToadletSymlinkPort port = new LegacyToadletSymlinkPort(node, core);

    List<ToadletSymlinkEntry> entries = port.loadConfiguredSymlinks();

    assertEquals(
        List.of(
            new ToadletSymlinkEntry("/one/", "/target/"),
            new ToadletSymlinkEntry("/ok/", "/again/")),
        entries);
    verify(subConfig).finishedInitialization();
  }

  @Test
  void persistConfiguredSymlinks_whenUpdated_expectSerializesEntriesAndStoresConfig() {
    when(subConfig.getStringArr("symlinks")).thenReturn(new String[0]);
    LegacyToadletSymlinkPort port = new LegacyToadletSymlinkPort(node, core);
    ArgumentCaptor<StringArrCallback> callbackCaptor =
        ArgumentCaptor.forClass(StringArrCallback.class);

    port.loadConfiguredSymlinks();
    verify(subConfig)
        .register(eq("symlinks"), isNull(), any(Option.Meta.class), callbackCaptor.capture());

    port.persistConfiguredSymlinks(
        List.of(
            new ToadletSymlinkEntry("/first/", "/target-a/"),
            new ToadletSymlinkEntry("/second/", "/target-b/")));

    assertArrayEquals(
        new String[] {"/first/#/target-a/", "/second/#/target-b/"},
        callbackCaptor.getValue().get());
    verify(core).storeConfig();
  }
}
