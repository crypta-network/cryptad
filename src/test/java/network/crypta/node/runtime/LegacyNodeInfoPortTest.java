package network.crypta.node.runtime;

import java.util.Map;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.Version;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyNodeInfoPortTest {

  @Mock private Node node;

  @Mock private NodeNetworkSubsystem network;

  @Test
  @SuppressWarnings("ResultOfMethodCallIgnored")
  void greeting_whenCalled_mapsExpectedDaemonValuesToSnapshot() {
    LegacyNodeInfoPort port = new LegacyNodeInfoPort(node);

    try (MockedStatic<Version> version = Mockito.mockStatic(Version.class);
        MockedStatic<Node> nodeClass = Mockito.mockStatic(Node.class);
        MockedStatic<NodeL10n> nodeL10n = Mockito.mockStatic(NodeL10n.class);
        MockedStatic<Compressor.COMPRESSOR_TYPE> compressor =
            Mockito.mockStatic(Compressor.COMPRESSOR_TYPE.class)) {

      version.when(Version::getVersionString).thenReturn("v-string");
      version.when(Version::currentBuildNumber).thenReturn(123);
      version.when(Version::gitRevision).thenReturn("rev-xyz");
      nodeClass.when(Node::isTestnetEnabled).thenReturn(true);
      compressor
          .when(Compressor.COMPRESSOR_TYPE::getHelloCompressorDescriptor)
          .thenReturn("descriptor");

      BaseL10n base = Mockito.mock(BaseL10n.class);
      Mockito.when(base.getSelectedLanguage()).thenReturn(BaseL10n.LANGUAGE.ENGLISH);
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);

      NodeGreetingSnapshot snapshot = port.greeting();

      assertEquals(
          new NodeGreetingSnapshot(
              Version.NODE_NAME,
              "v-string",
              123,
              "rev-xyz",
              true,
              "descriptor",
              BaseL10n.LANGUAGE.ENGLISH.toString()),
          snapshot);
      verifyNoInteractions(node);
    }
  }

  @ParameterizedTest
  @EnumSource(NodeReferenceView.class)
  void exportReference_whenViewRequested_selectsCorrectBaseExport(NodeReferenceView view) {
    LegacyNodeInfoPort port = new LegacyNodeInfoPort(node);
    when(node.network()).thenReturn(network);
    SimpleFieldSet base = new SimpleFieldSet(true);
    base.putSingle("identity", view.name());
    SimpleFieldSet physical = new SimpleFieldSet(true);
    physical.putSingle("host", "127.0.0.1");
    base.put("physical", physical);
    stubBaseExport(view, base);

    NodeReferenceSnapshot snapshot = port.exportReference(view, false);

    assertEquals(
        new NodeReferenceSnapshot(
            new NodeFieldSet(
                Map.of("identity", view.name()),
                Map.of("physical", new NodeFieldSet(Map.of("host", "127.0.0.1"), Map.of())))),
        snapshot);
    verifySelectedBaseExport(view);
    verify(network, never()).exportVolatileFieldSet();
  }

  @Test
  void exportReference_whenVolatileDataPresent_attachesVolatileSubset() {
    LegacyNodeInfoPort port = new LegacyNodeInfoPort(node);
    when(node.network()).thenReturn(network);
    SimpleFieldSet base = new SimpleFieldSet(true);
    base.putSingle("identity", "alpha");
    SimpleFieldSet volatileFieldSet = new SimpleFieldSet(true);
    volatileFieldSet.putSingle("uptimeSeconds", "42");
    when(network.exportDarknetPublicFieldSet()).thenReturn(base);
    when(network.exportVolatileFieldSet()).thenReturn(volatileFieldSet);

    NodeReferenceSnapshot snapshot = port.exportReference(NodeReferenceView.DARKNET_PUBLIC, true);

    assertEquals("alpha", snapshot.root().directValues().get("identity"));
    assertEquals(
        new NodeFieldSet(Map.of("uptimeSeconds", "42"), Map.of()),
        snapshot.root().directSubsets().get("volatile"));
  }

  @Test
  void exportReference_whenVolatileDataEmpty_omitsVolatileSubset() {
    LegacyNodeInfoPort port = new LegacyNodeInfoPort(node);
    when(node.network()).thenReturn(network);
    SimpleFieldSet base = new SimpleFieldSet(true);
    base.putSingle("identity", "alpha");
    when(network.exportOpennetPrivateFieldSet()).thenReturn(base);
    when(network.exportVolatileFieldSet()).thenReturn(new SimpleFieldSet(true));

    NodeReferenceSnapshot snapshot = port.exportReference(NodeReferenceView.OPENNET_PRIVATE, true);

    assertFalse(snapshot.root().directSubsets().containsKey("volatile"));
    assertNull(snapshot.root().directSubsets().get("volatile"));
  }

  private void stubBaseExport(NodeReferenceView view, SimpleFieldSet base) {
    switch (view) {
      case DARKNET_PUBLIC -> when(network.exportDarknetPublicFieldSet()).thenReturn(base);
      case DARKNET_PRIVATE -> when(network.exportDarknetPrivateFieldSet()).thenReturn(base);
      case OPENNET_PUBLIC -> when(network.exportOpennetPublicFieldSet()).thenReturn(base);
      case OPENNET_PRIVATE -> when(network.exportOpennetPrivateFieldSet()).thenReturn(base);
    }
  }

  private void verifySelectedBaseExport(NodeReferenceView view) {
    switch (view) {
      case DARKNET_PUBLIC -> verify(network).exportDarknetPublicFieldSet();
      case DARKNET_PRIVATE -> verify(network).exportDarknetPrivateFieldSet();
      case OPENNET_PUBLIC -> verify(network).exportOpennetPublicFieldSet();
      case OPENNET_PRIVATE -> verify(network).exportOpennetPrivateFieldSet();
    }
  }
}
