package network.crypta.runtime.bootstrap;

import java.io.File;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputs;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputsFactory;
import network.crypta.runtime.endpoints.fcp.FcpQueueAdminBackend;
import network.crypta.runtime.endpoints.http.CoreHttpShellRuntimeSupport;
import network.crypta.runtime.endpoints.http.HttpShellRuntimeSupportFactory;
import network.crypta.runtime.endpoints.http.geoip.HttpGeoIpCountryLookup;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class NodeRuntimeBridgeFactoriesTest {

  @Test
  void constructor_whenAdminRuntimeBridgeInputsFactoryIsNull_throws() {
    HttpShellRuntimeSupportFactory httpShellRuntimeSupportFactory =
        ignoredCore -> mock(HttpShellRuntimeSupport.class);

    assertThrows(
        NullPointerException.class,
        () -> new NodeRuntimeBridgeFactories(null, httpShellRuntimeSupportFactory));
  }

  @Test
  void constructor_whenHttpShellRuntimeSupportFactoryIsNull_throws() {
    NodeRuntimeBridgeFactoriesFixture fixture = new NodeRuntimeBridgeFactoriesFixture();
    AdminRuntimeBridgeInputsFactory adminRuntimeBridgeInputsFactory =
        fixture.adminRuntimeBridgeInputsFactory();

    assertThrows(
        NullPointerException.class,
        () -> new NodeRuntimeBridgeFactories(adminRuntimeBridgeInputsFactory, null));
  }

  @Test
  void coreBacked_whenCreated_exposesCurrentEndpointBackedFactories() {
    NodeRuntimeBridgeFactoriesFixture fixture = new NodeRuntimeBridgeFactoriesFixture();

    NodeRuntimeBridgeFactories runtimeBridgeFactories = NodeRuntimeBridgeFactories.coreBacked();
    AdminRuntimeBridgeInputs bridgeInputs =
        runtimeBridgeFactories
            .adminRuntimeBridgeInputsFactory()
            .create(fixture.node(), fixture.core());
    HttpShellRuntimeSupport runtimeSupport =
        runtimeBridgeFactories.httpShellRuntimeSupportFactory().create(fixture.core());

    assertNotNull(runtimeBridgeFactories.adminRuntimeBridgeInputsFactory());
    assertNotNull(runtimeBridgeFactories.httpShellRuntimeSupportFactory());
    assertInstanceOf(FcpQueueAdminBackend.class, bridgeInputs.queueAdminBackend());
    assertInstanceOf(HttpGeoIpCountryLookup.class, bridgeInputs.geoIpCountryLookup());
    CoreHttpShellRuntimeSupport coreRuntimeSupport =
        assertInstanceOf(CoreHttpShellRuntimeSupport.class, runtimeSupport);
    assertSame(fixture.core(), coreRuntimeSupport.core());
  }

  private record NodeRuntimeBridgeFactoriesFixture(Node node, NodeClientCore core, File geoIpDb) {
    private NodeRuntimeBridgeFactoriesFixture() {
      this(mock(Node.class), mock(NodeClientCore.class), new File("run/IpToCountry.dat"));

      ProgramDirectory runDir = mock(ProgramDirectory.class);
      when(node.runDir()).thenReturn(runDir);
      when(runDir.file("IpToCountry.dat")).thenReturn(geoIpDb);
    }

    private AdminRuntimeBridgeInputsFactory adminRuntimeBridgeInputsFactory() {
      return (ignoredNode, ignoredCore) -> mock(AdminRuntimeBridgeInputs.class);
    }
  }
}
