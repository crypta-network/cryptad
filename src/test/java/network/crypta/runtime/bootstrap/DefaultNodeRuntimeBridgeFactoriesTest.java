package network.crypta.runtime.bootstrap;

import java.io.File;
import network.crypta.clients.fcp.bridge.FcpPersistentRequestServices;
import network.crypta.clients.fcp.bridge.FcpQueueAdminBackend;
import network.crypta.clients.fcp.bridge.FcpQueuePageBackend;
import network.crypta.clients.fcp.bridge.LegacyQueueCompletionPort;
import network.crypta.clients.fcp.bridge.LegacyQueueDownloadPort;
import network.crypta.clients.fcp.bridge.LegacyQueueInsertPort;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.bridge.CoreHttpShellRuntimeSupport;
import network.crypta.clients.http.bridge.geoip.HttpGeoIpCountryLookup;
import network.crypta.clients.http.bridge.security.CorePasswordFormPageRenderer;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputs;
import network.crypta.runtime.fcp.PersistentRequestEndpointServices;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.http.HttpShellContainerFactory;
import network.crypta.runtime.http.HttpShellRuntimeSupport;
import network.crypta.runtime.http.security.PasswordFormPageRenderer;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class DefaultNodeRuntimeBridgeFactoriesTest {

  @Test
  void coreBacked_whenCreated_exposesCurrentProductionFactories() throws Exception {
    Fixture fixture = new Fixture();

    NodeRuntimeBridgeFactories runtimeBridgeFactories =
        DefaultNodeRuntimeBridgeFactories.coreBacked();
    AdminRuntimeBridgeInputs bridgeInputs =
        runtimeBridgeFactories
            .adminRuntimeBridgeInputsFactory()
            .create(fixture.node(), fixture.core());
    PersistentRequestEndpointServices persistentRequestEndpointServices =
        runtimeBridgeFactories.persistentRequestEndpointServicesFactory().create();
    PersistentRequestEndpointServices anotherPersistentRequestEndpointServices =
        runtimeBridgeFactories.persistentRequestEndpointServicesFactory().create();
    HttpShellRuntimeSupport runtimeSupport =
        runtimeBridgeFactories.httpShellRuntimeSupportFactory().create(fixture.core());
    HttpShellContainerFactory httpShellContainerFactory =
        runtimeBridgeFactories.httpShellContainerFactory();
    PasswordFormPageRenderer passwordFormPageRenderer =
        runtimeBridgeFactories.passwordFormPageRenderer();

    try (MockedConstruction<SimpleToadletServer> construction =
        mockConstruction(SimpleToadletServer.class)) {
      HttpShellContainer container =
          httpShellContainerFactory.create(fixture.fproxyConfig(), fixture.executor());

      assertEquals(1, construction.constructed().size());
      assertInstanceOf(HttpShellContainer.class, container);
    }

    assertInstanceOf(FcpQueueAdminBackend.class, bridgeInputs.queueAdminBackend());
    assertInstanceOf(FcpQueuePageBackend.class, bridgeInputs.queuePageBackend());
    assertInstanceOf(LegacyQueueCompletionPort.class, bridgeInputs.queueCompletionPort());
    assertInstanceOf(LegacyQueueDownloadPort.class, bridgeInputs.queueDownloadPort());
    assertInstanceOf(LegacyQueueInsertPort.class, bridgeInputs.queueInsertPort());
    assertInstanceOf(HttpGeoIpCountryLookup.class, bridgeInputs.geoIpCountryLookup());
    assertSame(fixture.core(), readField(bridgeInputs.queueAdminBackend(), "core"));
    assertSame(fixture.core(), readField(bridgeInputs.queuePageBackend(), "core"));
    assertSame(fixture.core(), readField(bridgeInputs.queueCompletionPort(), "core"));
    assertSame(fixture.core(), readField(bridgeInputs.queueDownloadPort(), "core"));
    assertSame(fixture.core(), readField(bridgeInputs.queueInsertPort(), "core"));
    assertSame(fixture.geoIpDb(), readField(bridgeInputs.geoIpCountryLookup(), "dbFile"));
    assertInstanceOf(FcpPersistentRequestServices.class, persistentRequestEndpointServices);
    assertInstanceOf(FcpPersistentRequestServices.class, anotherPersistentRequestEndpointServices);
    assertNotSame(
        persistentRequestEndpointServices,
        anotherPersistentRequestEndpointServices,
        "core-backed FCP persistent-request services should be created on demand");
    CoreHttpShellRuntimeSupport coreRuntimeSupport =
        assertInstanceOf(CoreHttpShellRuntimeSupport.class, runtimeSupport);
    assertInstanceOf(network.crypta.clients.http.HttpShellRuntimeSupport.class, runtimeSupport);
    assertInstanceOf(CorePasswordFormPageRenderer.class, passwordFormPageRenderer);
    assertSame(fixture.core(), coreRuntimeSupport.core());
  }

  private static Object readField(Object target, String fieldName) {
    try {
      java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.get(target);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed reading field '" + fieldName + "'", e);
    }
  }

  private record Fixture(Node node, NodeClientCore core, File geoIpDb) {
    private Fixture() {
      this(mock(Node.class), mock(NodeClientCore.class), new File("run/IpToCountry.dat"));

      ProgramDirectory runDir = mock(ProgramDirectory.class);
      when(node.runDir()).thenReturn(runDir);
      when(runDir.file("IpToCountry.dat")).thenReturn(geoIpDb);
    }

    private SubConfig fproxyConfig() {
      return mock(SubConfig.class);
    }

    private PriorityAwareExecutor executor() {
      return mock(PriorityAwareExecutor.class);
    }
  }
}
