package network.crypta.runtime.endpoints.fcp;

import network.crypta.client.async.persistence.PersistentRequestCatalog;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestIdentifier;
import network.crypta.client.async.persistence.PersistentRequestRecoveryCodec;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.FcpServerDependencies;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.config.PersistentConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class FcpPersistentRequestServicesTest {

  @Test
  void accessors_whenFreshInstance_exposeSharedEmptyPersistentState() {
    // Arrange
    FcpPersistentRequestServices services = new FcpPersistentRequestServices();
    PersistentRequestCoordinator coordinator = services.coordinator();
    PersistentRequestCatalog catalog = services.catalog();
    PersistentRequestRecoveryCodec recoveryCodec = services.recoveryCodec();
    PersistentRequestIdentifier lookupIdentifier =
        new PersistentRequestIdentifier(
            false, "client-a", "request-1", PersistentRequestIdentifier.RequestType.PUT);

    // Assert
    assertSame(coordinator, services.coordinator());
    assertSame(catalog, services.catalog());
    assertSame(recoveryCodec, services.recoveryCodec());
    assertInstanceOf(FcpPersistentRequestRecoveryCodec.class, recoveryCodec);
    assertNotNull(coordinator.getOrCreateClientHandle(false, "client-a"));
    assertArrayEquals(new PersistentRequestHandle[0], services.getPersistentRequests());
    assertArrayEquals(new PersistentRequestHandle[0], catalog.getPersistentRequests());
    assertFalse(catalog.hasRequest(lookupIdentifier));
  }

  @Test
  void createEndpointHandle_whenCalled_wrapsCreatedServer() {
    // Arrange
    FcpPersistentRequestServices services = new FcpPersistentRequestServices();
    Node node = mock(Node.class);
    PersistentConfig config = mock(PersistentConfig.class);
    NodeClientCore core = mock(NodeClientCore.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    FcpServerDependencies dependencies = mock(FcpServerDependencies.class);
    FCPServer server = mock(FCPServer.class);
    when(node.getConfig()).thenReturn(config);

    // Act
    try (MockedStatic<CoreFcpServerDependenciesFactory> factoryMock =
            mockStatic(CoreFcpServerDependenciesFactory.class);
        MockedStatic<FCPServer> fcpServerMock = mockStatic(FCPServer.class)) {
      factoryMock
          .when(
              () ->
                  CoreFcpServerDependenciesFactory.create(
                      eq(core), eq(runtimePorts), any(PersistentRequestRoot.class)))
          .thenReturn(dependencies);
      fcpServerMock
          .when(() -> FCPServer.maybeCreate(eq(dependencies), eq(config)))
          .thenReturn(server);

      FcpEndpointHandle endpointHandle = services.createEndpointHandle(node, core, runtimePorts);

      // Assert
      assertSame(server, FcpEndpointHandles.unwrap(endpointHandle));
      factoryMock.verify(
          () ->
              CoreFcpServerDependenciesFactory.create(
                  eq(core), eq(runtimePorts), any(PersistentRequestRoot.class)));
      fcpServerMock.verify(() -> FCPServer.maybeCreate(eq(dependencies), eq(config)));
    }
  }
}
