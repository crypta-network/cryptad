package network.crypta.clients.fcp.bridge;

import network.crypta.clients.fcp.FcpServerDependencies;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CoreFcpServerDependenciesFactoryTest {

  @Mock private NodeClientCore core;
  @Mock private RuntimePorts runtimePorts;
  @Mock private RuntimePorts coreRuntimePorts;
  @Mock private TransferAccessPort serverTransferAccess;
  @Mock private TransferAccessPort coreTransferAccess;

  @Test
  void create_whenCoreNull_expectNullPointerException() {
    // Arrange
    PersistentRequestRoot persistentRoot = new PersistentRequestRoot();

    // Act & Assert
    assertThrows(
        NullPointerException.class,
        () -> CoreFcpServerDependenciesFactory.create(null, runtimePorts, persistentRoot));
  }

  @Test
  void create_whenRuntimePortsNull_expectNullPointerException() {
    // Arrange
    PersistentRequestRoot persistentRoot = new PersistentRequestRoot();

    // Act & Assert
    assertThrows(
        NullPointerException.class,
        () -> CoreFcpServerDependenciesFactory.create(core, null, persistentRoot));
  }

  @Test
  void create_whenPersistentRootNull_expectNullPointerException() {
    // Act & Assert
    assertThrows(
        NullPointerException.class,
        () -> CoreFcpServerDependenciesFactory.create(core, runtimePorts, null));
  }

  @Test
  void create_whenCalled_expectBundleRetainsProvidedDependencies() {
    // Arrange
    PersistentRequestRoot persistentRoot = new PersistentRequestRoot();

    // Act
    FcpServerDependencies dependencies =
        CoreFcpServerDependenciesFactory.create(core, runtimePorts, persistentRoot);

    // Assert
    assertSame(runtimePorts, dependencies.runtimePorts());
    assertSame(persistentRoot, dependencies.persistentRoot());
    assertInstanceOf(CoreFcpServerRuntimeSupport.class, dependencies.serverRuntimeSupport());
    assertNotNull(dependencies.serverRuntimeSupport());
    assertNotNull(dependencies.messageRuntimeSupport());
    assertNotNull(dependencies.fetchRuntimeSupport());
    assertNotNull(dependencies.messageFetchRuntimeSupport());
    assertNotNull(dependencies.insertRuntimeSupport());
  }

  @Test
  void create_whenTransferAccessQueried_expectSupportsUseExpectedRuntimePorts() {
    // Arrange
    PersistentRequestRoot persistentRoot = new PersistentRequestRoot();
    when(runtimePorts.transferAccess()).thenReturn(serverTransferAccess);
    when(core.getRuntimePorts()).thenReturn(coreRuntimePorts);
    when(coreRuntimePorts.transferAccess()).thenReturn(coreTransferAccess);
    FcpServerDependencies dependencies =
        CoreFcpServerDependenciesFactory.create(core, runtimePorts, persistentRoot);

    // Act & Assert
    assertSame(serverTransferAccess, dependencies.fetchRuntimeSupport().transferAccess());
    assertSame(coreTransferAccess, dependencies.messageFetchRuntimeSupport().transferAccess());
    assertSame(coreTransferAccess, dependencies.insertRuntimeSupport().transferAccess());
  }

  @Test
  void create_whenTransferPoliciesChange_expectSupportsReadLiveRuntimePorts() {
    // Arrange
    PersistentRequestRoot persistentRoot = new PersistentRequestRoot();
    TransferAccessPort updatedServerTransferAccess = mock(TransferAccessPort.class);
    TransferAccessPort updatedCoreTransferAccess = mock(TransferAccessPort.class);
    when(runtimePorts.transferAccess()).thenReturn(serverTransferAccess);
    when(core.getRuntimePorts()).thenReturn(coreRuntimePorts);
    when(coreRuntimePorts.transferAccess()).thenReturn(coreTransferAccess);
    FcpServerDependencies dependencies =
        CoreFcpServerDependenciesFactory.create(core, runtimePorts, persistentRoot);
    when(runtimePorts.transferAccess()).thenReturn(updatedServerTransferAccess);
    when(coreRuntimePorts.transferAccess()).thenReturn(updatedCoreTransferAccess);

    // Act & Assert
    assertSame(updatedServerTransferAccess, dependencies.fetchRuntimeSupport().transferAccess());
    assertSame(
        updatedCoreTransferAccess, dependencies.messageFetchRuntimeSupport().transferAccess());
    assertSame(updatedCoreTransferAccess, dependencies.insertRuntimeSupport().transferAccess());
  }
}
