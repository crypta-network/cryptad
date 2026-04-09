package network.crypta.clients.fcp.bridge;

import network.crypta.node.NodeClientCore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FcpQueuePortsTest {

  @Mock private NodeClientCore core;

  @Test
  void create_whenCalled_expectLegacyBridgeTypes() {
    FcpQueuePorts.Bundle bundle = FcpQueuePorts.create(core);

    assertAll(
        () -> assertInstanceOf(FcpQueueAdminBackend.class, bundle.adminBackend()),
        () -> assertInstanceOf(FcpQueuePageBackend.class, bundle.pageBackend()),
        () -> assertInstanceOf(LegacyQueueCompletionPort.class, bundle.completionPort()),
        () -> assertInstanceOf(LegacyQueueDownloadPort.class, bundle.downloadPort()),
        () -> assertInstanceOf(LegacyQueueInsertPort.class, bundle.insertPort()));
  }

  @Test
  void create_whenCalled_expectNoEagerCoreInteractions() {
    FcpQueuePorts.create(core);

    verifyNoInteractions(core);
  }

  @Test
  void create_whenCalledTwice_expectFreshBridgeInstances() {
    FcpQueuePorts.Bundle first = FcpQueuePorts.create(core);
    FcpQueuePorts.Bundle second = FcpQueuePorts.create(core);

    assertAll(
        () -> assertNotSame(first, second),
        () -> assertNotSame(first.adminBackend(), second.adminBackend()),
        () -> assertNotSame(first.pageBackend(), second.pageBackend()),
        () -> assertNotSame(first.completionPort(), second.completionPort()),
        () -> assertNotSame(first.downloadPort(), second.downloadPort()),
        () -> assertNotSame(first.insertPort(), second.insertPort()));
  }
}
