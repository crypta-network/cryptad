package network.crypta.node.runtime;

import java.io.File;
import java.nio.file.Path;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.node.ClientEndpoints;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyQueueSupportPortTest {

  @Mock private NodeClientCore core;
  @Mock private ClientEndpoints endpoints;
  @Mock private FCPServer fcp;
  @Mock private Node node;
  @Mock private NodeStorageSubsystem storage;

  @TempDir Path tempDir;

  private LegacyQueueSupportPort port;

  @BeforeEach
  void setUp() {
    port = new LegacyQueueSupportPort(core);
  }

  @Test
  void isQueueBackendEnabled_whenQueried_delegatesToFcpServerFlag() {
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getFCPServer()).thenReturn(fcp);
    when(fcp.isEnabled()).thenReturn(true).thenReturn(false);

    assertTrue(port.isQueueBackendEnabled());
    assertFalse(port.isQueueBackendEnabled());
  }

  @Test
  void persistenceStatus_whenQueried_exportsAwaitingPasswordStoppingTempDirAndDatabasePath() {
    File persistentTempDir = tempDir.resolve("persistent-temp").toFile();
    String databasePath = tempDir.resolve("queue.db").toString();
    when(core.getNode()).thenReturn(node);
    when(node.awaitingPassword()).thenReturn(false);
    when(node.isStopping()).thenReturn(false);
    when(core.getPersistentTempDir()).thenReturn(persistentTempDir);
    when(node.getDatabasePath()).thenReturn(databasePath);

    QueuePersistenceStatusSnapshot snapshot = port.persistenceStatus();

    assertFalse(snapshot.awaitingPassword());
    assertFalse(snapshot.stopping());
    assertSame(persistentTempDir, snapshot.persistentTempDir());
    assertEquals(databasePath, snapshot.databasePath());
  }

  @Test
  void persistenceStatus_whenAwaitingPasswordShortCircuits_doesNotResolvePersistenceBrokenPaths() {
    when(core.getNode()).thenReturn(node);
    when(node.awaitingPassword()).thenReturn(true);
    when(node.isStopping()).thenReturn(false);

    QueuePersistenceStatusSnapshot snapshot = port.persistenceStatus();

    assertTrue(snapshot.awaitingPassword());
    assertFalse(snapshot.stopping());
    assertNull(snapshot.persistentTempDir());
    assertNull(snapshot.databasePath());
    verify(core, never()).getPersistentTempDir();
    verify(node, never()).getDatabasePath();
  }

  @Test
  void persistenceStatus_whenStoppingShortCircuits_doesNotResolvePersistenceBrokenPaths() {
    when(core.getNode()).thenReturn(node);
    when(node.awaitingPassword()).thenReturn(false);
    when(node.isStopping()).thenReturn(true);

    QueuePersistenceStatusSnapshot snapshot = port.persistenceStatus();

    assertFalse(snapshot.awaitingPassword());
    assertTrue(snapshot.stopping());
    assertNull(snapshot.persistentTempDir());
    assertNull(snapshot.databasePath());
    verify(core, never()).getPersistentTempDir();
    verify(node, never()).getDatabasePath();
  }

  @Test
  void beginPanic_whenCalled_triggersExistingPanicStartBehavior() throws Exception {
    when(core.getNode()).thenReturn(node);
    when(node.storage()).thenReturn(storage);

    port.beginPanic();

    InOrder inOrder = org.mockito.Mockito.inOrder(storage, node);
    inOrder.verify(storage).killMasterKeysFile();
    inOrder.verify(node).panic();
  }

  @Test
  void finishPanic_whenCalled_delegatesToNodeFinishPanic() {
    when(core.getNode()).thenReturn(node);

    port.finishPanic();

    verify(node).finishPanic();
  }
}
