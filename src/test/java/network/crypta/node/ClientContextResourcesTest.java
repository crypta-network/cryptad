package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import network.crypta.client.ArchiveManager;
import network.crypta.client.async.HealingQueue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientContextResourcesTest {
  @Mock private ArchiveManager archiveManager;
  @Mock private HealingQueue healingQueue;

  @Test
  void getArchiveManager_whenConstructedWithValue_returnsSameInstance() {
    ClientContextResources resources = new ClientContextResources(archiveManager, healingQueue);

    ArchiveManager result = resources.getArchiveManager();

    assertSame(archiveManager, result);
  }

  @Test
  void getHealingQueue_whenConstructedWithValue_returnsSameInstance() {
    ClientContextResources resources = new ClientContextResources(archiveManager, healingQueue);

    HealingQueue result = resources.getHealingQueue();

    assertSame(healingQueue, result);
  }

  @Test
  void getArchiveManager_whenConstructedWithNull_returnsNull() {
    ClientContextResources resources = new ClientContextResources(null, healingQueue);

    ArchiveManager result = resources.getArchiveManager();

    assertNull(result);
  }

  @Test
  void getHealingQueue_whenConstructedWithNull_returnsNull() {
    ClientContextResources resources = new ClientContextResources(archiveManager, null);

    HealingQueue result = resources.getHealingQueue();

    assertNull(result);
  }
}
