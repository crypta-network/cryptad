package network.crypta.client;

import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100") // test method naming convention
@ExtendWith(MockitoExtension.class)
class ArchiveStoreContextTest {
  private FreenetURI key;

  @Mock private ArchiveManager manager;

  @BeforeEach
  void setup() {
    key = new FreenetURI("KSK", "doc");
  }

  @Test
  @DisplayName("constructor_andAccessors_basicFields_areInitialized")
  void constructor_andAccessors_basicFields_areInitialized() {
    ArchiveStoreContext ctx = new ArchiveStoreContext(key, ARCHIVE_TYPE.ZIP);

    assertNotNull(ctx.getKey());
    assertEquals(key, ctx.getKey());
    assertEquals(ARCHIVE_TYPE.ZIP.metadataID, ctx.getArchiveType());
    assertEquals(-1L, ctx.getLastSize());
    assertNull(ctx.getLastHash());
  }

  @Test
  void setLastSize_whenZero_expectZero() {
    ArchiveStoreContext ctx = new ArchiveStoreContext(key, ARCHIVE_TYPE.TAR);

    ctx.setLastSize(0L);

    assertEquals(0L, ctx.getLastSize());
  }

  @Test
  void setLastSize_whenLargeValue_expectStored() {
    ArchiveStoreContext ctx = new ArchiveStoreContext(key, ARCHIVE_TYPE.TAR);
    long value = 123_456_789_012L;

    ctx.setLastSize(value);

    assertEquals(value, ctx.getLastSize());
  }

  @Test
  void setLastHash_whenNullAndWhenBytes_expectRoundTrip() {
    ArchiveStoreContext ctx = new ArchiveStoreContext(key, ARCHIVE_TYPE.TAR);
    assertNull(ctx.getLastHash(), "default lastHash must be null");

    byte[] hash = new byte[] {1, 2, 3, 4};
    ctx.setLastHash(hash);
    assertArrayEquals(hash, ctx.getLastHash());

    ctx.setLastHash(null);
    assertNull(ctx.getLastHash());
  }

  @Test
  void removeItem_whenItemNotPresent_doesNotInvokeInnerClose() {
    ArchiveStoreContext ctx = new ArchiveStoreContext(key, ARCHIVE_TYPE.TAR);
    TrackingItem item = new TrackingItem(ctx, key, "fileA", 10);

    ctx.removeItem(item);

    assertEquals(0, item.closeCount.get(), "innerClose should not be called");
  }

  @Test
  void addItem_thenRemoveItem_invokesInnerCloseOnce() {
    ArchiveStoreContext ctx = new ArchiveStoreContext(key, ARCHIVE_TYPE.TAR);
    TrackingItem item = new TrackingItem(ctx, key, "fileA", 10);

    ctx.addItem(item);
    ctx.removeItem(item);
    ctx.removeItem(item); // second call should be a no-op

    assertEquals(1, item.closeCount.get(), "innerClose should be called exactly once");
  }

  @Test
  void removeAllCachedItems_whenNoItems_managerIsNotCalled() {
    ArchiveStoreContext ctx = new ArchiveStoreContext(key, ARCHIVE_TYPE.TAR);

    ctx.removeAllCachedItems(manager);

    verify(manager, never()).removeCachedItem(any());
  }

  @Test
  void removeAllCachedItems_whenTwoItems_callsManagerInLifoOrder_andClosesEachOnce() {
    ArchiveStoreContext ctx = new ArchiveStoreContext(key, ARCHIVE_TYPE.TAR);
    TrackingItem first = new TrackingItem(ctx, key, "first", 1);
    TrackingItem second = new TrackingItem(ctx, key, "second", 1);

    // Add in order: first, then second. LinkedList#push makes second the head.
    ctx.addItem(first);
    ctx.addItem(second);

    // When manager.removeCachedItem(item) is called, simulate ArchiveManager behavior: item.close()
    doAnswer(
            invocation -> {
              ArchiveStoreItem it = invocation.getArgument(0);
              it.close(); // triggers context.removeItem(...)->innerClose()
              return null;
            })
        .when(manager)
        .removeCachedItem(any(ArchiveStoreItem.class));

    ctx.removeAllCachedItems(manager);

    // Verify order: second (head) removed first, then first
    InOrder order = inOrder(manager);
    order.verify(manager).removeCachedItem(second);
    order.verify(manager).removeCachedItem(first);
    order.verifyNoMoreInteractions();

    assertEquals(1, first.closeCount.get(), "first item should be closed exactly once");
    assertEquals(1, second.closeCount.get(), "second item should be closed exactly once");
  }

  // Test helper: minimal concrete ArchiveStoreItem that tracks innerClose invocations
  private static final class TrackingItem extends ArchiveStoreItem {
    final AtomicInteger closeCount = new AtomicInteger();
    private final long size;

    TrackingItem(ArchiveStoreContext ctx, FreenetURI key, String filename, long size) {
      super(new ArchiveKey(key, filename), ctx);
      this.size = size;
    }

    @Override
    void innerClose() {
      closeCount.incrementAndGet();
    }

    @Override
    Bucket getDataOrThrow() {
      return null;
    }

    @Override
    long spaceUsed() {
      return size;
    }

    @Override
    Bucket getReaderBucket() {
      return null;
    }
  }
}
