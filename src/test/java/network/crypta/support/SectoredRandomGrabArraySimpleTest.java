package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestSelector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Allow method names like method_whenCondition_expectOutcome
class SectoredRandomGrabArraySimpleTest {

  @Mock private RemoveRandomParent parent;

  private ClientRequestSelector root;

  @BeforeEach
  void setUp() {
    // Use a Mockito mock as the synchronization root; only used for locking in these tests.
    root = mock(ClientRequestSelector.class);
  }

  private static RandomGrabArrayItem readyItem() {
    RandomGrabArrayItem item = mock(RandomGrabArrayItem.class);
    when(item.getWakeupTime(any(), any(Long.class))).thenReturn(0L);
    return item;
  }

  @Test
  @DisplayName("add_whenNoExistingGrabber_createsRga_addsItem_andClearsParentWakeup")
  void add_whenNoExistingGrabber_createsRga_addsItem_andClearsParentWakeup() {
    SectoredRandomGrabArraySimple<String, Object> srga =
        new SectoredRandomGrabArraySimple<>("owner", parent, root);

    Object client = new Object();
    RandomGrabArrayItem item = readyItem();
    ClientContext ctx = mock(ClientContext.class);

    // Act
    srga.add(client, item, ctx);

    // Assert – SRGA now has one child grabber for the client
    RandomGrabArrayWithObject<Object> rga = srga.getGrabber(client);
    assertNotNull(rga, "Expected a new RandomGrabArrayWithObject to be created for the client");
    assertSame(client, rga.getObject(), "New RGA should be associated with the same client object");
    assertEquals(1, srga.size(), "One child grabber should be present");
    assertEquals(1, rga.size(), "The created RGA should contain the added item");

    // clearWakeupTime(context) should propagate to the SRGA's parent when context != null
    verify(parent, atLeastOnce()).clearWakeupTime(ctx);
  }

  @Test
  @DisplayName("add_whenExistingGrabber_reusesAndDoesNotDuplicate")
  void add_whenExistingGrabber_reusesAndDoesNotDuplicate() {
    SectoredRandomGrabArraySimple<String, Object> srga =
        new SectoredRandomGrabArraySimple<>("owner", parent, root);

    Object client = new Object();
    ClientContext ctx = mock(ClientContext.class);

    // First item creates the grabber
    srga.add(client, readyItem(), ctx);
    // Second item for the same client should reuse the same RGA
    srga.add(client, readyItem(), ctx);

    RandomGrabArrayWithObject<Object> rga = srga.getGrabber(client);
    assertNotNull(rga);
    assertEquals(1, srga.size(), "Should still have exactly one child grabber for the client");
    assertEquals(2, rga.size(), "Existing RGA must contain both items after two adds");
  }

  @Test
  @DisplayName("add_whenContextNull_doesNotPropagateClearWakeup")
  void add_whenContextNull_doesNotPropagateClearWakeup() {
    SectoredRandomGrabArraySimple<String, Object> srga =
        new SectoredRandomGrabArraySimple<>("owner", parent, root);

    Object client = new Object();
    // No stubbing required: add() will not consult item when context is null
    RandomGrabArrayItem item = mock(RandomGrabArrayItem.class);

    // Act with null ClientContext
    srga.add(client, item, null);

    // Assert: no propagation to parent when context is null
    verify(parent, never()).clearWakeupTime(any());
  }

  @Test
  @DisplayName("add_identitySemantics_equalButNotSame_createsDistinctGrabbers")
  void add_identitySemantics_equalButNotSame_createsDistinctGrabbers() {
    SectoredRandomGrabArraySimple<String, String> srga =
        new SectoredRandomGrabArraySimple<>("owner", parent, root);

    // Use distinct String instances (not interned literals) with equal contents
    // to validate that SRGA compares clients by identity (==), not equals().
    String a1 = String.valueOf("clientA".toCharArray());
    String a2 = String.valueOf("clientA".toCharArray());

    srga.add(a1, readyItem(), mock(ClientContext.class));
    srga.add(a2, readyItem(), mock(ClientContext.class));

    assertNotNull(srga.getGrabber(a1));
    assertNotNull(srga.getGrabber(a2));
    assertEquals(2, srga.size(), "Two distinct child grabbers expected due to identity semantics");
  }

  @Test
  @DisplayName("getObject_returnsOwnerPassedToConstructor")
  void getObject_returnsOwnerPassedToConstructor() {
    String owner = "OWNER";
    SectoredRandomGrabArraySimple<String, Object> srga =
        new SectoredRandomGrabArraySimple<>(owner, parent, root);

    assertEquals(owner, srga.getObject());
  }

  @Test
  @DisplayName("add_concurrentSameClient_createsSingleGrabber_andAddsAllItems")
  void add_concurrentSameClient_createsSingleGrabber_andAddsAllItems() throws Exception {
    SectoredRandomGrabArraySimple<String, Object> srga =
        new SectoredRandomGrabArraySimple<>("owner", parent, root);

    Object client = new Object();
    int threads = 8;
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(threads);
    java.util.concurrent.atomic.AtomicReference<Throwable> failure =
        new java.util.concurrent.atomic.AtomicReference<>();
    List<Thread> ths = new ArrayList<>();

    for (int i = 0; i < threads; i++) {
      ths.add(
          new Thread(
              () -> {
                try {
                  boolean ok = start.await(5, TimeUnit.SECONDS);
                  if (!ok) throw new AssertionError("start latch timed out");
                  srga.add(client, readyItem(), mock(ClientContext.class));
                } catch (Throwable t) {
                  failure.compareAndSet(null, t);
                  if (t instanceof InterruptedException) Thread.currentThread().interrupt();
                } finally {
                  done.countDown();
                }
              }));
    }
    ths.forEach(Thread::start);
    start.countDown();
    assertTrue(done.await(10, TimeUnit.SECONDS), "Timed out waiting for worker threads");
    if (failure.get() != null) {
      // Surface worker failure in the main test thread to fail deterministically
      throw new AssertionError("Worker failed", failure.get());
    }

    RandomGrabArrayWithObject<Object> rga = srga.getGrabber(client);
    assertNotNull(rga, "Single grabber should exist for the client after concurrent adds");
    assertEquals(1, srga.size(), "Only one child grabber should be created for the client");
    assertEquals(threads, rga.size(), "All items should be present in the client's RGA");
  }
}
