package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DNSRequesterTest {

  @Mock private Node node;

  // Track only threads started by this test instance.
  private final java.util.List<Thread> startedThreads =
      java.util.Collections.synchronizedList(new java.util.ArrayList<>());

  @AfterEach
  void afterEach() throws InterruptedException {
    // Interrupt and join only threads created by these tests.
    synchronized (startedThreads) {
      for (Thread t : startedThreads) {
        if (t == null) continue;
        if (t.isAlive()) t.interrupt();
      }
      for (Thread t : startedThreads) {
        if (t == null) continue;
        joinOrFail(t, Duration.ofSeconds(2));
      }
      startedThreads.clear();
    }
  }

  @Test
  @DisplayName("start() delegates to executor with descriptive thread name")
  void start_whenCalled_executorExecuteWithName() {
    // Arrange
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    when(node.getExecutor()).thenReturn(executor);
    when(node.getDarknetPortNumber()).thenReturn(12345);

    DNSRequester requester = new DNSRequester(node);

    // Act
    requester.start();

    // Assert
    verify(executor).execute(requester, "DNSRequester thread for 12345");
  }

  @Test
  @DisplayName("forceRun() notifies waiting threads")
  void forceRun_whenThreadWaiting_notified() throws Exception {
    DNSRequester requester = new DNSRequester(node);
    CountDownLatch waiting = new CountDownLatch(1);
    CountDownLatch awakened = new CountDownLatch(1);

    Thread waiter =
        new Thread(
            () -> {
              synchronized (requester) {
                waiting.countDown();
                try {
                  requester.wait(5000);
                } catch (InterruptedException _) {
                  Thread.currentThread().interrupt();
                }
              }
              awakened.countDown();
            },
            "dnsrequester-test-waiter");

    // Track and start the waiter owned by this test.
    startedThreads.add(waiter);
    waiter.start();
    assertTrue(waiting.await(1, TimeUnit.SECONDS), "waiter did not enter wait state");

    // Act
    requester.forceRun();

    // Assert
    assertTrue(awakened.await(1, TimeUnit.SECONDS), "waiter was not awakened by notifyAll()");
  }

  @Test
  @Timeout(5)
  @DisplayName("realRun(): with no unconnected peers, does not attempt DNS update")
  void realRun_whenNoUnconnectedPeers_doesNothing() {
    // Arrange: peers all connected
    PeerManager pm = mock(PeerManager.class);
    PeerNode p1 = mock(PeerNode.class);
    PeerNode p2 = mock(PeerNode.class);
    when(p1.isConnected()).thenReturn(true);
    when(p2.isConnected()).thenReturn(true);
    when(pm.myPeers()).thenReturn(new PeerNode[] {p1, p2});
    when(node.getPeers()).thenReturn(pm);
    when(node.getFastWeakRandom()).thenReturn(new FixedSequenceRandom(0));

    DNSRequester requester = new DNSRequester(node);

    // Act: call private realRun() once in a worker and interrupt promptly to avoid sleeping
    runRealRunOnceAndInterrupt(requester);

    // Assert: no DNS update attempted
    verify(p1, never()).maybeUpdateHandshakeIPs(anyBoolean());
    verify(p2, never()).maybeUpdateHandshakeIPs(anyBoolean());
  }

  @Test
  @Timeout(5)
  @DisplayName("realRun(): selects an unconnected peer and triggers maybeUpdateHandshakeIPs(false)")
  void realRun_whenEligiblePeers_selectsOne_callsMaybeUpdateHandshakeIPs() throws Exception {
    // Arrange: three unconnected peers, choose index 1 deterministically
    PeerManager pm = mock(PeerManager.class);
    PeerNode p0 = mock(PeerNode.class);
    PeerNode p1 = mock(PeerNode.class);
    PeerNode p2 = mock(PeerNode.class);
    when(p0.isConnected()).thenReturn(false);
    when(p1.isConnected()).thenReturn(false);
    when(p2.isConnected()).thenReturn(false);
    when(p0.getLocation()).thenReturn(0.10);
    when(p1.getLocation()).thenReturn(0.20);
    when(p2.getLocation()).thenReturn(0.30);
    when(pm.myPeers()).thenReturn(new PeerNode[] {p0, p1, p2});
    when(node.getPeers()).thenReturn(pm);
    // Sequence: select index=1, then minimal wait; run only once
    when(node.getFastWeakRandom()).thenReturn(new FixedSequenceRandom(1, 0));

    CountDownLatch called = new CountDownLatch(1);
    doAnswer(
            inv -> {
              called.countDown();
              return null;
            })
        .when(p1)
        .maybeUpdateHandshakeIPs(false);

    DNSRequester requester = new DNSRequester(node);

    // Act
    Thread t = startRealRunInThread(requester);
    assertTrue(called.await(1, TimeUnit.SECONDS), "Selected peer did not receive DNS update call");
    t.interrupt();
    t.join(2000);

    // Assert
    verify(p1).maybeUpdateHandshakeIPs(false);
    verify(p0, never()).maybeUpdateHandshakeIPs(anyBoolean());
    verify(p2, never()).maybeUpdateHandshakeIPs(anyBoolean());
  }

  @Test
  @Timeout(10)
  @DisplayName(
      "realRun(): with >=5 peers, cache works until filtered set <5 then clears; reselection"
          + " follows")
  void realRun_whenSixPeers_recentnessTrimsAndReallowsOldest() throws Exception {
    // Arrange: six unconnected peers with stable order and distinct locations
    PeerManager pm = mock(PeerManager.class);
    PeerNode[] peers = new PeerNode[6];
    for (int i = 0; i < peers.length; i++) {
      peers[i] = mock(PeerNode.class);
      when(peers[i].isConnected()).thenReturn(false);
      when(peers[i].getLocation()).thenReturn(10.0 + i);
    }
    when(pm.myPeers()).thenReturn(peers);
    when(node.getPeers()).thenReturn(pm);

    // Random always selects index 0 of the current filtered list, then minimal wait.
    // For 7 runs we need 14 numbers: [0,0] * 7
    int[] seq = new int[14];
    Arrays.fill(seq, 0);
    when(node.getFastWeakRandom()).thenReturn(new FixedSequenceRandom(seq));

    DNSRequester requester = new DNSRequester(node);

    // Capture invocation order
    java.util.List<Integer> order =
        java.util.Collections.synchronizedList(new java.util.ArrayList<>());
    final CountDownLatch[] perRunLatch = {new CountDownLatch(1)};

    for (int i = 0; i < peers.length; i++) {
      final int idx = i;
      if (idx < 3) {
        doAnswer(
                inv -> {
                  order.add(idx);
                  perRunLatch[0].countDown();
                  return null;
                })
            .when(peers[idx])
            .maybeUpdateHandshakeIPs(false);
      }
    }

    // Expected selection given we always choose index 0 within the filtered array.
    // After two selections, filtered size drops below 5 and the cache is cleared each run,
    // cycling deterministically over the first three peers again.
    int[] expected = new int[] {0, 1, 2, 0, 1, 2, 0};

    for (int run = 0; run < expected.length; run++) {
      perRunLatch[0] = new CountDownLatch(1);
      Thread t = startRealRunInThread(requester);
      assertTrue(
          perRunLatch[0].await(1, TimeUnit.SECONDS),
          "DNS update not called in time (run " + run + ")");
      t.interrupt();
      t.join(2000);
    }

    // Assert exact order and that peer[5] was never selected
    org.junit.jupiter.api.Assertions.assertEquals(
        expected.length, order.size(), "Unexpected call count");
    for (int i = 0; i < expected.length; i++) {
      org.junit.jupiter.api.Assertions.assertEquals(
          expected[i], order.get(i), "Mismatch at run " + i + "; actual order=" + order);
    }
    // Peers 3,4,5 are never selected in this deterministic path
    verify(peers[3], never()).maybeUpdateHandshakeIPs(false);
    verify(peers[4], never()).maybeUpdateHandshakeIPs(false);
    verify(peers[5], never()).maybeUpdateHandshakeIPs(false);
  }

  @Test
  @Timeout(5)
  @DisplayName("realRun(): connected peers are ignored")
  void realRun_filtersOutConnectedPeers() throws Exception {
    PeerManager pm = mock(PeerManager.class);
    PeerNode connected = mock(PeerNode.class);
    PeerNode unconnectedA = mock(PeerNode.class);
    PeerNode unconnectedB = mock(PeerNode.class);

    when(connected.isConnected()).thenReturn(true);
    when(unconnectedA.isConnected()).thenReturn(false);
    when(unconnectedB.isConnected()).thenReturn(false);
    when(unconnectedA.getLocation()).thenReturn(1.1);
    when(unconnectedB.getLocation()).thenReturn(2.2);

    when(pm.myPeers()).thenReturn(new PeerNode[] {connected, unconnectedA, unconnectedB});
    when(node.getPeers()).thenReturn(pm);
    // Choose the first eligible (index 0 of filtered -> unconnectedA)
    when(node.getFastWeakRandom()).thenReturn(new FixedSequenceRandom(0, 0));

    CountDownLatch called = new CountDownLatch(1);
    doAnswer(
            inv -> {
              called.countDown();
              return null;
            })
        .when(unconnectedA)
        .maybeUpdateHandshakeIPs(false);

    DNSRequester requester = new DNSRequester(node);

    Thread t = startRealRunInThread(requester);
    assertTrue(called.await(1, TimeUnit.SECONDS), "Unconnected peer was not selected");
    t.interrupt();
    t.join(2000);

    verify(unconnectedA).maybeUpdateHandshakeIPs(false);
    verify(unconnectedB, never()).maybeUpdateHandshakeIPs(anyBoolean());
    verify(connected, never()).maybeUpdateHandshakeIPs(anyBoolean());
  }

  // Helpers

  private Thread startRealRunInThread(DNSRequester requester) {
    Thread t =
        new Thread(
            () -> {
              try {
                invokeRealRun(requester);
              } catch (Exception t1) {
                // Fail fast in the worker to make the issue visible in reports
                org.junit.jupiter.api.Assertions.fail(
                    "Unexpected exception in DNSRequester worker thread", t1);
              }
            },
            "DNSRequesterTest-worker");
    startedThreads.add(t);
    t.start();
    return t;
  }

  private void runRealRunOnceAndInterrupt(DNSRequester requester) {
    Thread t = startRealRunInThread(requester);
    // Interrupt immediately to avoid the internal 1s wait
    t.interrupt();
    assertDoesNotThrow(() -> joinOrFail(t, Duration.ofSeconds(2)));
  }

  private static void joinOrFail(Thread t, Duration timeout) throws InterruptedException {
    t.join(timeout.toMillis());
    assertFalse(t.isAlive(), "Worker thread did not terminate in time");
  }

  @SuppressWarnings("java:S3011")
  private static void invokeRealRun(DNSRequester requester)
      throws NoSuchMethodException,
          IllegalAccessException,
          java.lang.reflect.InvocationTargetException {
    Method m = DNSRequester.class.getDeclaredMethod("realRun");
    m.setAccessible(true);
    m.invoke(requester);
  }

  /**
   * Random with a fixed, repeating sequence of values used for deterministic selection and minimal
   * waiting inside DNSRequester.realRun().
   */
  private static final class FixedSequenceRandom extends Random {
    private final int[] seq;
    private int idx;

    private FixedSequenceRandom(int... seq) {
      this.seq = (seq == null || seq.length == 0) ? new int[] {0} : seq.clone();
    }

    @Override
    public int nextInt(int bound) {
      int v = seq[idx++ % seq.length];
      if (v < 0) v = -v;
      if (bound <= 0) return 0;
      return v % bound;
    }
  }
}
