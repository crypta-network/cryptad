package network.crypta.support.transport.ip;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import network.crypta.node.NodeIPDetector;
import network.crypta.support.PriorityAwareExecutor;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** Unit tests for {@link IPAddressDetector}. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // allow underscore-based test method names per project convention
class IPAddressDetectorTest {

  @Test
  void onGetAddresses_filters_expected_addresses() throws Exception {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    IPAddressDetector det = new IPAddressDetector(10, nodeIPDetector);

    List<InetAddress> input = new ArrayList<>();
    InetAddress loopbackV4 = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    input.add(addr("0.0.0.0")); // any local -> excluded
    input.add(loopbackV4); // loopback -> included
    input.add(addr("224.0.0.1")); // multicast -> excluded
    input.add(addr("8.8.8.8")); // global unicast -> included
    input.add(addr("192.168.1.5")); // site-local -> included
    input.add(addr("fe80::1")); // IPv6 link-local -> included
    input.add(addr("2001:db8::5efe:0:1")); // ISATAP style (may be included)

    det.onGetAddresses(input);

    InetAddress[] out = toArray(det.lastAddressList.get());
    assertNotNull(out, "Expected filtered addresses");

    Set<String> actual = new HashSet<>();
    for (InetAddress a : out) actual.add(a.getHostAddress());

    // Expected inclusions
    assertTrue(actual.contains(loopbackV4.getHostAddress()));
    assertTrue(actual.contains(addr("8.8.8.8").getHostAddress()));
    assertTrue(actual.contains(addr("192.168.1.5").getHostAddress()));
    assertTrue(actual.contains(addr("fe80::1").getHostAddress()));

    // Exclusions (wildcard + multicast)
    assertFalse(actual.contains(addr("0.0.0.0").getHostAddress()));
    assertFalse(actual.contains(addr("224.0.0.1").getHostAddress()));
  }

  @Test
  void getAddress_triggers_detector_callback_when_changed() {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    // Override checkpoint to inject a deterministic change without touching real interfaces
    TestIPAddressDetector det = new TestIPAddressDetector(1, nodeIPDetector);
    det.lastDetectedTime = -1; // force checkpoint on the first call

    PriorityAwareExecutor directExec = new DirectExecutor();
    InetAddress[] out = det.getAddress(directExec);
    assertNotNull(out);
    assertEquals(1, out.length);
    assertEquals("8.8.8.8", out[0].getHostAddress());
    // Verify that change triggered detector.redetectAddress() via executor
    verify(nodeIPDetector, times(1)).redetectAddress();
  }

  @Test
  void getAddress_whenNullExecutor_expectNullPointerException() {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    IPAddressDetector det = new IPAddressDetector(10, nodeIPDetector);
    det.lastDetectedTime = System.currentTimeMillis();
    det.lastAddressList.set(new AtomicReferenceArray<>(new InetAddress[0]));

    NullPointerException npe = assertThrows(NullPointerException.class, () -> det.getAddress(null));
    assertEquals("executor", npe.getMessage());
  }

  @Test
  void getAddress_whenStaleButUnchanged_expectNoCallback() {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    // checkpoint returns false (no change)
    TestNoChangeDetector det = new TestNoChangeDetector(1, nodeIPDetector);
    det.lastDetectedTime = -1; // force checkpoint

    CapturingExecutor exec = new CapturingExecutor();
    InetAddress[] out = det.getAddress(exec);
    assertNotNull(out);
    assertEquals(1, out.length);
    assertEquals("8.8.4.4", out[0].getHostAddress());
    // No runnable submitted, no callback invoked
    assertEquals(0, exec.capturedCount());
    verify(nodeIPDetector, times(0)).redetectAddress();
  }

  @Test
  void getAddressNoCallback_whenNoSnapshotAndFresh_expectEmptyArray() {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    IPAddressDetector det = new IPAddressDetector(60_000, nodeIPDetector);
    // Keep the snapshot unequivocally "fresh" to avoid flaky timing around the staleness window.
    det.lastDetectedTime = System.currentTimeMillis() + 60_000;
    det.lastAddressList.set(null); // no snapshot yet

    InetAddress[] out = assertDoesNotThrow(det::getAddressNoCallback);
    assertNotNull(out);
    assertEquals(0, out.length);
  }

  private static InetAddress addr(String host) throws Exception {
    return InetAddress.getAllByName(host)[0];
  }

  private static InetAddress[] toArray(AtomicReferenceArray<InetAddress> addresses) {
    if (addresses == null) return null;
    InetAddress[] out = new InetAddress[addresses.length()];
    for (int i = 0; i < out.length; i++) {
      out[i] = addresses.get(i);
    }
    return out;
  }

  @Test
  void getAddressNoCallback_whenStale_callsCheckpoint() throws Exception {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    CountingDetector det = new CountingDetector(1, nodeIPDetector);
    det.lastDetectedTime = -1; // force checkpoint

    InetAddress[] out = det.getAddressNoCallback();
    assertEquals(1, det.checkpointCalls.get());
    assertNotNull(out);
    assertEquals(2, out.length);
    // Result equals the list set by checkpoint()
    assertArrayEquals(
        new InetAddress[] {InetAddress.getByName("1.1.1.1"), InetAddress.getByName("9.9.9.9")},
        out);
  }

  @Test
  void addressListChanged_ignores_order_detects_difference() throws Exception {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    IPAddressDetector det = new IPAddressDetector(10, nodeIPDetector);

    InetAddress a1 = InetAddress.getByName("8.8.8.8");
    InetAddress a2 = InetAddress.getByName("192.0.2.1"); // documentation range
    InetAddress a3 = InetAddress.getByName("8.8.4.4");

    InetAddress[] oldList = new InetAddress[] {a1, a2};
    InetAddress[] newListSameContentDifferentOrder = new InetAddress[] {a2, a1};
    InetAddress[] newListDifferent = new InetAddress[] {a3, a2};

    Method m =
        IPAddressDetector.class.getDeclaredMethod(
            "addressListChanged", InetAddress[].class, InetAddress[].class);
    m.setAccessible(true);

    boolean changedSame = (Boolean) m.invoke(det, oldList, newListSameContentDifferentOrder);
    boolean changedDifferent = (Boolean) m.invoke(det, oldList, newListDifferent);
    boolean changedFromNull = (Boolean) m.invoke(det, null, new InetAddress[] {a1});
    boolean changedSameRef = (Boolean) m.invoke(det, oldList, oldList);

    assertFalse(changedSame, "Order-only changes should not be considered different");
    assertTrue(changedDifferent, "Different content should be considered changed");
    assertTrue(changedFromNull, "Transition from null to non-null should be a change");
    assertFalse(changedSameRef, "Same reference should not be a change");
  }

  @Test
  void onGetAddresses_whenEmpty_expectNullSnapshot() {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    IPAddressDetector det = new IPAddressDetector(10, nodeIPDetector);
    det.onGetAddresses(new ArrayList<>());
    assertNull(det.lastAddressList.get());
  }

  @Test
  void onGetAddresses_skips_null_entries() throws Exception {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    IPAddressDetector det = new IPAddressDetector(10, nodeIPDetector);
    List<InetAddress> input = new ArrayList<>();
    input.add(null);
    InetAddress loopbackV4 = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    input.add(loopbackV4);
    det.onGetAddresses(input);
    assertNotNull(det.lastAddressList.get());
    assertEquals(1, det.lastAddressList.get().length());
    assertEquals(loopbackV4.getHostAddress(), det.lastAddressList.get().get(0).getHostAddress());
  }

  @Test
  @SuppressWarnings("java:S100") // method naming convention per project test style
  void cleanGlobalIPv6_whenGlobalV6WithScope_removesScopeId() throws Exception {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    IPAddressDetector det = new IPAddressDetector(10, nodeIPDetector);

    InetAddress withScope = InetAddress.getByName("2001:db8::1%42");
    Method m = IPAddressDetector.class.getDeclaredMethod("cleanGlobalIPv6", InetAddress.class);
    m.setAccessible(true);
    InetAddress cleaned = (InetAddress) m.invoke(det, withScope);

    assertEquals("2001:db8:0:0:0:0:0:1", cleaned.getHostAddress());
    // Ensure the original still contains the scope id
    assertTrue(withScope.getHostAddress().contains("%"));
  }

  /** Test subclass to provide a deterministic checkpoint without touching system interfaces. */
  private static final class TestIPAddressDetector extends IPAddressDetector {
    TestIPAddressDetector(long interval, NodeIPDetector detector) {
      super(interval, detector);
    }

    @Override
    protected synchronized boolean checkpoint() {
      try {
        this.lastAddressList.set(
            new AtomicReferenceArray<>(new InetAddress[] {InetAddress.getByName("8.8.8.8")}));
      } catch (Exception e) {
        throw new AssertionError(e);
      }
      this.lastDetectedTime = System.currentTimeMillis();
      return true; // indicate the list changed
    }
  }

  /** Minimal direct executor for tests. */
  private static final class DirectExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NotNull Runnable job) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      job.run();
    }

    @Override
    public int[] waitingThreads() {
      return new int[] {0};
    }

    @Override
    public int[] runningThreads() {
      return new int[] {1};
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  /**
   * Test subclass which sets a fixed list and reports no change, to verify that getAddress() does
   * not dispatch callbacks when the snapshot is identical.
   */
  private static final class TestNoChangeDetector extends IPAddressDetector {
    TestNoChangeDetector(long interval, NodeIPDetector detector) {
      super(interval, detector);
    }

    @Override
    protected synchronized boolean checkpoint() {
      try {
        this.lastAddressList.set(
            new AtomicReferenceArray<>(new InetAddress[] {InetAddress.getByName("8.8.4.4")}));
      } catch (Exception e) {
        throw new AssertionError(e);
      }
      this.lastDetectedTime = System.currentTimeMillis();
      return false; // no change
    }
  }

  /** Test subclass that counts checkpoint invocations and supplies a deterministic snapshot. */
  private static final class CountingDetector extends IPAddressDetector {
    private final AtomicInteger checkpointCalls = new AtomicInteger();

    CountingDetector(long interval, NodeIPDetector detector) {
      super(interval, detector);
    }

    @Override
    protected synchronized boolean checkpoint() {
      checkpointCalls.incrementAndGet();
      try {
        this.lastAddressList.set(
            new AtomicReferenceArray<>(
                new InetAddress[] {
                  InetAddress.getByName("1.1.1.1"), InetAddress.getByName("9.9.9.9")
                }));
      } catch (Exception e) {
        throw new AssertionError(e);
      }
      this.lastDetectedTime = System.currentTimeMillis();
      return true;
    }
  }

  /** Executor that captures submitted runnable without executing them automatically. */
  private static final class CapturingExecutor implements PriorityAwareExecutor {
    private final List<Runnable> captured = new ArrayList<>();

    int capturedCount() {
      return captured.size();
    }

    @Override
    public void execute(@NotNull Runnable job) {
      captured.add(job);
    }

    @Override
    public void execute(Runnable job, String jobName) {
      captured.add(job);
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      captured.add(job);
    }

    @Override
    public int[] waitingThreads() {
      return new int[] {0};
    }

    @Override
    public int[] runningThreads() {
      return new int[] {0};
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }
}
