package network.crypta.support.transport.ip;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import network.crypta.node.NodeIPDetector;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link IPAddressDetector}. */
class IPAddressDetectorTest {

  @Test
  void onGetAddresses_filters_expected_addresses() throws Exception {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    IPAddressDetector det = new IPAddressDetector(10, nodeIPDetector);

    List<InetAddress> input = new ArrayList<>();
    input.add(InetAddress.getByName("0.0.0.0")); // any local -> excluded
    input.add(InetAddress.getByName("127.0.0.1")); // loopback -> included
    input.add(InetAddress.getByName("224.0.0.1")); // multicast -> excluded
    input.add(InetAddress.getByName("8.8.8.8")); // global unicast -> included
    input.add(InetAddress.getByName("192.168.1.5")); // site-local -> included
    input.add(InetAddress.getByName("fe80::1")); // IPv6 link-local -> included
    input.add(InetAddress.getByName("2001:db8::5efe:0:1")); // ISATAP style (may be included)

    det.onGetAddresses(input);

    InetAddress[] out = det.lastAddressList;
    assertNotNull(out, "Expected filtered addresses");

    Set<String> actual = new HashSet<>();
    for (InetAddress a : out) actual.add(a.getHostAddress());

    // Expected inclusions
    assertTrue(actual.contains(InetAddress.getByName("127.0.0.1").getHostAddress()));
    assertTrue(actual.contains(InetAddress.getByName("8.8.8.8").getHostAddress()));
    assertTrue(actual.contains(InetAddress.getByName("192.168.1.5").getHostAddress()));
    assertTrue(actual.contains(InetAddress.getByName("fe80::1").getHostAddress()));

    // Exclusions (wildcard + multicast)
    assertFalse(actual.contains(InetAddress.getByName("0.0.0.0").getHostAddress()));
    assertFalse(actual.contains(InetAddress.getByName("224.0.0.1").getHostAddress()));
  }

  @Test
  void getAddress_triggers_detector_callback_when_changed() throws Exception {
    NodeIPDetector nodeIPDetector = mock(NodeIPDetector.class);
    // Override checkpoint to inject a deterministic change without touching real interfaces
    TestIPAddressDetector det = new TestIPAddressDetector(1, nodeIPDetector);
    det.lastDetectedTime = -1; // force checkpoint on first call

    PriorityAwareExecutor directExec = new DirectExecutor();
    InetAddress[] out = det.getAddress(directExec);
    assertNotNull(out);
    assertEquals(1, out.length);
    assertEquals("8.8.8.8", out[0].getHostAddress());
    // Verify that change triggered detector.redetectAddress() via executor
    verify(nodeIPDetector, times(1)).redetectAddress();
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

  /** Test subclass to provide a deterministic checkpoint without touching system interfaces. */
  private static final class TestIPAddressDetector extends IPAddressDetector {
    TestIPAddressDetector(long interval, NodeIPDetector detector) {
      super(interval, detector);
    }

    @Override
    protected synchronized boolean checkpoint() {
      try {
        this.lastAddressList = new InetAddress[] {InetAddress.getByName("8.8.8.8")};
      } catch (Exception e) {
        throw new AssertionError(e);
      }
      this.lastDetectedTime = System.currentTimeMillis();
      return true; // indicate list changed
    }
  }

  /** Minimal direct executor for tests. */
  private static final class DirectExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(Runnable job) {
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
}
