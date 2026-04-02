/* -*- Mode: java; c-basic-indent: 4; tab-width: 4 -*- */
package network.crypta.support.transport.ip;

import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceArray;
import network.crypta.io.AddressIdentifier;
import network.crypta.node.NodeIPDetector;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.InetAddressComparator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Periodically discovers the node's local IP addresses.
 *
 * <p>Addresses are collected from {@link java.net.NetworkInterface} instances and lightly filtered
 * for common non-routable cases. IPv6 global addresses have any scope-id removed. The most recent
 * snapshot is cached and returned by the query methods. When a change in the address set is
 * detected, the associated {@link network.crypta.node.NodeIPDetector} is notified on a caller
 * provided {@link PriorityAwareExecutor}.
 *
 * <p>This class does not start threads by itself. If you want periodic detection independent of
 * explicit queries, run it as a {@link Runnable}. The background loop runs on the caller's thread
 * (typically the node executor), waits between ticks, and exits when interrupted.
 */
public class IPAddressDetector implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(IPAddressDetector.class);

  // no static initialization required

  /** Minimum time in milliseconds between detections. */
  private final long interval;

  /** Callback target for MTU reports and re-detection notifications. */
  private final NodeIPDetector detector;

  /**
   * Creates a new detector.
   *
   * @param interval minimum time in milliseconds between detection runs
   * @param detector callback target used to report MTU information and to notify when the detected
   *     addresses change; must not be {@code null}
   */
  public IPAddressDetector(long interval, NodeIPDetector detector) {
    this.interval = interval;
    this.detector = detector;
  }

  final AtomicReference<AtomicReferenceArray<InetAddress>> lastAddressList =
      new AtomicReference<>();
  long lastDetectedTime = -1;

  /**
   * Returns the current snapshot of detected addresses.
   *
   * <p>If the cached snapshot is older than {@link #interval}, a detection pass is executed
   * synchronously on the calling thread. This method never invokes {@code detector.redetectAddress}
   * and is therefore safe to call from inside the detector itself.
   *
   * @return an array of addresses (possibly empty) representing the last known snapshot
   */
  public InetAddress[] getAddressNoCallback() {
    if (System.currentTimeMillis() > (lastDetectedTime + interval)) {
      checkpoint();
    }
    return snapshotAddresses(lastAddressList.get());
  }

  /**
   * Returns the current snapshot and, if needed, triggers callback processing.
   *
   * <p>If the cached snapshot is older than {@link #interval}, a detection pass is performed. When
   * the set of addresses has changed since the previous snapshot, {@link
   * NodeIPDetector#redetectAddress()} is dispatched on the supplied {@link PriorityAwareExecutor}.
   * The callback is never invoked synchronously on the caller's thread.
   *
   * @param executor the executor used to run the callback; must not be {@code null}
   * @return an array of addresses (possibly empty) representing the last known snapshot
   */
  public InetAddress[] getAddress(PriorityAwareExecutor executor) {
    Objects.requireNonNull(executor, "executor");
    if (System.currentTimeMillis() > (lastDetectedTime + interval) && checkpoint()) {
      executor.execute(detector::redetectAddress);
    }
    return snapshotAddresses(lastAddressList.get());
  }

  boolean old = false;

  /**
   * Performs a detection pass.
   *
   * <p>Lists network interfaces, reports MTU information, collects and normalizes addresses, and
   * updates the cached snapshot. If interface enumeration fails, a best-effort fallback based on a
   * UDP socket connection is used to determine a single outward-facing address.
   *
   * @return {@code true} if the snapshot changed compared to the previous pass
   */
  protected synchronized boolean checkpoint() {
    List<InetAddress> addrs = new ArrayList<>();

    Enumeration<NetworkInterface> interfaces = getNetworkInterfacesOrFallback(addrs);
    if (!old && interfaces != null) {
      collectAddressesFromInterfaces(addrs, interfaces);
    }

    InetAddress[] oldAddressList = snapshotAddresses(lastAddressList.get());
    onGetAddresses(addrs);
    lastDetectedTime = System.currentTimeMillis();
    return addressListChanged(oldAddressList, snapshotAddresses(lastAddressList.get()));
  }

  private static InetAddress[] snapshotAddresses(AtomicReferenceArray<InetAddress> addresses) {
    if (addresses == null) return new InetAddress[0];
    InetAddress[] snapshot = new InetAddress[addresses.length()];
    for (int i = 0; i < snapshot.length; i++) {
      snapshot[i] = addresses.get(i);
    }
    return snapshot;
  }

  /** Returns network interfaces or populates a fallback address when enumeration fails. */
  private Enumeration<NetworkInterface> getNetworkInterfacesOrFallback(List<InetAddress> addrs) {
    try {
      return NetworkInterface.getNetworkInterfaces();
    } catch (SocketException e) {
      LOG.error("SocketException trying to detect NetworkInterfaces: {}", e, e);
      addrs.add(oldDetect());
      old = true;
      return null;
    }
  }

  /** Scans all provided interfaces and collects their addresses. */
  private void collectAddressesFromInterfaces(
      List<InetAddress> addrs, Enumeration<NetworkInterface> interfaces) {
    while (interfaces.hasMoreElements()) {
      NetworkInterface iface = interfaces.nextElement();
      if (LOG.isTraceEnabled()) LOG.trace("Scanning NetworkInterface {}", iface.getDisplayName());
      int ifaceMTU = getInterfaceMtu(iface);
      collectInterfaceAddresses(addrs, iface, ifaceMTU);
      if (LOG.isTraceEnabled()) LOG.trace("Finished scanning interface {}", iface.getDisplayName());
    }
    if (LOG.isTraceEnabled()) LOG.trace("Finished scanning interfaces");
  }

  /** Returns the MTU for a non-loopback interface, or {@code 0} if unavailable. */
  private int getInterfaceMtu(NetworkInterface iface) {
    try {
      if (!iface.isLoopback()) {
        int mtu = iface.getMTU();
        if (LOG.isTraceEnabled()) LOG.trace("MTU = {}", mtu);
        return mtu;
      }
    } catch (SocketException e) {
      LOG.error("SocketException trying to retrieve the MTU NetworkInterfaces: {}", e, e);
    }
    return 0; // code for ignoring this MTU
  }

  /**
   * Adds all addresses of an interface to the accumulator, reporting MTU and normalizing IPv6
   * globals by stripping their scope-id.
   */
  private void collectInterfaceAddresses(
      List<InetAddress> addrs, NetworkInterface iface, int ifaceMTU) {
    Enumeration<InetAddress> ee = iface.getInetAddresses();
    while (ee.hasMoreElements()) {
      InetAddress addr = ee.nextElement();
      // telling the NodeIPDetector object about the MTU only if MTU != 0
      // MTU = 0 means error in retrieving it
      // Note: Consider whether reporting MTU for local IPs.
      if (ifaceMTU > 0) detector.reportMTU(ifaceMTU, addr instanceof Inet6Address);

      addrs.add(cleanGlobalIPv6(addr));
      if (LOG.isTraceEnabled())
        LOG.trace("Adding address {} from {}", addr, iface.getDisplayName());
    }
  }

  /** Returns {@code addr} with its IPv6 scope-id removed when the address is global. */
  private InetAddress cleanGlobalIPv6(InetAddress addr) {
    if ((addr instanceof Inet6Address)
        && !(addr.isLinkLocalAddress() || IPUtil.isSiteLocalAddress(addr))) {
      try {
        // strip scope_id from global addresses
        return InetAddress.getByAddress(addr.getAddress());
      } catch (UnknownHostException _) {
        // ignore/impossible
      }
    }
    return addr;
  }

  /**
   * Compares two address arrays ignoring order.
   *
   * <p>{@code null} and empty arrays are treated differently: {@code null} indicates that no
   * addresses were available at all, whereas an empty array indicates an empty but known snapshot.
   */
  private boolean addressListChanged(InetAddress[] oldList, InetAddress[] newList) {
    if (oldList == null) return newList != null;
    if (oldList == newList) return false;
    if (oldList.length != newList.length) return true;
    InetAddress[] a = Arrays.copyOf(oldList, oldList.length);
    InetAddress[] b = Arrays.copyOf(newList, newList.length);
    Arrays.sort(a, InetAddressComparator.COMPARATOR);
    Arrays.sort(b, InetAddressComparator.COMPARATOR);
    return !Arrays.deepEquals(a, b);
  }

  /**
   * Fallback address discovery used when interface enumeration fails.
   *
   * <p>Creates a UDP socket and "connects" it to a well-known DNS host. No packets are sent, but
   * the OS selects a local address for the socket which reveals our outward-facing address.
   *
   * @return the local address chosen by the OS, or {@code null} on failure
   */
  protected InetAddress oldDetect() {
    boolean shouldLog = LOG.isTraceEnabled();
    if (shouldLog) LOG.trace("Running old style detection code");
    DatagramSocket ds = null;
    try {
      try {
        ds = new DatagramSocket();
      } catch (SocketException e) {
        LOG.error("SocketException", e);
        return null;
      }

      // This does not transfer any data. Use a documentation IPv4 address
      // (RFC 5737 TEST-NET-1: 192.0.2.0/24) so no DNS is required, and no
      // real host is contacted. The OS still performs a route lookup to
      // choose the local source address.
      try {
        ds.connect(InetAddress.getByName("192.0.2.1"), 53);
      } catch (UnknownHostException ex) {
        LOG.error("UnknownHostException", ex);
        return null;
      }
      return ds.getLocalAddress();
    } finally {
      if (ds != null) {
        ds.close();
      }
    }
  }

  /**
   * Filters and stores the list of detected addresses.
   *
   * <p>Wildcard (0.0.0.0) and multicast addresses are dropped. Link-local, loopback, and site-local
   * addresses are retained so that higher layers can decide how to handle them. ISATAP-style IPv6
   * addresses are filtered out.
   *
   * @param addrs a mutable list of addresses produced by {@link #checkpoint()}
   */
  protected void onGetAddresses(List<InetAddress> addrs) {
    List<InetAddress> output = new ArrayList<>();
    if (LOG.isTraceEnabled())
      LOG.trace("onGetAddresses found {} potential addresses)", addrs.size());

    if (addrs.isEmpty()) {
      LOG.error("No addresses found!");
      lastAddressList.set(null);
      return;
    }

    for (InetAddress addr : addrs) {
      if (addr == null) continue;
      if (LOG.isTraceEnabled()) LOG.trace("Address: {}", addr);
      if (shouldInclude(addr)) {
        output.add(addr);
      }
    }

    lastAddressList.set(new AtomicReferenceArray<>(output.toArray(new InetAddress[0])));
  }

  /** Returns {@code true} when an address should be kept in the snapshot. */
  private boolean shouldInclude(InetAddress i) {
    if (i.isAnyLocalAddress()) {
      return false; // Wildcard address, 0.0.0.0, ignore.
    } else if (i.isLinkLocalAddress() || i.isLoopbackAddress() || i.isSiteLocalAddress()) {
      // Will be filtered out later if necessary.
      return true;
    } else if (i.isMulticastAddress()) {
      return false; // Ignore
    }
    // Ignore ISATAP addresses
    // @see http://archives.freenetproject.org/message/20071129.220955.ac2a2a36.en.html
    // Note: AddressIdentifier.isAnISATAPIPv6Address(i.toString()) relies on the string form, which
    // may include a leading host or '/'. If we ever tighten detection, consider using
    // i.getHostAddress() instead to avoid environment-dependent false negatives. Behavior is kept
    // unchanged here.
    return !AddressIdentifier.isAnISATAPIPv6Address(i.toString());
  }

  /**
   * Periodically performs IP detection on the caller's thread.
   *
   * <p>The loop waits up to {@link #interval} milliseconds between ticks. On each tick it calls
   * {@link #checkpoint()}, and if the detected address set changed, it invokes {@code
   * detector.redetectAddress()}.
   *
   * <p>Why not ScheduledExecutorService?
   *
   * <ul>
   *   <li>Threading contract: running on a scheduler would execute callbacks on a different thread
   *       and break the single-threaded executor serialization expected by {@code NodeIPDetector},
   *       risking visibility and ordering issues. Keeping the work on the caller's thread preserves
   *       that contract.
   *   <li>Lifecycle: the default scheduler uses a non-daemon worker which can keep the JVM alive if
   *       not shut down explicitly.
   *   <li>Robustness: with a scheduler, any uncaught error in the task suppresses further
   *       executions. This loop explicitly catches {@link AssertionError} and {@link Exception} to
   *       continue running while still honoring interruption.
   * </ul>
   *
   * <p>The loop terminates when the current thread is interrupted; the interrupt status is
   * preserved.
   */
  @Override
  public void run() {
    while (!Thread.currentThread().isInterrupted()) {
      try {
        // Sleep between ticks without spawning extra threads.
        synchronized (this) {
          this.wait(interval);
        }
        if (checkpoint()) {
          detector.redetectAddress();
        }
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        break;
      } catch (AssertionError ae) {
        // Keep periodic detection alive when assertions are enabled.
        LOG.error("Caught {}", ae, ae);
      } catch (Exception e) {
        LOG.error("Caught {}", e, e);
      }
    }
  }
}
