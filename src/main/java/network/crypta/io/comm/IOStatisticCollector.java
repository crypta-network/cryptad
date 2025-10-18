package network.crypta.io.comm;

import java.net.InetAddress;
import network.crypta.support.transport.ip.IPUtil;

/**
 * Collects aggregate counts of outbound and inbound network traffic.
 *
 * <p>The collector tracks total bytes sent to and received from remote peers. Traffic attributed to
 * local addresses (loopback, link-local, or site-local as determined by {@link InetAddress} and
 * {@link IPUtil}) is intentionally excluded so that statistics reflect external I/O only.
 *
 * <p>Thread-safety: All mutating operations synchronize on {@code this}; reads use a synchronized
 * snapshot. Methods are safe for concurrent use from multiple threads.
 *
 * <p>Units: bytes. Counters are monotonic for the life of the instance.
 */
public class IOStatisticCollector {
  private long totalBytesIn;
  private long totalBytesOut;

  /**
   * Records bytes received from a remote address.
   *
   * <p>Calls for local addresses are ignored. Zero or negative byte counts are ignored.
   *
   * @param addr the peer address; local/link-local/loopback/site-local are ignored
   * @param bytes number of bytes received; values {@code <= 0} are ignored
   */
  public void reportReceivedBytes(InetAddress addr, int bytes) {
    if (isLocal(addr) || bytes <= 0) {
      return;
    }
    // Synchronize to ensure atomic update and proper memory visibility across threads.
    synchronized (this) {
      totalBytesIn += bytes;
    }
  }

  /**
   * Records bytes sent to a remote address.
   *
   * <p>Calls for local addresses are ignored. Zero or negative byte counts are ignored.
   *
   * @param addr the peer address; local/link-local/loopback/site-local are ignored
   * @param bytes number of bytes sent; values {@code <= 0} are ignored
   */
  public void reportSentBytes(InetAddress addr, int bytes) {
    if (isLocal(addr) || bytes <= 0) {
      return;
    }
    // Synchronize to ensure atomic update and proper memory visibility across threads.
    synchronized (this) {
      totalBytesOut += bytes;
    }
  }

  /**
   * Returns a snapshot of the total bytes sent and received.
   *
   * <p>The returned array is a new two-element instance where index {@code 0} is total outbound
   * bytes (sent) and index {@code 1} is total inbound bytes (received). The values reflect a
   * moment-in-time snapshot and are not live views.
   *
   * @return {@code new long[] { totalBytesOut, totalBytesIn }}; never {@code null}
   */
  public synchronized long[] getTotalIO() {
    return new long[] {totalBytesOut, totalBytesIn};
  }

  // Treat link-local, loopback, and site-local addresses as local; exclude them from statistics so
  // counters represent external network I/O only.
  private static boolean isLocal(InetAddress address) {
    return address.isLinkLocalAddress()
        || address.isLoopbackAddress()
        || IPUtil.isSiteLocalAddress(address);
  }
}
