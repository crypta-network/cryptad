package network.crypta.support.io;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Comparator;
import java.util.Objects;
import java.util.function.Predicate;
import network.crypta.support.Fields;
import network.crypta.support.LRUCache;

import static network.crypta.node.NodeStats.DEFAULT_MAX_PING_TIME;

/**
 * Comparator for {@link InetAddress} values that prefers IPv6 over IPv4 and applies
 * scope/reachability heuristics to produce a stable total ordering.
 *
 * <p>Ordering (most- to least-preferred):
 *
 * <ol>
 *   <li>Non-{@code null} before {@code null} (i.e., {@code null}s sort last).
 *   <li>Not wildcard (“any local”) before wildcard (see {@link InetAddress#isAnyLocalAddress()}).
 *   <li>Not loopback before loopback (see {@link InetAddress#isLoopbackAddress()}).
 *   <li>Not link-local before link-local (see {@link InetAddress#isLinkLocalAddress()}).
 *   <li>Site-local addresses that are reachable (per {@link #isReachable(InetAddress)}) before
 *       site-local addresses that are not reachable.
 *   <li>IPv6 ({@link Inet6Address}) before IPv4.
 *   <li>Tie-break by {@link Object#hashCode()} and finally by raw address bytes ({@link
 *       InetAddress#getAddress}) using {@link Fields#compareBytes(byte[], byte[])} to ensure a
 *       total order.
 * </ol>
 *
 * <p>Reachability checks use {@link InetAddress#isReachable(int)} with the default node ping time
 * (see {@link network.crypta.node.NodeStats#DEFAULT_MAX_PING_TIME}) and are cached to avoid
 * repeated probes during sorting.
 *
 * <p>Side effects and performance:
 *
 * <ul>
 *   <li>{@link #compare(InetAddress, InetAddress)} may perform a network probe on the first
 *       encounter of a given site-local address; the result is cached for a bounded time.
 *   <li>Failures and timeouts are treated as “not reachable”.
 * </ul>
 *
 * <p>Thread-safety: instances keep a mutable cache. The underlying map synchronizes its operations,
 * but this class does not add external synchronization. Callers that require strict guarantees
 * should avoid sharing instances across threads or guard access externally.
 *
 * @author toad
 */
public class InetAddressIpv6FirstComparator implements Comparator<InetAddress> {

  // Cache reachability to avoid repeated isReachable() calls during O(N log N) sorts.
  // Size ~1000 entries; TTL ~300_000 ms (5 minutes). Keys use InetAddress.hashCode().
  LRUCache<Integer, Boolean> reachabilityCache = new LRUCache<>(1000, 300000);

  // Ordered chain implementing the preference rules described in the class Javadoc.
  private final Comparator<InetAddress> innerComparator =
      prefer(Objects::nonNull)
          .thenComparing(preferNot(InetAddress::isAnyLocalAddress))
          .thenComparing(preferNot(InetAddress::isLoopbackAddress))
          .thenComparing(preferNot(InetAddress::isLinkLocalAddress))
          .thenComparing(prefer(this::isReachableSiteLocalAddress))
          .thenComparing(prefer(Inet6Address.class::isInstance))
          .thenComparingInt(Objects::hashCode)
          .thenComparing(InetAddress::getAddress, Fields::compareBytes);

  // Site-local addresses move up in ordering only when they are currently reachable.
  private boolean isReachableSiteLocalAddress(InetAddress inetAddress) {
    return inetAddress.isSiteLocalAddress() && isReachable(inetAddress);
  }

  public static final Comparator<InetAddress> COMPARATOR = new InetAddressIpv6FirstComparator();

  /**
   * Compares two addresses according to the rules documented for this class.
   *
   * <p>Special cases:
   *
   * <ul>
   *   <li>Returns {@code 0} when both references are equal (including both {@code null}).
   *   <li>When one argument is {@code null}, the non-{@code null} value is ordered first.
   * </ul>
   *
   * <p>May perform a reachability probe for site-local addresses and therefore may block up to
   * {@link network.crypta.node.NodeStats#DEFAULT_MAX_PING_TIME} milliseconds on a first encounter;
   * results are cached to mitigate repeated calls.
   *
   * @param arg0 the first address; may be {@code null}
   * @param arg1 the second address; may be {@code null}
   * @return a negative value, zero, or a positive value as the first argument is ordered before,
   *     equal to, or after the second
   */
  @Override
  public int compare(InetAddress arg0, InetAddress arg1) {
    if (Objects.equals(arg0, arg1)) {
      return 0;
    }
    return innerComparator.compare(arg0, arg1);
  }

  private boolean isReachable(InetAddress inetAddress) {
    int hashCode = inetAddress.hashCode();
    Boolean reachable = reachabilityCache.get(hashCode);
    if (reachable == null) {
      try {
        reachable = inetAddress.isReachable((int) DEFAULT_MAX_PING_TIME);
      } catch (IOException _) {
        reachable = false;
      }
      reachabilityCache.put(hashCode, reachable);
    }
    return reachable;
  }

  private Comparator<InetAddress> prefer(Predicate<InetAddress> pred) {
    return (arg0, arg1) -> Boolean.compare(!pred.test(arg0), !pred.test(arg1));
  }

  /** Inverted {@link #prefer(Predicate)}; explicit inversion keeps the intent clear. */
  private Comparator<InetAddress> preferNot(Predicate<InetAddress> pred) {
    return prefer(pred).reversed();
  }
}
