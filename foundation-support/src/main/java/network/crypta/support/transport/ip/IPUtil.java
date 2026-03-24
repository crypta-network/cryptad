package network.crypta.support.transport.ip;

import java.net.Inet6Address;
import java.net.InetAddress;

/**
 * Utility methods for IP address classification used by the transport layer.
 *
 * <p>These helpers provide small, side-effect-free checks for IPv4/IPv6 addresses. Where older JDK
 * behavior is incomplete for IPv6 site-local detection, this class applies the intended ranges. All
 * methods are thread-safe.
 */
public class IPUtil {

  private IPUtil() {}

  /**
   * Returns whether the address should be treated as site/unique-local.
   *
   * <p>For IPv6 addresses, this replaces the outdated {@link Inet6Address#isSiteLocalAddress()}
   * behavior in some older JDKs by recognizing both Unique Local Addresses (ULAs) ({@code
   * fc00::/7}) and the deprecated site-local range ({@code fec0::/10}). For non-IPv6 addresses, the
   * method delegates to {@link InetAddress#isSiteLocalAddress()}.
   *
   * <p>This classification is used when deciding whether an address is local-only to publish
   * noderefs and similar metadata.
   *
   * @param i the address to test; must not be {@code null}
   * @return {@code true} if the address is considered site-local (or unique-local), otherwise
   *     {@code false}
   * @throws NullPointerException if {@code i} is {@code null}
   */
  public static boolean isSiteLocalAddress(InetAddress i) {
    if (i instanceof Inet6Address) {
      byte[] addr = i.getAddress();
      // The JVM returns 16 bytes for IPv6 addresses; assert to document the invariant.
      assert (addr.length == 128 / 8);
      // IPv6-mapped IPv4 addresses are treated as IPv6 here; callers should normalize if they
      // require IPv4-specific handling.
      return ((addr[0] & (byte) 0xfe) == (byte) 0xfc
          /* Unique local (ULA): fc00::/7 */ )
          || (addr[0] == (byte) 0xfe && (addr[1] & (byte) 0xc0) == (byte) 0xc0
          /* Deprecated site-local: fec0::/10 */ );
    }
    return i.isSiteLocalAddress();
  }

  /**
   * Determines whether an address is suitable for publication (e.g., in a node reference).
   *
   * <p>The check rejects wildcard addresses ({@code 0.0.0.0} or {@code ::}), multicast addresses,
   * and, unless explicitly allowed, local-only addresses (loopback, link-local, and
   * site/unique-local as determined by {@link #isSiteLocalAddress(InetAddress)}).
   *
   * <p>Additional IPv4 rule: addresses whose first octet is zero ({@code 0.0.0.0/8}) are considered
   * invalid and are rejected. IPv6 addresses are allowed subject to the rules above.
   *
   * @param i the address to test; must not be {@code null}
   * @param includeLocalAddressesInNoderefs when {@code true}, permits loopback, link-local, and
   *     site/unique-local addresses
   * @return {@code true} if the address is acceptable for publication; otherwise {@code false}
   * @throws NullPointerException if {@code i} is {@code null}
   */
  public static boolean isValidAddress(InetAddress i, boolean includeLocalAddressesInNoderefs) {
    if (i.isAnyLocalAddress()) {
      // Wildcard address (0.0.0.0 or ::); never publish.
      return false;
    } else if (i.isLinkLocalAddress() || i.isLoopbackAddress() || isSiteLocalAddress(i)) {
      // Treat local-only addresses as publishable only if explicitly allowed.
      return includeLocalAddressesInNoderefs;
    } else if (i.isMulticastAddress()) {
      // Multicast addresses are not suitable for node references.
      return false;
    } else {
      byte[] ipAddressBytes = i.getAddress();
      return ipAddressBytes.length != 4
          || ipAddressBytes[0] != 0; // Reject IPv4 0.0.0.0/8; reserved since RFC 790.
      // Java networking generally refuses such addresses as well.
    }
  }
}
