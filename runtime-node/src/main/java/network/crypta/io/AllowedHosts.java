package network.crypta.io;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import network.crypta.io.AddressIdentifier.AddressType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses and evaluates an allow list for inbound IP connections.
 *
 * <p>This utility converts a comma-separated list of address rules into a set of {@link
 * AddressMatcher} instances and answers whether a given {@link InetAddress} is permitted. Supported
 * rule forms are:
 *
 * <ul>
 *   <li>IPv4 literal, optional mask:
 *       <ul>
 *         <li>Exact address: {@code 192.168.1.2}
 *         <li>Dotted mask: {@code 192.168.1.0/255.255.255.0}
 *         <li>CIDR length: {@code 192.168.1.0/24}
 *       </ul>
 *   <li>IPv6 literal, optional mask:
 *       <ul>
 *         <li>Exact address: {@code 2001:db8::1}
 *         <li>Prefix length: {@code 2001:db8::/64}
 *         <li>Explicit mask address: {@code 2001:db8::/ffff:ffff:ffff:ffff::}
 *       </ul>
 *   <li>Wildcard: a single asterisk ({@code *}) matches any address.
 * </ul>
 *
 * <p>If the input string is {@code null} or empty, the allow list defaults to loopback addresses
 * defined by {@link NetworkInterface#DEFAULT_BIND_TO} (for example, {@code 127.0.0.1} and {@code
 * ::1}). Hostnames are not accepted; tokens must be address literals. Invalid tokens are ignored
 * and logged.
 *
 * <p>Thread-safety: instances are safe for concurrent use. Mutating operations ({@link
 * #setAllowedHosts(String)}) and queries ({@link #allowed(InetAddress)}, {@link
 * #getAllowedHosts()}) are synchronized on {@code this}. Updates replace the internal matcher list
 * atomically with respect to readers.
 */
public class AllowedHosts {
  private static final Logger LOG = LoggerFactory.getLogger(AllowedHosts.class);

  // Current matcher set evaluated by allowed(...). The list reference is stable; contents are
  // replaced under synchronization by setAllowedHosts(...).
  protected final List<AddressMatcher> addressMatchers = new ArrayList<>();

  /**
   * Creates an instance from a comma-separated rule list.
   *
   * <p>When {@code allowedHosts} is {@code null} or empty, the list is initialized from {@link
   * NetworkInterface#DEFAULT_BIND_TO} (loopback-only). See the class documentation for supported
   * token forms.
   *
   * @param allowedHosts comma-separated rules (IPv4/IPv6 with optional masks, or {@code "*"}).
   */
  public AllowedHosts(String allowedHosts) {
    setAllowedHosts(allowedHosts);
  }

  /**
   * Replaces the current allow list with {@code allowedHosts}.
   *
   * <p>The change takes effect atomically for subsequent calls to {@link #allowed(InetAddress)}. If
   * the argument is {@code null} or empty, the list falls back to {@link
   * NetworkInterface#DEFAULT_BIND_TO}. Tokens that are not IPv4/IPv6 literals or {@code "*"} are
   * ignored; a log entry is written for each invalid token.
   *
   * @param allowedHosts comma-separated rules; see class documentation for syntax.
   */
  public synchronized void setAllowedHosts(String allowedHosts) {
    String allowedHostsValue =
        (allowedHosts == null || allowedHosts.isEmpty())
            ? NetworkInterface.DEFAULT_BIND_TO
            : allowedHosts;
    StringTokenizer allowedHostsTokens = new StringTokenizer(allowedHostsValue, ",");
    List<AddressMatcher> newAddressMatchers = new ArrayList<>();
    while (allowedHostsTokens.hasMoreTokens()) {
      String allowedHost = allowedHostsTokens.nextToken().trim();
      String hostname = allowedHost;
      int slashIndex = allowedHost.indexOf('/');
      if (slashIndex != -1) {
        hostname = allowedHost.substring(0, slashIndex);
      }
      AddressType addressType = AddressIdentifier.getAddressType(hostname);
      if (addressType == AddressType.IPV4) {
        newAddressMatchers.add(new Inet4AddressMatcher(allowedHost));
      } else if (addressType == AddressType.IPV6) {
        newAddressMatchers.add(new Inet6AddressMatcher(allowedHost));
      } else if ("*".equals(allowedHost)) {
        newAddressMatchers.add(new EverythingMatcher());
      } else {
        LOG.error("Ignoring invalid allowedHost: {}", allowedHost);
      }
    }
    this.addressMatchers.clear();
    this.addressMatchers.addAll(newAddressMatchers);
  }

  /**
   * Returns whether {@code clientAddress} matches at least one rule.
   *
   * <p>Evaluation stops at the first matching rule. If the configuration contains the wildcard
   * ({@code *}), this method always returns {@code true}. Non-IPv4/IPv6 addresses are rejected by
   * family-specific matchers and therefore yield {@code false} unless the wildcard is present.
   *
   * @param clientAddress address to test; never modified by this method.
   * @return {@code true} if permitted; {@code false} otherwise.
   */
  public synchronized boolean allowed(InetAddress clientAddress) {
    for (AddressMatcher matcher : addressMatchers) {
      if (matcher.matches(clientAddress)) return true;
    }
    return false;
  }

  /**
   * Returns the current configuration as a single string.
   *
   * <p>If a wildcard rule is present, returns {@code "*"}. Otherwise, returns a comma-separated
   * concatenation of each matcher's {@link AddressMatcher#getHumanRepresentation()}.
   *
   * @return canonicalized rule list suitable for logs and diagnostics; never {@code null}.
   */
  public synchronized String getAllowedHosts() {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < addressMatchers.size(); i++) {
      AddressMatcher matcher = addressMatchers.get(i);
      if (matcher instanceof EverythingMatcher) return "*";
      if (i != 0) sb.append(',');
      sb.append(matcher.getHumanRepresentation());
    }
    return sb.toString();
  }
}
