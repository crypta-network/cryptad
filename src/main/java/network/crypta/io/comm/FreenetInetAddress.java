package network.crypta.io.comm;

import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import network.crypta.io.AddressIdentifier;
import network.crypta.support.io.InetAddressIpv6FirstComparator;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import network.crypta.support.transport.ip.HostnameUtil;
import network.crypta.support.transport.ip.IPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Immutable-or-lazy network endpoint reference that can be backed by a hostname or a resolved IP
 * address.
 *
 * <p>When constructed from an {@link InetAddress}, the address is primary and immutable; when
 * constructed from a hostname, the hostname is primary and DNS resolution occurs lazily on first
 * access (or explicitly via handshake). This design helps nodes that use dynamic DNS.
 *
 * <p>Equality propagates the resolved IP between instances when the primary hostname matches (case
 * insensitive). Hostname never propagates. The hash code depends solely on the primary identity:
 * hostname if present, otherwise the IP address. As a result, inserting instances into hashed
 * collections is safe: neither {@link #equals(Object)} nor {@link #getAddress()} will change the
 * hash code of an existing instance.
 *
 * <p>Important behavior: an instance that has only an IP (no hostname) is not equal to another
 * instance that has a hostname, even when both resolve to the same numeric address. Call {@link
 * #dropHostname()} to compare by IP only, or compare the underlying {@link InetAddress} values
 * directly when appropriate.
 *
 * <p>DNS lookups are performed using the platform caches (as configured in the JVM). This class
 * does not implement its own caching policy beyond storing the last resolved address when helpful
 * for handshakes.
 */
public class FreenetInetAddress {
  private static final Logger LOG = LoggerFactory.getLogger(FreenetInetAddress.class);

  // no static initialization required

  // hostname - only set if we were created with a hostname
  // and not an address
  private final String hostname;
  private InetAddress address;

  /**
   * Constructs an instance by reading from a binary stream produced by {@link
   * #writeToDataOutputStream(DataOutputStream)}.
   *
   * <p>Format: one type byte ({@code 0} for IPv4, {@code 255} for IPv6), followed by the raw IP
   * bytes (4 or 16), then a UTF string containing the hostname or the empty string when absent.
   *
   * @param dis data source to read from
   * @throws IOException if the input cannot be read or the type byte is unknown
   */
  public FreenetInetAddress(DataInput dis) throws IOException {
    int firstByte = dis.readUnsignedByte();
    byte[] ba;
    switch (firstByte) {
      case 255 -> {
        if (LOG.isDebugEnabled()) LOG.debug("New format IPv6 address");
        ba = new byte[16];
        dis.readFully(ba);
      }
      case 0 -> {
        if (LOG.isDebugEnabled()) LOG.debug("New format IPv4 address");
        ba = new byte[4];
        dis.readFully(ba);
      }
      default ->
          throw new IOException(
              "Unknown type byte (old form? corrupt stream? too short/long prev field?): "
                  + firstByte);
    }
    address = InetAddress.getByAddress(ba);
    String name = null;
    String s = dis.readUTF();
    if (!s.isEmpty()) name = s;
    hostname = name;
  }

  /**
   * Constructs an instance by reading from a binary stream and optionally validating hostname
   * syntax.
   *
   * <p>This constructor also accepts the legacy IPv4 format where the first byte is part of the
   * address (no leading type byte). Newer encodings use a leading type byte as described for {@link
   * #FreenetInetAddress(DataInput)}.
   *
   * @param dis data source to read from
   * @param checkHostnameOrIPSyntax when {@code true}, validates the parsed hostname using {@link
   *     HostnameUtil#isValidHostname(String, boolean)}
   * @throws HostnameSyntaxException if validation is requested and the hostname is not valid
   * @throws IOException if the input cannot be read
   */
  public FreenetInetAddress(DataInput dis, boolean checkHostnameOrIPSyntax)
      throws HostnameSyntaxException, IOException {
    int firstByte = dis.readUnsignedByte();
    byte[] ba;
    switch (firstByte) {
      case 255 -> {
        if (LOG.isDebugEnabled()) LOG.debug("New format IPv6 address");
        ba = new byte[16];
        dis.readFully(ba);
      }
      case 0 -> {
        if (LOG.isDebugEnabled()) LOG.debug("New format IPv4 address");
        ba = new byte[4];
        dis.readFully(ba);
      }
      default -> {
        // Old format IPv4 address
        ba = new byte[4];
        ba[0] = (byte) firstByte;
        dis.readFully(ba, 1, 3);
      }
    }
    address = InetAddress.getByAddress(ba);
    String name = null;
    String s = dis.readUTF();
    if (!s.isEmpty()) name = s;
    hostname = name;
    if (checkHostnameOrIPSyntax
        && hostname != null
        && !HostnameUtil.isValidHostname(hostname, true)) throw new HostnameSyntaxException();
  }

  /**
   * Constructs an instance from a resolved IP address.
   *
   * <p>The IP address becomes the primary identity. No hostname is stored or looked up.
   *
   * @param address resolved IP address; must not be {@code null}
   */
  public FreenetInetAddress(InetAddress address) {
    this.address = address;
    hostname = null;
  }

  /**
   * Constructs an instance from a textual host which may be a DNS name or a literal IP address.
   *
   * <p>If {@code host} parses as an IP address, the instance is IP-primary. Otherwise the instance
   * is hostname-primary and resolution is deferred until required.
   *
   * @param host DNS name or literal IP; leading slashes are trimmed (e.g., {@code "/1.2.3.4"})
   * @param allowUnknown reserved for compatibility; does not alter behavior here
   * @throws UnknownHostException if the literal address cannot be parsed
   */
  public FreenetInetAddress(String host, boolean allowUnknown) throws UnknownHostException {
    InitResult r = computeInitFromHost(host, allowUnknown);
    this.address = r.addr;
    this.hostname = r.host;
    // we're created with a hostname so delay the lookup of the address
    // until it's needed to work better with dynamic DNS hostnames
  }

  /**
   * Constructs an instance from a textual host with optional hostname syntax validation.
   *
   * @param host DNS name or literal IP; leading slashes are trimmed
   * @param allowUnknown reserved for compatibility; does not alter behavior here
   * @param checkHostnameOrIPSyntax when {@code true}, validates {@code host} if it is a hostname
   * @throws HostnameSyntaxException if validation is requested and the hostname is not valid
   * @throws UnknownHostException if the literal address cannot be parsed
   */
  public FreenetInetAddress(String host, boolean allowUnknown, boolean checkHostnameOrIPSyntax)
      throws HostnameSyntaxException, UnknownHostException {
    InitResult r = computeInitFromHost(host, allowUnknown);
    this.address = r.addr;
    this.hostname = r.host;
    if (checkHostnameOrIPSyntax
        && this.hostname != null
        && !HostnameUtil.isValidHostname(this.hostname, true)) throw new HostnameSyntaxException();
    // we're created with a hostname so delay the lookup of the address
    // until it's needed to work better with dynamic DNS hostnames
  }

  private record InitResult(InetAddress addr, String host) {}

  private InitResult computeInitFromHost(String host, boolean allowUnknown)
      throws UnknownHostException {
    InetAddress addr = null;
    String h = host;
    if (h != null) {
      if (h.startsWith("/")) h = h.substring(1);
      h = h.trim();
    }
    AddressIdentifier.AddressType addressType = AddressIdentifier.getAddressType(h);
    if (LOG.isTraceEnabled())
      LOG.trace(
          "Address type of '{}' appears to be '{}' (allowUnknown={})",
          h,
          addressType,
          allowUnknown);
    if (addressType != AddressIdentifier.AddressType.OTHER) {
      // Is an IP address
      addr = InetAddress.getByName(h);
      if (LOG.isDebugEnabled())
        LOG.debug("host is '{}' and addr.getHostAddress() is '{}'", h, addr.getHostAddress());
      if (addr != null) {
        h = null;
      }
    }
    if (addr == null && LOG.isTraceEnabled()) LOG.trace("'{}' does not look like an IP address", h);
    return new InitResult(addr, h);
  }

  /**
   * Compares for equality using relaxed rules.
   *
   * <p>Behavior: - When this instance is hostname-primary, hostnames must match ignoring case. If
   * either side has a resolved IP, it is propagated to the other. If both have addresses, they must
   * match. - When this instance is IP-primary, only the numeric addresses are compared.
   *
   * @param other address to compare
   * @return {@code true} when considered equal under the relaxed rules
   */
  public boolean laxEquals(FreenetInetAddress other) {
    if (hostname != null) {
      return laxEqualsWhenThisHasHostname(other);
    }
    return addressesEqual(address, other.address);
  }

  private boolean laxEqualsWhenThisHasHostname(FreenetInetAddress other) {
    if (other.hostname == null) {
      return addressBasedComparisonWhenOtherHasNoHostname(other);
    }
    if (!hostname.equalsIgnoreCase(other.hostname)) {
      return false;
    }
    propagateAddresses(other);
    return (other.address == null) || (address == null) || other.address.equals(address);
  }

  private boolean addressBasedComparisonWhenOtherHasNoHostname(FreenetInetAddress other) {
    if (address == null) return false; // No basis for comparison.
    if (other.address != null) {
      return address.equals(other.address);
    }
    return false;
  }

  private void propagateAddresses(FreenetInetAddress other) {
    if (address != null && other.address == null) other.address = address;
    if (other.address != null && address == null) address = other.address;
  }

  private static boolean addressesEqual(InetAddress a, InetAddress b) {
    return a != null && a.equals(b);
  }

  /**
   * Compares for equality consistent with the propagation semantics described in the class
   * documentation.
   *
   * <p>When hostnames are present on both sides, they must match ignoring case; the resolved IP may
   * be propagated between instances. When neither side has a hostname, equality falls back to the
   * numeric IP address.
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof FreenetInetAddress addr)) {
      return false;
    }
    if (hostname != null) {
      if (addr.hostname == null) return false;
      if (!hostname.equalsIgnoreCase(addr.hostname)) {
        return false;
      }
      // Now that we know we have the same hostname, we can propagate the IP.
      if ((address != null) && (addr.address == null)) addr.address = address;
      if ((addr.address != null) && (address == null)) address = addr.address;
      // Except if we actually do have two different looked-up IPs!
      return addr.address == null || addr.address.equals(address);
      // Equal.
    }
    if (addr.hostname != null) return false;

    // No hostname, go by address.
    return address.equals(addr.address);
  }

  /**
   * Compares for equality using strict rules useful for peer identity checks.
   *
   * <p>When hostnames are present on both sides, the behavior matches {@link #equals(Object)}. When
   * neither side has a hostname, strict comparison requires the reverse hostnames derived from the
   * numeric IPs to match ignoring case (see {@link #getHostName(InetAddress)}).
   *
   * @param addr address to compare
   * @return {@code true} if equal under strict comparison
   */
  public boolean strictEquals(FreenetInetAddress addr) {
    if (hostname != null) {
      if (addr.hostname == null) return false;
      if (!hostname.equalsIgnoreCase(addr.hostname)) {
        return false;
      }
      // Now that we know we have the same hostname, we can propagate the IP.
      if ((address != null) && (addr.address == null)) addr.address = address;
      if ((addr.address != null) && (address == null)) address = addr.address;
      // Except if we actually do have two different looked-up IPs!
      return addr.address == null || addr.address.equals(address);
      // Equal.
    } else if (addr.hostname != null /* && hostname == null */) {
      return false;
    }

    // No hostname, go by address.
    String reverseHostNameISee = getHostName(address);
    String reverseHostNameTheySee = getHostName(addr.address);
    return reverseHostNameISee != null
        && reverseHostNameISee.equalsIgnoreCase(reverseHostNameTheySee);
  }

  /**
   * Returns the resolved IP address, performing a DNS lookup if needed.
   *
   * <p>If an address was resolved previously, it is returned without issuing a new lookup.
   *
   * @return resolved address or {@code null} if resolution fails
   */
  public InetAddress getAddress() {
    return getAddress(true);
  }

  /**
   * Returns the resolved IP address and optionally performs DNS resolution.
   *
   * @param doDNSRequest when {@code true}, resolve the hostname if not yet resolved; when {@code
   *     false}, return the cached value or {@code null}
   * @return resolved address or {@code null} when not cached and lookups are disabled
   */
  public InetAddress getAddress(boolean doDNSRequest) {
    if (address != null) {
      return address;
    } else {
      if (!doDNSRequest) return null;
      InetAddress addr = getHandshakeAddress();
      if (addr != null) {
        this.address = addr;
      }
      return addr;
    }
  }

  /**
   * Returns the IP used for handshakes, forcing a fresh DNS resolution when hostname-primary.
   *
   * <p>This method bypasses a previously cached value if a hostname is present so that dynamic DNS
   * updates are observed during connection attempts.
   *
   * @return the latest resolved address or {@code null} if the hostname cannot be resolved
   */
  public InetAddress getHandshakeAddress() {
    if (shouldReturnCachedAddress()) {
      if (LOG.isDebugEnabled()) LOG.debug("hostname is null, returning {}", address);
      return address;
    }
    return lookupHandshakeAddress();
  }

  private boolean shouldReturnCachedAddress() {
    // During handshakes only return the cached value when IP is primary; a hostname may have
    // changed due to dynamic DNS.
    return (address != null) && (hostname == null);
  }

  private InetAddress lookupHandshakeAddress() {
    if (LOG.isDebugEnabled()) LOG.debug("Looking up '{}' in DNS", hostname);
    /*
     * Peers are constructed from an address once a
     * handshake has been completed, so this lookup
     * will only be performed during a handshake
     * (this method should normally only be called
     * from PeerNode.getHandshakeIPs() and once
     * each connection from this.getAddress()
     * otherwise) - it doesn't mean we perform a
     * DNS lookup with every packet we send.
     */
    InetAddress[] addresses = resolveAllByName(hostname);
    if (addresses.length == 0) return null;
    if (addresses.length > 1) cacheFirstSortedAddress(addresses);
    return addresses[0];
  }

  private InetAddress[] resolveAllByName(String host) {
    try {
      return InetAddress.getAllByName(host);
    } catch (UnknownHostException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("DNS said hostname '{}' is an unknown host, returning null", host);
      return new InetAddress[0];
    }
  }

  private void cacheFirstSortedAddress(InetAddress[] addresses) {
    /* Prefer IPv6 when multiple answers exist to encourage IPv6 connectivity. */
    Arrays.sort(addresses, InetAddressIpv6FirstComparator.COMPARATOR);
    /* Cache the first answer to avoid immediate re-resolution on subsequent calls. */
    try {
      this.address = InetAddress.getByAddress(addresses[0].getAddress());
      if (LOG.isDebugEnabled()) LOG.debug("Setting address to {}", address);
    } catch (UnknownHostException e) {
      // Should not happen for valid IPv4/IPv6 byte arrays; skip caching if it does.
      if (LOG.isWarnEnabled())
        LOG.warn(
            "Failed to cache first sorted address for hostname '{}': {}", hostname, e.toString());
    }
  }

  /**
   * Computes a hash code consistent with the equality contract.
   *
   * <p>When a hostname is present it is the sole contributor; otherwise the numeric address is
   * used.
   */
  @Override
  public int hashCode() {
    if (hostname != null) {
      return hostname.hashCode(); // Was set at creation, so it can safely be used here.
    } else {
      return address.hashCode(); // Can be null, but if so, hostname will be non-null.
    }
  }

  /**
   * Returns a human-friendly representation: hostname when present, otherwise the numeric address.
   */
  @Override
  public String toString() {
    if (hostname != null) {
      return hostname;
    } else {
      return address.getHostAddress();
    }
  }

  /**
   * Returns a string favoring the numeric address when available, otherwise the hostname.
   *
   * @return numeric address or hostname; may be {@code null} when neither is available
   */
  public String toStringPrefNumeric() {
    if (address != null) return address.getHostAddress();
    else return hostname;
  }

  /**
   * Writes this instance to a {@link DataOutputStream} using the current binary encoding.
   *
   * <p>Format: one type byte ({@code 0} for IPv4, {@code 255} for IPv6), followed by the raw IP
   * bytes, then a UTF string of the hostname or the empty string when absent.
   *
   * @param dos destination stream
   * @throws IOException if writing fails or the address cannot be encoded
   */
  public void writeToDataOutputStream(DataOutputStream dos) throws IOException {
    InetAddress addr = this.getAddress();
    if (addr == null) throw new UnknownHostException();
    byte[] data = addr.getAddress();
    if (data.length == 4) dos.write(0);
    else dos.write(255);
    dos.write(data);
    if (hostname != null) dos.writeUTF(hostname);
    else dos.writeUTF("");
  }

  /**
   * Returns the name component of an {@link InetAddress} without performing reverse DNS.
   *
   * <p>Parses the {@code toString()} form ({@code name/address}) and returns the left-hand side. If
   * no name is present, returns {@link InetAddress#getHostAddress()}.
   *
   * @param primaryIPAddress address to read; may be {@code null}
   * @return hostname or numeric address; {@code null} when the input is {@code null}
   */
  public static String getHostName(InetAddress primaryIPAddress) {
    if (primaryIPAddress == null) return null;
    String s = primaryIPAddress.toString();
    String addr = s.substring(0, s.indexOf('/')).trim();
    if (addr.isEmpty()) return primaryIPAddress.getHostAddress();
    else return addr;
  }

  /**
   * Determines whether the address appears routable on the public Internet.
   *
   * <p>If a resolved address is available, the decision delegates to {@link
   * IPUtil#isValidAddress(InetAddress, boolean)}. Otherwise, when {@code lookup} is {@code true}, a
   * resolution attempt is made; when {@code false}, {@code defaultVal} is returned.
   *
   * @param lookup whether to resolve the hostname when no cached address is available
   * @param defaultVal value to return when not resolved and lookups are disabled
   * @param allowLocalAddresses whether RFC 1918/unique-local addresses are considered valid
   * @return {@code true} if the address is considered publicly routable (or allowed locally)
   */
  public boolean isRealInternetAddress(
      boolean lookup, boolean defaultVal, boolean allowLocalAddresses) {
    if (address != null) {
      return IPUtil.isValidAddress(address, allowLocalAddresses);
    } else {
      if (lookup) {
        InetAddress a = getAddress();
        if (a != null) return IPUtil.isValidAddress(a, allowLocalAddresses);
      }
      return defaultVal;
    }
  }

  /**
   * Returns a new instance with the hostname removed, preserving only the resolved IP address.
   *
   * <p>If no address is currently resolved, returns {@code null}. Call {@link #getAddress(boolean)}
   * with {@code true} first when the hostname is primary and resolution is desired.
   *
   * @return a new IP-primary instance, {@code null} when no address is known, or {@code this} when
   *     already IP-primary
   */
  public FreenetInetAddress dropHostname() {
    if (address == null) {
      LOG.debug("dropHostname() called without a resolved address; hostname='{}'", hostname);
      return null;
    }
    if (hostname != null) {
      return new FreenetInetAddress(address);
    } else return this;
  }

  /** Returns whether a non-empty hostname is present. */
  public boolean hasHostname() {
    return hostname != null && !hostname.isEmpty();
  }

  /** Returns whether a hostname is present but no address has been resolved yet. */
  public boolean hasHostnameNoIP() {
    return hasHostname() && address == null;
  }

  /**
   * Returns whether the resolved address is IPv6.
   *
   * @param defaultValue value to return when the address has not been resolved yet
   * @return {@code true} for IPv6, {@code false} for IPv4, or {@code defaultValue} when unknown
   */
  public boolean isIPv6(boolean defaultValue) {
    if (address == null) return defaultValue;
    else return (address instanceof Inet6Address);
  }
}
