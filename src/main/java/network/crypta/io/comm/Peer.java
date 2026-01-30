package network.crypta.io.comm;

import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Comparator;
import network.crypta.io.WritableToDataOutputStream;
import network.crypta.support.io.InetAddressIpv6FirstComparator;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import network.crypta.support.transport.ip.IPUtil;

/**
 * Immutable network endpoint consisting of a host (DNS name or IP literal) and a TCP port.
 *
 * <p>The host is represented by {@link FreenetInetAddress}, which can hold either a DNS hostname or
 * a resolved numeric address and defines multiple equality modes. This class mirrors those
 * semantics via {@link #laxEquals(Object)}, {@link #equals(Object)}, and {@link
 * #strictEquals(Object)} while also requiring the port numbers to match.
 *
 * <p>Instances created from a DNS name may re-resolve the address when explicitly requested (see
 * {@link #getHandshakeAddress()}). Regular address lookups (see {@link #getAddress(boolean)})
 * prefer cached results to avoid unnecessary DNS requests.
 */
public class Peer implements WritableToDataOutputStream {

  /**
   * Thrown when a resolved address is considered local/non‑public and therefore not acceptable for
   * the requested operation.
   */
  public static class LocalAddressException extends Exception {
    @Serial private static final long serialVersionUID = -1;
  }

  /** Comparator that prefers hostname peers, then IPv6 before IPv4. See {@link PeerComparator}. */
  public static final PeerComparator PEER_COMPARATOR = new PeerComparator();

  /** Legacy revision marker string. */
  public static final String VERSION = "$Id: Peer.java,v 1.4 2005/08/25 17:28:19 amphibian Exp $";

  private final FreenetInetAddress addr;
  private final int port;

  /**
   * Constructs a peer by reading from a {@link DataInput} in the same format written by {@link
   * #writeToDataOutputStream(DataOutputStream)}.
   *
   * <p>Format: serialized {@link FreenetInetAddress} followed by a 32‑bit port. The port must be in
   * {@code [0, 65535]}.
   *
   * @param dis data input to read from
   * @throws IOException if the input is malformed or the port is out of range
   */
  public Peer(DataInput dis) throws IOException {
    addr = new FreenetInetAddress(dis);
    port = dis.readInt();
    if (port > 65535 || port < 0) throw new IOException("bogus port");
  }

  /**
   * Constructs a peer from a {@link DataInput}, optionally validating hostname/IP syntax while
   * reading the {@link FreenetInetAddress}.
   *
   * @param dis data input to read from
   * @param checkHostnameOrIPSyntax when {@code true}, validate DNS hostname or IPv4 syntax during
   *     deserialization
   * @throws HostnameSyntaxException if syntax validation is enabled and the host is not well‑formed
   * @throws IOException if the input is malformed or the port is out of range
   */
  public Peer(DataInput dis, boolean checkHostnameOrIPSyntax)
      throws HostnameSyntaxException, IOException {
    addr = new FreenetInetAddress(dis, checkHostnameOrIPSyntax);
    port = dis.readInt();
    if (port > 65535 || port < 0) throw new IOException("bogus port");
  }

  /**
   * Constructs a peer from a concrete {@link InetAddress} and port. The numeric address is
   * considered primary and does not change with subsequent DNS updates.
   *
   * @param address resolved numeric address
   * @param port TCP port in {@code [0, 65535]}
   * @throws IllegalArgumentException if {@code port} is outside the valid range
   */
  public Peer(InetAddress address, int port) {
    addr = new FreenetInetAddress(address);
    this.port = port;
    if (this.port > 65535 || this.port < 0) throw new IllegalArgumentException("bogus port");
  }

  /**
   * Parses {@code "host:port"} where {@code host} is a DNS name or IP literal. When a DNS name is
   * provided, the name is treated as primary; {@link #getHandshakeAddress()} may re‑resolve it.
   *
   * <p>The split uses the last colon to separate the port, which tolerates IPv6 literals when the
   * port suffix is present.
   *
   * @param physical input in the form {@code <host>:<port>}
   * @param allowUnknown when {@code true}, allow construction even if the DNS name cannot be
   *     resolved at this time
   * @throws PeerParseException if the input is malformed or the port is missing/invalid
   * @throws UnknownHostException if {@code allowUnknown} is {@code false} and the DNS lookup fails
   */
  public Peer(String physical, boolean allowUnknown)
      throws PeerParseException, UnknownHostException {
    int offset = physical.lastIndexOf(':'); // split on final ':' to tolerate IPv6 literals
    if (offset < 0) throw new PeerParseException();
    String host = physical.substring(0, offset);
    addr = new FreenetInetAddress(host, allowUnknown);
    String strport = physical.substring(offset + 1);
    try {
      port = Integer.parseInt(strport);
      if (port < 0 || port > 65535) throw new PeerParseException("Invalid port " + port);
    } catch (NumberFormatException e) {
      throw new PeerParseException(e);
    }
  }

  /**
   * Parses {@code "host:port"} with optional hostname/IP syntax validation. Semantics are identical
   * to {@link #Peer(String, boolean)} with the added syntax check step.
   *
   * @param physical input in the form {@code <host>:<port>}
   * @param allowUnknown when {@code true}, allow construction even if the DNS name cannot be
   *     resolved at this time
   * @param checkHostnameOrIPSyntax when {@code true}, validate the DNS hostname or IPv4 literal
   *     syntax
   * @throws HostnameSyntaxException if syntax validation fails
   * @throws PeerParseException if the input is malformed or the port is missing/invalid
   * @throws UnknownHostException if {@code allowUnknown} is {@code false} and the DNS lookup fails
   */
  public Peer(String physical, boolean allowUnknown, boolean checkHostnameOrIPSyntax)
      throws HostnameSyntaxException, PeerParseException, UnknownHostException {
    int offset = physical.lastIndexOf(':'); // split on final ':' to tolerate IPv6 literals
    if (offset < 0) throw new PeerParseException("No port number: \"" + physical + "\"");
    String host = physical.substring(0, offset);
    addr = new FreenetInetAddress(host, allowUnknown, checkHostnameOrIPSyntax);
    String strport = physical.substring(offset + 1);
    try {
      port = Integer.parseInt(strport);
      if (port < 0 || port > 65535) throw new PeerParseException("Invalid port " + port);
    } catch (NumberFormatException e) {
      throw new PeerParseException(e);
    }
  }

  /**
   * Constructs a peer from an existing {@link FreenetInetAddress} and port. No copying is
   * performed; the provided instance is kept as‑is.
   *
   * @param addr address holder; must be non‑null
   * @param port TCP port in {@code [0, 65535]}
   * @throws NullPointerException if {@code addr} is {@code null}
   * @throws IllegalArgumentException if {@code port} is outside the valid range
   */
  public Peer(FreenetInetAddress addr, int port) {
    this.addr = addr;
    if (addr == null) throw new NullPointerException();
    this.port = port;
    if (this.port > 65535 || this.port < 0) throw new IllegalArgumentException("bogus port");
  }

  /**
   * Returns {@code true} when the port is zero. This is used as a sentinel for an uninitialized or
   * special peer in some contexts.
   */
  public boolean isNull() {
    return port == 0;
  }

  /**
   * Returns {@code true} if {@code o} is a {@code Peer} with the same port and an address that is
   * equal under {@link FreenetInetAddress#laxEquals(FreenetInetAddress)}.
   */
  public boolean laxEquals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Peer peer)) {
      return false;
    }

    if (port != peer.port) {
      return false;
    }
    return addr.laxEquals(peer.addr);
  }

  /**
   * Compares by port and address using {@link FreenetInetAddress#equals(Object)}. This is the
   * default, non‑lax, non‑strict comparison.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Peer peer)) {
      return false;
    }

    if (port != peer.port) {
      return false;
    }
    return addr.equals(peer.addr);
  }

  /**
   * Returns {@code true} if {@code o} is a {@code Peer} with the same port and an address that is
   * equal under {@link FreenetInetAddress#strictEquals(FreenetInetAddress)}.
   */
  public boolean strictEquals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null) return false;
    if (!(o instanceof Peer peer)) {
      return false;
    }

    if (port != peer.port) {
      return false;
    }
    return addr.strictEquals(peer.addr);
  }

  /**
   * Returns the IP address, performing a DNS lookup if needed and allowed by {@link
   * #getAddress(boolean)} semantics.
   */
  public InetAddress getAddress() {
    return getAddress(true);
  }

  /**
   * Returns the IP address. When {@code doDNSRequest} is {@code true} and no cached value exists, a
   * DNS lookup may be performed. If a previous lookup exists, the cached value is returned without
   * forcing a refresh.
   *
   * @param doDNSRequest whether a DNS lookup is permitted
   * @return the resolved address, or {@code null} when unknown and a lookup is not performed
   */
  public InetAddress getAddress(boolean doDNSRequest) {
    return addr.getAddress(doDNSRequest);
  }

  /**
   * Returns the IP address with optional DNS lookup and local‑address filtering.
   *
   * @param doDNSRequest whether a DNS lookup is permitted
   * @param allowLocal when {@code false}, reject addresses considered local/non‑public
   * @return the resolved address, or {@code null} when unknown and a lookup is not performed
   * @throws LocalAddressException if the resolved address is not acceptable and {@code allowLocal}
   *     is {@code false}
   */
  public InetAddress getAddress(boolean doDNSRequest, boolean allowLocal)
      throws LocalAddressException {
    InetAddress a = addr.getAddress(doDNSRequest);
    if (a == null) return null;
    if (allowLocal || IPUtil.isValidAddress(a, false)) return a;
    throw new LocalAddressException();
  }

  /**
   * Forces a re‑lookup when the hostname is primary, even if a previous resolution exists. This is
   * typically used before reconnect attempts when a dynamic DNS address may have changed.
   */
  @SuppressWarnings("UnusedReturnValue")
  public InetAddress getHandshakeAddress() {
    return addr.getHandshakeAddress();
  }

  /** Computes a hash code consistent with {@link #equals(Object)}. */
  @Override
  public int hashCode() {
    return addr.hashCode() + port;
  }

  /**
   * Returns the TCP port number.
   *
   * @return port in {@code [0, 65535]}
   */
  public int getPort() {
    return port;
  }

  /**
   * Returns {@code host:port} using the underlying {@link FreenetInetAddress#toString()} for the
   * host component.
   */
  @Override
  public String toString() {
    return addr.toString() + ':' + port;
  }

  /**
   * Writes this peer to a {@link DataOutputStream}. The format matches the constructor that accepts
   * a {@link DataInput}: serialized {@link FreenetInetAddress} then a 32‑bit port.
   *
   * @param dos output stream
   * @throws IOException if writing fails
   */
  @Override
  public void writeToDataOutputStream(DataOutputStream dos) throws IOException {
    addr.writeToDataOutputStream(dos);
    dos.writeInt(port);
  }

  /**
   * Returns the underlying address holder for advanced queries.
   *
   * @return the {@link FreenetInetAddress} backing this peer
   */
  public FreenetInetAddress getFreenetAddress() {
    return addr;
  }

  /**
   * Indicates whether the address is considered a real Internet address. The check may perform a
   * lookup based on {@code lookup} and may treat local addresses as acceptable based on {@code
   * allowLocalAddresses}.
   *
   * @param lookup whether to perform a lookup if needed
   * @param defaultVal value to return when the address is unknown
   * @param allowLocalAddresses whether to treat local/private addresses as acceptable
   * @return {@code true} if the address is acceptable per the above parameters
   */
  public boolean isRealInternetAddress(
      boolean lookup, boolean defaultVal, boolean allowLocalAddresses) {
    return addr.isRealInternetAddress(lookup, defaultVal, allowLocalAddresses);
  }

  /**
   * Returns {@code host:port} but prefers a numeric IP representation for the host when available,
   * avoiding DNS names.
   */
  public String toStringPrefNumeric() {
    return addr.toStringPrefNumeric() + ':' + port;
  }

  /**
   * Returns a peer where the hostname (if any) is dropped in favor of a numeric address. If no
   * numeric address is known, returns {@code null}. If the underlying address is unchanged, this
   * instance is returned.
   *
   * @return a peer without a hostname, or {@code null} if not possible
   */
  public Peer dropHostName() {
    FreenetInetAddress newAddr = addr.dropHostname();
    if (newAddr == null) return null;
    if (!addr.equals(newAddr)) {
      return new Peer(newAddr, port);
    } else return this;
  }

  /**
   * Returns {@code true} when the address is IPv6. If the address is unknown, {@code defaultValue}
   * is returned.
   *
   * @param defaultValue value to return when the address has not been resolved
   */
  public boolean isIPv6(boolean defaultValue) {
    if (addr == null) return defaultValue;
    return addr.isIPv6(defaultValue);
  }

  /**
   * Comparator that orders peers as follows:
   *
   * <ul>
   *   <li>Peers with a hostname sort before peers without one.
   *   <li>If both have hostnames, they compare as equal (no further ordering by name).
   *   <li>Otherwise, IPv6 addresses sort before IPv4.
   *   <li>Ties are broken using {@link InetAddressIpv6FirstComparator#COMPARATOR} on the resolved
   *       addresses.
   * </ul>
   *
   * <p>This is not a strict total ordering. Callers that require a complete order should apply an
   * additional tie‑breaker.
   */
  public static class PeerComparator implements Comparator<Peer> {
    /**
     * Compares two peers according to {@link PeerComparator} rules.
     *
     * @return negative if {@code p0} should sort before {@code p1}; positive if after; zero when
     *     considered equivalent by this comparator
     */
    @Override
    public int compare(Peer p0, Peer p1) {
      boolean hasHostnameP0 = p0.getFreenetAddress().hasHostname();
      boolean hasHostnameP1 = p1.getFreenetAddress().hasHostname();
      boolean isIpv6P0 = p0.isIPv6(false); // default used when the address is not yet resolved
      boolean isIpv6P1 = p1.isIPv6(false); // default used when the address is not yet resolved
      if (hasHostnameP0 && !hasHostnameP1) {
        return -1;
      } else if (!hasHostnameP0 && hasHostnameP1) {
        return 1;
      } else if (hasHostnameP0) {
        return 0;
      }
      if (isIpv6P0 && !isIpv6P1) {
        return -1;
      } else if (!isIpv6P0 && isIpv6P1) {
        return 1;
      }
      return InetAddressIpv6FirstComparator.COMPARATOR.compare(p0.getAddress(), p1.getAddress());
    }
  }
}
