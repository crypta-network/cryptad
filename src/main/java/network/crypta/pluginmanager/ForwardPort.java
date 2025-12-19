package network.crypta.pluginmanager;

/**
 * Describes a public-facing port that may require NAT/IGD forwarding.
 *
 * <p>This is a small, immutable value object used to describe a single port mapping the node would
 * like to be reachable on. It captures a logical name for the mapping (for example, a network
 * "interface" label used by the node), whether the mapping is intended for IPv6, the IP protocol
 * number, and the external port number.
 *
 * <p>Instances are immutable and therefore safe to share between threads. Equality is defined
 * purely in terms of the four public fields ({@link #name}, {@link #isIP6}, {@link #protocol}, and
 * {@link #portNumber}). The hash code is precomputed at construction time to keep lookups and
 * deduplication efficient when these objects are used as keys in collections.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> carry port-forwarding intent and provide stable equality semantics
 *       for collection membership.
 *   <li><b>Notable behaviors:</b> the constructor stores values as provided and does not validate
 *       ranges (for example, {@code portNumber} is not clamped to {@code 0..65535}).
 * </ul>
 *
 * @author toad
 */
public class ForwardPort {

  /**
   * Logical name associated with this mapping (for example {@code "opennet"} or {@code "darknet"}).
   *
   * <p>This value is treated as an opaque identifier: it is stored and compared for equality, but
   * it is not interpreted as an operating system network interface name or bind address by this
   * class. It must be non-null.
   */
  public final String name;

  /**
   * Whether this mapping is intended for IPv6.
   *
   * <p>This flag is part of the value object's identity and is included in {@link #equals(Object)}
   * and {@link #hashCode()}. It does not imply any particular socket binding behavior by itself; it
   * merely records the caller's intent when describing the port to be forwarded.
   */
  public final boolean isIP6;

  /**
   * IP protocol number for the traffic this mapping is for.
   *
   * <p>This is the IANA protocol number (for example {@code 6} for TCP, {@code 17} for UDP). The
   * class exposes common constants such as {@link #PROTOCOL_TCP_IPV4} and {@link
   * #PROTOCOL_UDP_IPV4}, but callers may store any integer value; no validation is performed.
   */
  public final int protocol;

  /**
   * IANA protocol number for UDP over IPv4 ({@code 17}).
   *
   * <p>This constant is provided as a convenience for callers constructing {@link ForwardPort}
   * instances and for tests asserting protocol values. It is a stable, compile-time constant.
   */
  public static final int PROTOCOL_UDP_IPV4 = 17;

  /**
   * IANA protocol number for TCP over IPv4 ({@code 6}).
   *
   * <p>This constant is provided as a convenience for callers constructing {@link ForwardPort}
   * instances and for tests asserting protocol values. It is a stable, compile-time constant.
   */
  public static final int PROTOCOL_TCP_IPV4 = 6;

  /**
   * External port number to forward.
   *
   * <p>This value is stored exactly as provided by the caller and is used for equality and hash
   * code calculations. No range checks are performed, so callers are responsible for supplying
   * values appropriate for their environment (typically {@code 0..65535} for TCP/UDP ports).
   */
  public final int portNumber;

  // We don't currently support binding to a specific internal interface.
  // It would be complicated: Different interfaces may be on different LANs,
  // and an IGD is normally on only one LAN.
  private final int hashCode;

  /**
   * Creates a new immutable port-forwarding descriptor.
   *
   * <p>The provided values are stored verbatim and become part of the instance identity used by
   * {@link #equals(Object)} and {@link #hashCode()}. This constructor does not validate protocol or
   * port ranges; it only enforces that {@code name} is non-null. Callers should normalize values
   * (for example, canonicalize the mapping name and validate port bounds) before construction when
   * needed.
   *
   * @param name logical mapping name; must be non-null and is compared using {@link String#equals}
   * @param isIP6 whether this mapping is intended for IPv6 rather than IPv4
   * @param protocol IANA protocol number (for example {@code 6} TCP, {@code 17} UDP); stored as-is
   * @param portNumber external port number to forward; stored as-is without range validation
   * @throws NullPointerException if {@code name} is null
   */
  public ForwardPort(String name, boolean isIP6, int protocol, int portNumber) {
    this.name = name;
    this.isIP6 = isIP6;
    this.protocol = protocol;
    this.portNumber = portNumber;
    hashCode = name.hashCode() | (isIP6 ? 1 : 0) | protocol | portNumber;
  }

  /**
   * Returns the precomputed hash code for this value object.
   *
   * <p>The hash code is computed once at construction time from the same fields used by {@link
   * #equals(Object)}. This keeps repeated lookups efficient when instances are used as keys in hash
   * based collections. The value remains stable for the lifetime of the object because the instance
   * is immutable.
   *
   * @return a stable hash code derived from {@link #name}, {@link #isIP6}, {@link #protocol}, and
   *     {@link #portNumber}
   */
  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Compares this instance to another object for value equality.
   *
   * <p>Two {@link ForwardPort} instances are considered equal when and only when they have the same
   * mapping name, {@code isIP6} flag, protocol number, and port number. Comparisons to {@code null}
   * and to objects of other types return {@code false}.
   *
   * @param o the object to compare against; may be null or a different type
   * @return true if {@code o} is a {@link ForwardPort} with identical field values; otherwise false
   */
  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    if (!(o instanceof ForwardPort f)) return false;
    return (f.name.equals(name))
        && f.isIP6 == isIP6
        && f.protocol == protocol
        && f.portNumber == portNumber;
  }
}
