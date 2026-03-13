package network.crypta.compat;

/**
 * Compatibility descriptor for a public-facing transport port that may require forwarding.
 *
 * <p>This record models a single externally reachable endpoint requested by the node networking
 * subsystem. It carries a logical name, an IP-family flag, an IP protocol number, and the external
 * port number that should be mapped or checked. The structure intentionally mirrors historical
 * plugin-era semantics so adapter implementations can continue to exchange values without
 * data-shape conversion.
 *
 * <p>Protocol constants retain legacy numeric compatibility with IANA assignments ({@code 17} for
 * UDP and {@code 6} for TCP). The record is immutable and value-based, making it suitable as a key
 * in sets or maps used by status callbacks.
 *
 * <ul>
 *   <li><b>Primary use:</b> communicate desired forwarded endpoints to provider adapters.
 *   <li><b>Interoperability goal:</b> preserve historical numeric protocol semantics.
 * </ul>
 *
 * @param name logical mapping label such as {@code "darknet"} or {@code "opennet"}
 * @param ipv6 whether the mapping is intended for IPv6 rather than IPv4
 * @param protocol transport protocol number, typically one of the {@code PROTOCOL_*} constants
 * @param portNumber external port number associated with the requested mapping
 */
public record ForwardPort(String name, boolean ipv6, int protocol, int portNumber) {
  /** IANA protocol number for UDP, preserved for legacy compatibility. */
  public static final int PROTOCOL_UDP_IPV4 = 17;

  /** IANA protocol number for TCP, preserved for legacy compatibility. */
  @SuppressWarnings("unused")
  public static final int PROTOCOL_TCP_IPV4 = 6;

  /** Compatibility alias for UDP over IPv6, using the same UDP protocol number. */
  @SuppressWarnings("unused")
  public static final int PROTOCOL_UDP_IPV6 = PROTOCOL_UDP_IPV4;
}
