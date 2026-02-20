package network.crypta.compat;

/** Compatibility descriptor of a public-facing port. */
public record ForwardPort(String name, boolean ipv6, int protocol, int portNumber) {
  public static final int PROTOCOL_UDP_IPV4 = 17;

  @SuppressWarnings("unused")
  public static final int PROTOCOL_TCP_IPV4 = 6;

  @SuppressWarnings("unused")
  public static final int PROTOCOL_UDP_IPV6 = PROTOCOL_UDP_IPV4;
}
