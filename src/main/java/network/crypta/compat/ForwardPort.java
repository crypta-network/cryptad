package network.crypta.compat;

import java.util.Objects;

/** Compatibility descriptor of a public-facing port. */
public class ForwardPort {
  public static final int PROTOCOL_UDP_IPV4 = 0;
  public static final int PROTOCOL_UDP_IPV6 = 1;

  public final String name;
  public final boolean ipv6;
  public final int protocol;
  public final int portNumber;

  public ForwardPort(String name, boolean ipv6, int protocol, int portNumber) {
    this.name = name;
    this.ipv6 = ipv6;
    this.protocol = protocol;
    this.portNumber = portNumber;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof ForwardPort that)) {
      return false;
    }
    return ipv6 == that.ipv6
        && protocol == that.protocol
        && portNumber == that.portNumber
        && Objects.equals(name, that.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, ipv6, protocol, portNumber);
  }
}
