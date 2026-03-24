package network.crypta.io.comm;

/**
 * Differentiated Services Code Point (DSCP) values for use with {@link
 * java.net.Socket#setTrafficClass(int)}.
 *
 * <p>Each constant encodes the 6-bit DSCP value left-shifted into the IPv4/IPv6 traffic class
 * field; the two least significant bits (ECN) are {@code 0}. These values can be passed directly to
 * {@code Socket#setTrafficClass(int)} on platforms that honor DSCP settings.
 *
 * <p>Naming follows common DSCP conventions: {@code CSx} (Class Selector), {@code AFxy} (Assured
 * Forwarding), and a critical/expedited forwarding class.
 *
 * @see java.net.Socket#setTrafficClass(int)
 * @see <a href="https://en.wikipedia.org/wiki/Differentiated_services">Differentiated services</a>
 */
public enum TrafficClass {
  BEST_EFFORT(0),
  DSCP_CRITICAL(0xB8),
  DSCP_AF11(0x28),
  DSCP_AF12(0x30),
  DSCP_AF13(0x38),
  DSCP_AF21(0x48),
  DSCP_AF22(0x50),
  DSCP_AF23(0x52),
  DSCP_AF31(0x58),
  DSCP_AF32(0x70),
  DSCP_AF33(0x78),
  DSCP_AF41(0x88),
  DSCP_AF42(0x90),
  DSCP_AF43(0x98),
  DSCP_CS0(0),
  DSCP_CS1(0x20),
  DSCP_CS2(0x40),
  DSCP_CS3(0x60),
  DSCP_CS4(0x80),
  DSCP_CS5(0xA0),
  DSCP_CS6(0xC0),
  DSCP_CS7(0xE0),
  RFC1349_IPTOS_LOWCOST(0x02),
  RFC1349_IPTOS_RELIABILITY(0x04),
  RFC1349_IPTOS_THROUGHPUT(0x08),
  RFC1349_IPTOS_LOWDELAY(0x10);

  public final int value;

  TrafficClass(int tc) {
    value = tc;
  }

  public static TrafficClass getDefault() {
    // Default: CS1 (often treated as lower priority but suitable for bulk throughput).
    return TrafficClass.DSCP_CS1;
  }

  public static TrafficClass fromNameOrValue(String tcName) {
    // Accept either a symbolic enum name (case-insensitive) or a decimal integer value.
    int tcParsed = -1;
    try {
      tcParsed = Integer.parseInt(tcName);
    } catch (NumberFormatException _) {
      // Not an integer; fall through and attempt name matching.
    }

    for (TrafficClass t : TrafficClass.values()) {
      if (t.toString().equalsIgnoreCase(tcName) || t.value == tcParsed) {
        return t;
      }
    }
    throw new IllegalArgumentException();
  }
}
