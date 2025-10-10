package network.crypta.support.transport.ip;

import network.crypta.io.AddressIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lightweight hostname validation helpers.
 *
 * <p>Behavior
 *
 * <ul>
 *   <li>If {@code allowIPAddress} is {@code true}, numeric IP literals are accepted based on {@link
 *       AddressIdentifier} (IPv4 including abridged forms, IPv6 including abbreviated forms and
 *       optional percent scope IDs).
 *   <li>Otherwise, hostnames are checked with a conservative ASCII pattern intended to cover
 *       ACE/IDNA (Punycode) labels. It requires at least one dot and a 2–6 letter TLD. Single-label
 *       names such as {@code localhost} are rejected by design.
 * </ul>
 *
 * <p>Limitations
 *
 * <ul>
 *   <li>This is not a full IDNA implementation; Unicode hostnames must be supplied in ACE
 *       (Punycode) form.
 *   <li>Bracketed IPv6 forms (e.g., {@code [::1]}) are not recognized; supply raw literals.
 *   <li>TLDs longer than 6 ASCII letters are not accepted.
 * </ul>
 *
 * <p>This class is stateless and thread-safe.
 */
public class HostnameUtil {
  private static final Logger LOG = LoggerFactory.getLogger(HostnameUtil.class);

  private HostnameUtil() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Validates a host name or (optionally) a numeric IP literal.
   *
   * @param hn the candidate value; must not be {@code null}
   * @param allowIPAddress when {@code true}, IPv4/IPv6 literals are accepted using {@link
   *     AddressIdentifier}; when {@code false}, only DNS-like hostnames are allowed.
   * @return {@code true} if the input is valid according to the rules above; otherwise {@code
   *     false}
   * @throws NullPointerException if {@code hn} is {@code null}
   * @see AddressIdentifier#getAddressType(String, boolean)
   */
  public static boolean isValidHostname(String hn, boolean allowIPAddress) {
    if (allowIPAddress) {
      // debugging log messages because AddressIdentifier doesn't appear to handle all IPv6 literals
      // correctly, such as "fe80::204:1234:dead:beef"
      AddressIdentifier.AddressType addressType = AddressIdentifier.getAddressType(hn, true);
      if (LOG.isTraceEnabled())
        LOG.trace("Address type of '{}' appears to be '{}'", hn, addressType);
      if (!addressType.toString().equals("Other")) {
        // the address typer thinks it's either an IPv4 or IPv6 IP address
        return true;
      }
    }
    // NOTE: It is believed that this code supports PUNYCODE based
    //       ASCII Compatible Encoding (ACE) IDNA labels as
    //       described in RFC3490.  Such an assertion has not been
    //       thoroughly tested.
    if (!hn.matches("(?:[-!#$%&'*+\\\\/0-9=?A-Z^_`a-z{|}]++\\.)++[a-zA-Z]{2,6}")) {
      LOG.warn("Failed to match {} as a hostname or IPv4/IPv6 IP address", hn);
      return false;
    }
    return true;
  }
}
