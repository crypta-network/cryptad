package network.crypta.support.transport.ip;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class HostnameUtilTest {

  @Nested
  @DisplayName("Domain names (allowIPAddress=false)")
  class DomainOnly {

    @ParameterizedTest
    @ValueSource(
        strings = {
          "example.com",
          "sub.example.org",
          "A-B.cd",
          "foo_bar.io",
          "xn--d1acufc7f.com",
          "example.travel" // 6-letter TLD
        })
    void validDomainsReturnTrue(String domain) {
      assertTrue(HostnameUtil.isValidHostname(domain, false));
    }

    @ParameterizedTest
    @ValueSource(
        strings = {
          "",
          "localhost",
          "example.company", // TLD too long (>6)
          "example.com.",
          "foo..bar.com",
          "com" // no dot + TLD pair
        })
    void invalidDomainsReturnFalse(String domain) {
      assertFalse(HostnameUtil.isValidHostname(domain, false));
    }
  }

  @Nested
  @DisplayName("IP literals when allowed (allowIPAddress=true)")
  class IpAllowed {

    @ParameterizedTest
    @ValueSource(
        strings = {
          // IPv4 variants (unabridged + abridged forms) — loopback range avoids S1313
          "127.0.0.1",
          "127.0.1.2",
          "127.1",
          "127.0.1",
          // IPv6 variants (abridged + full) in documentation range 2001:db8::/32
          "2001:db8:204:1234:dead:beef:0:1",
          "2001:db8:85a3:0:0:8a2e:370:7334",
          "2001:db8::1",
          "2001:db8::9"
        })
    void ipLiteralsAreAccepted(String ip) {
      assertTrue(HostnameUtil.isValidHostname(ip, true));
    }

    // Intentionally not asserting negative IP cases here because AddressIdentifier is permissive
    // (e.g., abridged IPv4) and HostnameUtil passes through to it when allowIPAddress=true.
  }

  @Nested
  @DisplayName("IP literals when disallowed (allowIPAddress=false)")
  class IpDisallowed {

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "198.51.100.1", "2001:db8::1", "2001:db8:1:2:3:4:5:6"})
    void ipsAreRejectedWhenDisallowed(String ip) {
      assertFalse(HostnameUtil.isValidHostname(ip, false));
    }
  }
}
