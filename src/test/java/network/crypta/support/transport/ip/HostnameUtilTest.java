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

    @ParameterizedTest
    @ValueSource(
        strings = {
          // IPv4-mapped / embedded IPv6 forms
          "::ffff:127.0.0.1",
          "::ffff:192.0.2.1",
          "0:0:0:0:0:ffff:192.0.2.1",
          "2001:db8::ffff:192.0.2.1",
          // IPv4-compatible (deprecated, but should still parse as a literal)
          "::192.0.2.1",
          // With percent scope id (syntactic only)
          "2001:db8::ffff:192.0.2.1%1"
        })
    void ipv6WithEmbeddedIPv4IsAccepted(String ip) {
      assertTrue(HostnameUtil.isValidHostname(ip, true));
    }
  }

  @Nested
  @DisplayName("IP literals when disallowed (allowIPAddress=false)")
  class IpDisallowed {

    @ParameterizedTest
    @ValueSource(
        strings = {
          "127.0.0.1",
          "198.51.100.1",
          "2001:db8::1",
          "2001:db8:1:2:3:4:5:6",
          // Also reject IPv6-with-embedded-IPv4 when IPs are disallowed
          "::ffff:192.0.2.1",
          "::192.0.2.1"
        })
    void ipsAreRejectedWhenDisallowed(String ip) {
      assertFalse(HostnameUtil.isValidHostname(ip, false));
    }
  }

  @Nested
  @DisplayName("Hostnames when IPs allowed (allowIPAddress=true)")
  class HostnamesWithIpAllowed {

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "sub.example.org", "xn--d1acufc7f.com"})
    void validHostnamesStillValidate(String domain) {
      // Even when IPs are allowed, plain hostnames must pass the hostname regex
      assertTrue(HostnameUtil.isValidHostname(domain, true));
    }

    @ParameterizedTest
    @ValueSource(
        strings = {
          "localhost",
          "example.company",
          "foo..bar.com",
          "com",
          "",
          // Explicitly invalid IPv6-like strings must not pass
          ":::ffff:192.0.2.1",
          "::::ffff:192.0.2.1",
          "[::1]" // bracketed forms are not accepted by design
        })
    void invalidHostnamesAreRejected(String domain) {
      // Regression check: previously, enum name comparison allowed any string to pass
      assertFalse(HostnameUtil.isValidHostname(domain, true));
    }
  }
}
