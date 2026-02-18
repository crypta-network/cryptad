package network.crypta.support.transport.ip;

import java.net.Inet6Address;
import network.crypta.io.AddressIdentifier;
import network.crypta.io.AddressIdentifier.AddressType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Allow method names with underscores for clarity
class HostnameUtilTest {

  @Test
  void isValidHostname_whenNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> HostnameUtil.isValidHostname(null, true));
  }

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
    void isValidHostname_whenDomainOnly_validDomains_returnTrue(String domain) {
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
    void isValidHostname_whenDomainOnly_invalidDomains_returnFalse(String domain) {
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
    void isValidHostname_whenIpsAllowed_validIpLiterals_returnTrue(String ip) {
      assertTrue(HostnameUtil.isValidHostname(ip, true));
    }

    // Intentionally not asserting negative plain-IP cases here because AddressIdentifier is
    // permissive (e.g., abridged IPv4) and HostnameUtil passes through to it when allowIPAddress
    // is true.

    @ParameterizedTest
    @ValueSource(
        strings = {
          // IPv4-mapped / embedded IPv6 forms
          "::ffff:127.0.0.1",
          "::ffff:192.0.2.1",
          // Zero-padded IPv4 tails must remain valid
          "::ffff:0.0.0.001",
          "2001:db8::ffff:000.000.000.000",
          "0:0:0:0:0:ffff:192.0.2.1",
          "2001:db8::ffff:192.0.2.1",
          // IPv4-compatible (deprecated, but should still parse as a literal)
          "::192.0.2.1",
          // With percent scope id (syntactic only; accepts numeric and interface-name scopes)
          "2001:db8::ffff:192.0.2.1%1",
          "2001:db8::ffff:192.0.2.1%abc",
          "2001:db8::ffff:192.0.2.1%1234"
        })
    void isValidHostname_whenIpsAllowed_ipv6EmbeddedIPv4_returnTrue(String ip) {
      assertTrue(HostnameUtil.isValidHostname(ip, true));
    }

    @ParameterizedTest
    @ValueSource(
        strings = {
          // Multiple "::" occurrences are invalid
          "2001::db8::ffff:192.0.2.1",
          // Invalid IPv4 tail
          "2001:db8::ffff:192.0.256.1",
          "2001:db8::ffff:192.0.2",
          // Invalid percent scope id: empty only (non-empty names and longer numeric are allowed)
          "2001:db8::ffff:192.0.2.1%",
          // Bracketed forms are not recognized by this utility
          "[::ffff:192.0.2.1]"
        })
    void isValidHostname_whenIpsAllowed_invalidEmbeddedIPv4Forms_returnFalse(String ip) {
      assertFalse(HostnameUtil.isValidHostname(ip, true));
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
    void isValidHostname_whenIpsDisallowed_ips_returnFalse(String ip) {
      assertFalse(HostnameUtil.isValidHostname(ip, false));
    }
  }

  @Nested
  @DisplayName("Hostnames when IPs allowed (allowIPAddress=true)")
  class HostnamesWithIpAllowed {

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "sub.example.org", "xn--d1acufc7f.com"})
    void isValidHostname_whenIpsAllowed_validHostnames_returnTrue(String domain) {
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
    void isValidHostname_whenIpsAllowed_invalidHostnames_returnFalse(String domain) {
      assertFalse(HostnameUtil.isValidHostname(domain, true));
    }
  }

  @Test
  void ipv6_with_interface_name_scope_is_classified_as_ipv6_and_valid() {
    String s = "fe80::1%eth0";
    AddressType t = AddressIdentifier.getAddressType(s, /* allowIPv6PercentScopeID= */ true);
    assertSame(AddressType.IPV6, t, "expected IPV6 literal classification");
    assertTrue(HostnameUtil.isValidHostname(s, /* allowIPAddress= */ true));
  }

  @Test
  void toNoderefHost_prefers_numeric_scope_when_available() throws Exception {
    byte[] bytes = new byte[] {(byte) 0xFE, (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    Inet6Address addr = Inet6Address.getByAddress(null, bytes, /* scope_id= */ 3);
    String s = HostnameUtil.toNoderefHost(addr);
    assertEquals("fe80:0:0:0:0:0:0:1%3", s, "got=" + s);
  }
}
