package network.crypta.io;

import java.util.stream.Stream;
import network.crypta.io.AddressIdentifier.AddressType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Deterministic unit tests for {@link AddressIdentifier}. */
@SuppressWarnings("java:S100") // test method naming with underscores
@ExtendWith(MockitoExtension.class)
class AddressIdentifierTest {

  // -------- IPv4 --------
  @ParameterizedTest(name = "{index} => {0}")
  @MethodSource("validIPv4")
  void getAddressType_whenIPv4Valid_expectIPv4(String input) {
    // Arrange

    // Act
    AddressType type = AddressIdentifier.getAddressType(input);

    // Assert
    assertEquals(AddressType.IPV4, type);
  }

  static Stream<String> validIPv4() {
    return Stream.of(
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        // Abridged forms
        "183.24.17",
        "127.1");
  }

  @ParameterizedTest(name = "{index} => {0}")
  @MethodSource("invalidIPv4")
  void getAddressType_whenIPv4Invalid_expectOther(String input) {
    AddressType type = AddressIdentifier.getAddressType(input);
    assertEquals(AddressType.OTHER, type);
  }

  static Stream<String> invalidIPv4() {
    return Stream.of(
        // Out-of-range byte
        "192.168.370.12",
        // Too many parts
        "127.0.0.0.1",
        // Unicode digits (full-width); must not match IPv4
        "１２７.０.０.１");
  }

  // -------- IPv6 (no percent scope) --------
  @ParameterizedTest(name = "{index} => {0}")
  @MethodSource("validIPv6NoPercent")
  void getAddressType_whenIPv6ValidNoPercent_expectIPv6(String input) {
    AddressType type = AddressIdentifier.getAddressType(input, false);
    assertEquals(AddressType.IPV6, type);
  }

  static Stream<String> validIPv6NoPercent() {
    return Stream.of(
        // Unabridged
        "0:0:0:0:0:0:0:1",
        "2001:db8:0:0:203:dff:fe22:420f",
        // Representative abridged forms (covering different compression positions)
        "2001:db8::1",
        "2001:db8::",
        "2001:db8:1::",
        "2001:db8::3:4:5:6",
        "2001:db8:1:2:3:4::7",
        "2001:db8:1:2:3:4::");
  }

  // -------- IPv6 with percent scope ID --------
  @Test
  @DisplayName("getAddressType accepts %scope by default")
  void getAddressType_whenIPv6WithPercent_defaultAllow_expectIPv6() {
    assertEquals(
        AddressType.IPV6, AddressIdentifier.getAddressType("2001:db8::203:dff:fe22:420f%10"));
    assertEquals(
        AddressType.IPV6, AddressIdentifier.getAddressType("2001:DB8::203:DFF:FE22:420F%10"));
  }

  @ParameterizedTest(name = "{index} => {0}")
  @MethodSource("ipv6WithPercent")
  void getAddressType_whenIPv6WithPercent_disallowed_expectOther(String input) {
    AddressType type = AddressIdentifier.getAddressType(input, false);
    assertEquals(AddressType.OTHER, type);
  }

  static Stream<String> ipv6WithPercent() {
    return Stream.of(
        // Valid numeric scope when allowed, but here we disallow
        "2001:db8::203:dff:fe22:420f%10",
        // Invalid alphanumeric scope
        "2001:db8::203:dff:fe22:420f%a");
  }

  // -------- Invalid IPv6 --------
  @ParameterizedTest(name = "{index} => {0}")
  @MethodSource("invalidIPv6")
  void getAddressType_whenIPv6Invalid_expectOther(String input) {
    // Act: evaluate both overloads to ensure invalid inputs are consistently rejected
    AddressType typeDefault = AddressIdentifier.getAddressType(input); // allow %scope by default
    AddressType typeNoScope = AddressIdentifier.getAddressType(input, false);

    // Assert
    assertEquals(AddressType.OTHER, typeDefault);
    assertEquals(AddressType.OTHER, typeNoScope);
  }

  static Stream<String> invalidIPv6() {
    return Stream.of(
        // Too many groups
        "1:2:3:4:5:6:7:8:9",
        // Group too long
        "12345:6:7:8:9",
        // Bad placements of ':'
        ":1:2:3:4:5:6:7:8",
        ":1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:",
        ":1:2::3:4",
        "2001:db8:1:2::3:4:",
        // Double '::' compressions
        "1::2:3:4:5:6:7:8:9",
        "::1::2:3",
        "1::2:3::",
        "1::2:3::4",
        // Non-hex digit
        "12:34:56:78:9a:bc:de:fg");
  }

  // -------- ISATAP detection --------
  @ParameterizedTest(name = "valid ISATAP => {0}")
  @MethodSource("validIsatap")
  void isAnISATAPIPv6Address_whenValid_expectTrue(String input) {
    assertTrue(AddressIdentifier.isAnISATAPIPv6Address(input));
  }

  static Stream<String> validIsatap() {
    return Stream.of(
        "2001:db8:1:2:0:5efe:c801:20a",
        "2001:db8:1:2:0:5efe:c801:20a%10",
        // Unabridged ISATAP variant (X:X:X:X:0:5EFE:X:X)
        "2001:db8:1:2:0:5efe:6:7");
  }

  @ParameterizedTest(name = "invalid ISATAP => {0}")
  @MethodSource("invalidIsatap")
  void isAnISATAPIPv6Address_whenInvalid_expectFalse(String input) {
    assertFalse(AddressIdentifier.isAnISATAPIPv6Address(input));
  }

  static Stream<String> invalidIsatap() {
    return Stream.of(
        // Not ISATAP positions
        "2001:db8:0:0:203:dff:fe22:420f",
        "2001:db8:0:5efe:0:203:dff:fe22:420f",
        // Missing field before 5efe or too many groups
        "2001:db8:1:2:3:5efe:c801:20a",
        "2001:db8:1:2:3:4:5:5efe:c801:20a",
        // Double '::' or trailing '::' misuse
        "2001:db8::1::5efe:c801:20a",
        "2001:db8:1:2:3:0:5efe::");
  }
}
