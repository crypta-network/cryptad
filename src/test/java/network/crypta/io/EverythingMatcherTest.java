package network.crypta.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class EverythingMatcherTest {

  static Stream<InetAddress> addressesProvider() throws UnknownHostException {
    return Stream.of(
        literal("127.0.0.1"),
        literal("0.0.0.0"),
        literal("255.255.255.255"),
        literal("203.0.113.1"),
        literal("::1"),
        literal("::"),
        literal("2001:db8::1"));
  }

  @ParameterizedTest
  @MethodSource("addressesProvider")
  @DisplayName("matches returns true for any IPv4/IPv6 literal")
  void matches_whenGivenVariousAddresses_expectTrue(InetAddress address) {
    // Arrange
    EverythingMatcher matcher = new EverythingMatcher();

    // Act
    boolean result = matcher.matches(address);

    // Assert
    assertTrue(result, () -> "Expected true for address: " + address);
  }

  @Test
  @DisplayName("matches returns true for null input")
  void matches_whenNullAddress_expectTrue() {
    // Arrange
    EverythingMatcher matcher = new EverythingMatcher();

    // Act
    boolean result = matcher.matches(null);

    // Assert
    assertTrue(result, "Expected true for null address");
  }

  @Test
  @DisplayName("getHumanRepresentation returns wildcard asterisk")
  void getHumanRepresentation_whenCalled_expectWildcard() {
    // Arrange
    EverythingMatcher matcher = new EverythingMatcher();

    // Act
    String human = matcher.getHumanRepresentation();

    // Assert
    assertEquals("*", human);
  }

  private static InetAddress literal(String host) throws UnknownHostException {
    return InetAddress.getAllByName(host)[0];
  }
}
