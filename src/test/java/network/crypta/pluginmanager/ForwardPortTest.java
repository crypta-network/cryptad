package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100")
class ForwardPortTest {

  private static final String OPENNET = "opennet";
  private static final String DARKNET = "darknet";

  private static ForwardPort constructForwardPort(
      String name, boolean isIp6, int protocol, int port) {
    return new ForwardPort(name, isIp6, protocol, port);
  }

  @Test
  void constructor_whenValidArgs_setsPublicFields() {
    ForwardPort forwardPort = new ForwardPort(OPENNET, true, ForwardPort.PROTOCOL_UDP_IPV4, 12345);

    assertAll(
        () -> assertEquals(OPENNET, forwardPort.name),
        () -> assertTrue(forwardPort.isIP6),
        () -> assertEquals(ForwardPort.PROTOCOL_UDP_IPV4, forwardPort.protocol),
        () -> assertEquals(12345, forwardPort.portNumber));
  }

  @Test
  void constructor_whenNameIsNull_throwsNullPointerException() {
    //noinspection DataFlowIssue
    assertThrows(
        NullPointerException.class, () -> assertNotNull(constructForwardPort(null, false, 0, 0)));
  }

  @Test
  void protocolConstants_whenAccessed_matchIanaValues() {
    assertAll(
        () -> assertEquals(17, ForwardPort.PROTOCOL_UDP_IPV4),
        () -> assertEquals(6, ForwardPort.PROTOCOL_TCP_IPV4));
  }

  @Test
  void equals_whenSameInstance_returnsTrue() {
    ForwardPort forwardPort = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);
    //noinspection UnnecessaryLocalVariable
    ForwardPort alias = forwardPort;

    assertEquals(forwardPort, alias);
  }

  @Test
  void equals_whenOtherIsNull_returnsFalse() {
    ForwardPort forwardPort = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);
    Object other = null;

    //noinspection ConstantValue
    assertNotEquals(other, forwardPort);
  }

  @Test
  void equals_whenOtherIsDifferentType_returnsFalse() {
    ForwardPort forwardPort = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);
    Object other = "not a ForwardPort";

    assertNotEquals(other, forwardPort);
  }

  @ParameterizedTest
  @MethodSource("equalPairs")
  void equals_whenAllFieldsEqual_returnsTrueAndHashCodesMatch(
      ForwardPort first, ForwardPort second) {
    assertAll(
        () -> assertEquals(first, second),
        () -> assertEquals(second, first),
        () -> assertEquals(first.hashCode(), second.hashCode()));
  }

  @Test
  void equals_whenAllFieldsEqual_isTransitive() {
    ForwardPort first = new ForwardPort(OPENNET, true, ForwardPort.PROTOCOL_UDP_IPV4, 12345);
    ForwardPort second = new ForwardPort(OPENNET, true, ForwardPort.PROTOCOL_UDP_IPV4, 12345);
    ForwardPort third = new ForwardPort(OPENNET, true, ForwardPort.PROTOCOL_UDP_IPV4, 12345);

    assertAll(
        () -> assertEquals(first, second),
        () -> assertEquals(second, third),
        () -> assertEquals(first, third));
  }

  @Test
  void equals_whenNameDiffers_returnsFalse() {
    ForwardPort first = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);
    ForwardPort second = new ForwardPort(DARKNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);

    assertNotEquals(first, second);
  }

  @Test
  void equals_whenIsIP6Differs_returnsFalse() {
    ForwardPort first = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);
    ForwardPort second = new ForwardPort(OPENNET, true, ForwardPort.PROTOCOL_TCP_IPV4, 8080);

    assertNotEquals(first, second);
  }

  @Test
  void equals_whenProtocolDiffers_returnsFalse() {
    ForwardPort first = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);
    ForwardPort second = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_UDP_IPV4, 8080);

    assertNotEquals(first, second);
  }

  @Test
  void equals_whenPortNumberDiffers_returnsFalse() {
    ForwardPort first = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);
    ForwardPort second = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8081);

    assertNotEquals(first, second);
  }

  @ParameterizedTest
  @MethodSource("nonStandardPortNumbers")
  void constructor_whenPortNumberIsAnyInt_preservesValue(int portNumber) {
    ForwardPort forwardPort =
        new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, portNumber);

    assertEquals(portNumber, forwardPort.portNumber);
  }

  @ParameterizedTest
  @MethodSource("nonStandardProtocols")
  void constructor_whenProtocolIsAnyInt_preservesValue(int protocol) {
    ForwardPort forwardPort = new ForwardPort(OPENNET, false, protocol, 123);

    assertEquals(protocol, forwardPort.protocol);
  }

  @Test
  void hashCode_whenCalledMultipleTimes_returnsSameValue() {
    ForwardPort forwardPort = new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 8080);

    int firstHashCode = forwardPort.hashCode();
    int secondHashCode = forwardPort.hashCode();

    assertEquals(firstHashCode, secondHashCode);
  }

  private static Stream<Arguments> equalPairs() {
    return Stream.of(
        Arguments.of(
            new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 0),
            new ForwardPort(OPENNET, false, ForwardPort.PROTOCOL_TCP_IPV4, 0)),
        Arguments.of(
            new ForwardPort(OPENNET, true, ForwardPort.PROTOCOL_TCP_IPV4, 8080),
            new ForwardPort(OPENNET, true, ForwardPort.PROTOCOL_TCP_IPV4, 8080)),
        Arguments.of(
            new ForwardPort(DARKNET, false, ForwardPort.PROTOCOL_UDP_IPV4, 65535),
            new ForwardPort(DARKNET, false, ForwardPort.PROTOCOL_UDP_IPV4, 65535)),
        Arguments.of(new ForwardPort("", false, 0, -1), new ForwardPort("", false, 0, -1)),
        Arguments.of(
            new ForwardPort("a", true, Integer.MIN_VALUE, Integer.MAX_VALUE),
            new ForwardPort("a", true, Integer.MIN_VALUE, Integer.MAX_VALUE)));
  }

  private static Stream<Integer> nonStandardPortNumbers() {
    return Stream.of(-1, 0, 1, 65535, 65536, Integer.MIN_VALUE, Integer.MAX_VALUE);
  }

  private static Stream<Integer> nonStandardProtocols() {
    return Stream.of(0, 1, -1, 6, 17, 255, Integer.MIN_VALUE, Integer.MAX_VALUE);
  }
}
