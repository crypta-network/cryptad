package network.crypta.io;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;
import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class InetAddressAddressTrackerItemTest {

  private static Stream<Arguments> ipAddresses() {
    return Stream.of(
        Arguments.of("192.0.2.10"), // TEST-NET-1 IPv4 literal
        Arguments.of("2001:db8::1")); // Documentation IPv6 literal
  }

  @ParameterizedTest
  @MethodSource("ipAddresses")
  @DisplayName("toFieldSet round-trips address and preserves base tracker state")
  void toFieldSet_whenRoundTripped_expectAddressAndStatePreserved(String literal) throws Exception {
    // Arrange
    long base = 10_000L;
    InetAddress address = InetAddress.getAllByName(literal)[0];
    InetAddressAddressTrackerItem original =
        new InetAddressAddressTrackerItem(base /* no-recv */, base /* no-sent */, address);

    // Touch counters and timestamps a bit to ensure parent fields are non-trivial
    long sentAt = base + 5_000L;
    long recvAt = sentAt + AddressTracker.MAYBE_TUNNEL_LENGTH + 2_000L;
    original.sentPacket(sentAt);
    original.receivedPacket(recvAt);

    // Act
    SimpleFieldSet fs = original.toFieldSet();
    // Assert write
    assertNotNull(fs);
    assertEquals(address.getHostAddress(), fs.getString("Address"));

    // Act: reconstruct
    InetAddressAddressTrackerItem restored = new InetAddressAddressTrackerItem(fs);

    // Assert: address equality and a few representative parent fields
    assertEquals(address, restored.addr);
    assertEquals(original.firstSentPacket(), restored.firstSentPacket());
    assertEquals(original.firstReceivedPacket(), restored.firstReceivedPacket());
    assertEquals(original.packetsSent(), restored.packetsSent());
    assertEquals(original.packetsReceived(), restored.packetsReceived());
    assertEquals(original.timeDefinitelyNoPacketsSent(), restored.timeDefinitelyNoPacketsSent());
    assertEquals(
        original.timeDefinitelyNoPacketsReceived(), restored.timeDefinitelyNoPacketsReceived());
  }

  @Test
  @DisplayName("FS constructor throws FSParseException with UnknownHost cause on bad address")
  void fsConstructor_whenInvalidAddress_expectWrappedUnknownHost() {
    // Arrange: start from a valid parent snapshot
    AddressTrackerItem parent = new AddressTrackerItem(1_000L, 1_000L);
    parent.sentPacket(5_000L);
    parent.receivedPacket(5_000L + AddressTracker.MAYBE_TUNNEL_LENGTH + 1_000L);
    SimpleFieldSet fs = parent.toFieldSet();

    // Insert an invalid IP literal so parsing fails deterministically without DNS
    fs.putOverwrite("Address", "256.256.256.256");

    // Act + Assert
    FSParseException ex =
        assertThrows(FSParseException.class, () -> new InetAddressAddressTrackerItem(fs));
    assertTrue(
        ex.getMessage().startsWith("Unknown domain name in Address:"),
        "Message should indicate unknown domain");
    assertInstanceOf(
        UnknownHostException.class, ex.getCause(), "Cause should be UnknownHostException");
  }

  @Test
  @DisplayName("FS constructor throws when Address key missing")
  void fsConstructor_whenMissingAddress_expectException() {
    // Arrange: a fully populated parent field set (has all required keys except Address)
    AddressTrackerItem parent = new AddressTrackerItem(2_000L, 2_000L);
    SimpleFieldSet fs = parent.toFieldSet();

    // Act + Assert: missing Address triggers FSParseException via getString("Address")
    assertThrows(FSParseException.class, () -> new InetAddressAddressTrackerItem(fs));
  }
}
