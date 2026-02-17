package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DetectedIPTest {

  private static boolean equalsAsObjects(Object left, Object right) {
    return left.equals(right);
  }

  @Test
  void DetectedIP_whenConstructed_setsFieldsAndDefaultMtu() {
    // Arrange
    InetAddress address = inet4(203, 0, 113, 7);
    short natType = DetectedIP.FULL_INTERNET;

    // Act
    DetectedIP detectedIP = new DetectedIP(address, natType);

    // Assert
    assertSame(address, detectedIP.publicAddress);
    assertEquals(natType, detectedIP.natType);
    assertEquals(DetectedIP.DEFAULT_MTU, detectedIP.getMtu());
  }

  @ParameterizedTest
  @ValueSource(
      shorts = {
        DetectedIP.NOT_SUPPORTED,
        DetectedIP.FULL_INTERNET,
        DetectedIP.FULL_CONE_NAT,
        DetectedIP.RESTRICTED_CONE_NAT,
        DetectedIP.PORT_RESTRICTED_NAT,
        DetectedIP.SYMMETRIC_NAT,
        DetectedIP.SYMMETRIC_UDP_FIREWALL,
        DetectedIP.NO_UDP
      })
  void DetectedIP_whenConstructedWithNatType_preservesNatType(short natType) {
    // Arrange
    InetAddress address = inet4(198, 51, 100, 42);

    // Act
    DetectedIP detectedIP = new DetectedIP(address, natType);

    // Assert
    assertEquals(natType, detectedIP.natType);
  }

  @Test
  @SuppressWarnings("java:S2159")
  void equals_whenComparedToNull_returnsFalse() {
    // Arrange
    DetectedIP detectedIP = new DetectedIP(inet4(203, 0, 113, 1), DetectedIP.FULL_INTERNET);

    // Act
    //noinspection ConstantValue
    boolean result = detectedIP.equals(null);

    // Assert
    //noinspection ConstantValue
    assertFalse(result);
  }

  @Test
  void equals_whenComparedToNonDetectedIP_returnsFalse() {
    // Arrange
    DetectedIP detectedIP = new DetectedIP(inet4(203, 0, 113, 2), DetectedIP.FULL_INTERNET);
    Object other = "not a DetectedIP";
    Object left = detectedIP;

    // Act
    boolean result = equalsAsObjects(left, other);

    // Assert
    assertFalse(result);
  }

  @Test
  void equals_whenSameAddressAndNatType_returnsTrue() {
    // Arrange
    InetAddress address = inet4(203, 0, 113, 3);
    short natType = DetectedIP.PORT_RESTRICTED_NAT;
    DetectedIP first = new DetectedIP(address, natType);
    DetectedIP second = new DetectedIP(address, natType);

    // Act
    boolean result = first.equals(second);

    // Assert
    assertTrue(result);
  }

  @Test
  void equals_whenDifferentNatType_returnsFalse() {
    // Arrange
    InetAddress address = inet4(203, 0, 113, 4);
    DetectedIP first = new DetectedIP(address, DetectedIP.FULL_INTERNET);
    DetectedIP second = new DetectedIP(address, DetectedIP.SYMMETRIC_NAT);

    // Act
    boolean result = first.equals(second);

    // Assert
    assertFalse(result);
  }

  @Test
  void equals_whenDifferentAddress_returnsFalse() {
    // Arrange
    short natType = DetectedIP.FULL_INTERNET;
    DetectedIP first = new DetectedIP(inet4(203, 0, 113, 5), natType);
    DetectedIP second = new DetectedIP(inet4(203, 0, 113, 6), natType);

    // Act
    boolean result = first.equals(second);

    // Assert
    assertFalse(result);
  }

  @Test
  void equals_whenMtuDiffers_stillEqualButToStringDiffers() {
    // Arrange
    InetAddress address = inet4(203, 0, 113, 7);
    short natType = DetectedIP.FULL_INTERNET;
    DetectedIP first = new DetectedIP(address, natType);
    DetectedIP second = new DetectedIP(address, natType);
    second.setMtu(1280);

    // Act
    boolean equalsResult = first.equals(second);

    // Assert
    assertTrue(equalsResult);
    assertEquals(first.hashCode(), second.hashCode());
    assertNotEquals(first.toString(), second.toString());
  }

  @Test
  void equals_whenArgumentHasNullAddress_throwsNullPointerException() {
    // Arrange
    DetectedIP receiver = new DetectedIP(inet4(203, 0, 113, 8), DetectedIP.FULL_INTERNET);
    DetectedIP argument = new DetectedIP(null, DetectedIP.FULL_INTERNET);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> receiver.equals(argument));
  }

  @Test
  void equals_whenThisHasNullAddressAndArgumentNonNull_returnsFalse() {
    // Arrange
    DetectedIP receiver = new DetectedIP(null, DetectedIP.FULL_INTERNET);
    DetectedIP argument = new DetectedIP(inet4(203, 0, 113, 9), DetectedIP.FULL_INTERNET);

    // Act
    boolean result = receiver.equals(argument);

    // Assert
    assertFalse(result);
  }

  @Test
  void hashCode_whenEqualObjects_haveSameHashCode() {
    // Arrange
    InetAddress address = inet4(198, 51, 100, 1);
    short natType = DetectedIP.SYMMETRIC_UDP_FIREWALL;
    DetectedIP first = new DetectedIP(address, natType);
    DetectedIP second = new DetectedIP(address, natType);

    // Act
    int firstHash = first.hashCode();
    int secondHash = second.hashCode();

    // Assert
    assertEquals(firstHash, secondHash);
  }

  @Test
  void toString_whenCalled_includesNatTypeAndMtuSuffix() {
    // Arrange
    InetAddress address = inet4(203, 0, 113, 10);
    DetectedIP detectedIP = new DetectedIP(address, DetectedIP.NO_UDP);
    detectedIP.setMtu(1400);

    // Act
    String stringValue = detectedIP.toString();

    // Assert
    assertTrue(stringValue.endsWith(":" + DetectedIP.NO_UDP + ":" + 1400));
    assertTrue(stringValue.startsWith(address.toString()));
  }

  @Test
  void toString_whenAddressIsNull_throwsNullPointerException() {
    // Arrange
    DetectedIP detectedIP = new DetectedIP(null, DetectedIP.NO_UDP);

    // Act + Assert
    assertThrows(NullPointerException.class, detectedIP::toString);
  }

  private static InetAddress inet4(int a, int b, int c, int d) {
    try {
      return InetAddress.getByAddress(new byte[] {(byte) a, (byte) b, (byte) c, (byte) d});
    } catch (UnknownHostException e) {
      throw new AssertionError("Failed to create InetAddress for numeric IPv4 literal", e);
    }
  }
}
