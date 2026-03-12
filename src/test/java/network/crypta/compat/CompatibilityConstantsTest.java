package network.crypta.compat;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class CompatibilityConstantsTest {

  @Test
  void forwardPortProtocolConstants_whenRead_expectLegacyIanaValues() {
    assertEquals(17, ForwardPort.PROTOCOL_UDP_IPV4);
    assertEquals(6, ForwardPort.PROTOCOL_TCP_IPV4);
    assertEquals(17, ForwardPort.PROTOCOL_UDP_IPV6);
  }

  @Test
  void detectedIpNatTypeConstants_whenRead_expectLegacyNumericMapping() {
    assertEquals(1, DetectedIP.NOT_SUPPORTED);
    assertEquals(2, DetectedIP.FULL_INTERNET);
    assertEquals(3, DetectedIP.FULL_CONE_NAT);
    assertEquals(4, DetectedIP.RESTRICTED_CONE_NAT);
    assertEquals(5, DetectedIP.PORT_RESTRICTED_NAT);
    assertEquals(6, DetectedIP.SYMMETRIC_NAT);
    assertEquals(7, DetectedIP.SYMMETRIC_UDP_FIREWALL);
    assertEquals(8, DetectedIP.NO_UDP);
  }

  @Test
  void detectedIpConstructor_whenMtuOmitted_expectLegacyDefaultMtu() throws Exception {
    DetectedIP detectedIp = new DetectedIP(InetAddress.getByName("203.0.113.7"), DetectedIP.NO_UDP);

    assertEquals(1500, DetectedIP.DEFAULT_MTU);
    assertEquals(DetectedIP.DEFAULT_MTU, detectedIp.getMtu());
  }

  @Test
  @SuppressWarnings("java:S3415")
  void forwardPortStatusConstants_whenRead_expectLegacyCompatibilityValues() {
    assertEquals(3, ForwardPortStatus.DEFINITE_SUCCESS);
    assertEquals(2, ForwardPortStatus.PROBABLE_SUCCESS);
    assertEquals(1, ForwardPortStatus.MAYBE_SUCCESS);
    assertEquals(0, ForwardPortStatus.IN_PROGRESS);
    assertEquals(-1, ForwardPortStatus.PROBABLE_FAILURE);
    assertEquals(-2, ForwardPortStatus.DEFINITE_FAILURE);
  }
}
