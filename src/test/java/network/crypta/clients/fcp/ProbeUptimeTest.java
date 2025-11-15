package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class ProbeUptimeTest {

  @Test
  void constructor_whenIdentifierProvided_populatesIdentifierAndUptimePercent() {
    String identifier = "uptime-req-42";
    double uptimePercent = 99.875;

    ProbeUptime response = new ProbeUptime(identifier, uptimePercent);

    SimpleFieldSet fieldSet = response.getFieldSet();
    assertEquals(identifier, fieldSet.get(FCPMessage.IDENTIFIER));
    assertEquals(uptimePercent, Double.parseDouble(fieldSet.get(FCPMessage.UPTIME_PERCENT)));
  }

  @Test
  void constructor_whenIdentifierNull_omitsIdentifierFieldButStoresUptime() {
    double uptimePercent = 0.1234;

    ProbeUptime response = new ProbeUptime(null, uptimePercent);

    SimpleFieldSet fieldSet = response.getFieldSet();
    assertNull(fieldSet.get(FCPMessage.IDENTIFIER));
    assertEquals(uptimePercent, Double.parseDouble(fieldSet.get(FCPMessage.UPTIME_PERCENT)));
  }

  @Test
  void getName_whenCalled_returnsProbeUptimeLiteral() {
    ProbeUptime response = new ProbeUptime("any", 12.34);

    assertEquals("ProbeUptime", response.getName());
  }
}
