package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class ProbeIdentifierTest {

  @Test
  void constructor_whenIdentifierProvided_populatesIdentifierAndProbeFields() {
    String identifier = "req-789";
    long probeIdentifier = 42_123_456L;
    long uptimePercentage = 9833L;

    ProbeIdentifier response = new ProbeIdentifier(identifier, probeIdentifier, uptimePercentage);

    SimpleFieldSet fieldSet = response.getFieldSet();
    assertEquals(identifier, fieldSet.get(FCPMessage.IDENTIFIER));
    assertEquals(probeIdentifier, Long.parseLong(fieldSet.get(FCPMessage.PROBE_IDENTIFIER)));
    assertEquals(uptimePercentage, Long.parseLong(fieldSet.get(FCPMessage.UPTIME_PERCENT)));
  }

  @Test
  void constructor_whenIdentifierNull_omitsIdentifierField() {
    long probeIdentifier = 99L;
    long uptimePercentage = 10000L;

    ProbeIdentifier response = new ProbeIdentifier(null, probeIdentifier, uptimePercentage);

    SimpleFieldSet fieldSet = response.getFieldSet();
    assertNull(fieldSet.get(FCPMessage.IDENTIFIER));
    assertEquals(probeIdentifier, Long.parseLong(fieldSet.get(FCPMessage.PROBE_IDENTIFIER)));
    assertEquals(uptimePercentage, Long.parseLong(fieldSet.get(FCPMessage.UPTIME_PERCENT)));
  }

  @Test
  void getName_whenCalled_returnsProbeIdentifierLiteral() {
    ProbeIdentifier response = new ProbeIdentifier("any", 1L, 2L);

    assertEquals("ProbeIdentifier", response.getName());
  }
}
