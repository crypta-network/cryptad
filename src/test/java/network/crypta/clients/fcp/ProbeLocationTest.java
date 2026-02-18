package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
class ProbeLocationTest {

  @Test
  void constructor_whenIdentifierProvided_setsIdentifierAndLocationField() {
    ProbeLocation response = new ProbeLocation("req-123", 0.42d);

    SimpleFieldSet fields = response.getFieldSet();

    assertEquals("req-123", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(Double.toString(0.42d), fields.get(FCPMessage.LOCATION));
  }

  @Test
  void constructor_whenIdentifierNull_omitsIdentifierField() {
    ProbeLocation response = new ProbeLocation(null, -0.75d);

    SimpleFieldSet fields = response.getFieldSet();

    assertNull(fields.get(FCPMessage.IDENTIFIER));
    assertEquals(Double.toString(-0.75d), fields.get(FCPMessage.LOCATION));
  }

  @Test
  void getName_whenCalled_returnsProtocolName() {
    ProbeLocation response = new ProbeLocation("req-456", 1.0d);

    assertEquals("ProbeLocation", response.getName());
  }
}
