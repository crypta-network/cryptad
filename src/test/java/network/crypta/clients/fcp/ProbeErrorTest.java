package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ProbeErrorTest {
  @Test
  void constructor_whenCodeProvided_expectFieldsIncludeCode() {
    ProbeError message = new ProbeError("req-1", FcpProbeError.UNKNOWN, (byte) 101, true);

    SimpleFieldSet fields = message.getFieldSet();

    assertEquals("req-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(FcpProbeError.UNKNOWN.name(), fields.get(FCPMessage.TYPE));
    assertEquals("101", fields.get(FCPMessage.CODE));
    assertTrue(fields.getBoolean(FCPMessage.LOCAL, false));
  }

  @Test
  void constructor_whenCodeMissing_expectCodeOmitted() {
    ProbeError message = new ProbeError("req-2", FcpProbeError.TIMEOUT, null, false);

    SimpleFieldSet fields = message.getFieldSet();

    assertEquals("req-2", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(FcpProbeError.TIMEOUT.name(), fields.get(FCPMessage.TYPE));
    assertNull(fields.get(FCPMessage.CODE));
    assertFalse(fields.getBoolean(FCPMessage.LOCAL, true));
  }

  @Test
  void constructor_whenIdentifierMissing_expectIdentifierOmitted() {
    ProbeError message = new ProbeError(null, FcpProbeError.DISCONNECTED, null, true);

    assertNull(message.getFieldSet().get(FCPMessage.IDENTIFIER));
  }

  @Test
  void getName_whenInvoked_expectProtocolName() {
    ProbeError message = new ProbeError("any", FcpProbeError.CANNOT_FORWARD, null, true);

    assertEquals("ProbeError", message.getName());
  }
}
