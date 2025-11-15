package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class ProbeOverallBulkOutputCapacityUsageTest {

  @Test
  void constructor_whenIdentifierProvided_populatesIdentifierAndCapacityFields() {
    String identifier = "probe-123";
    byte bandwidthClass = (byte) 7;
    float capacityUsage = 0.8125f;

    ProbeOverallBulkOutputCapacityUsage response =
        new ProbeOverallBulkOutputCapacityUsage(identifier, bandwidthClass, capacityUsage);

    SimpleFieldSet fields = response.getFieldSet();
    assertEquals(identifier, fields.get(FCPMessage.IDENTIFIER));
    assertEquals(bandwidthClass, Byte.parseByte(fields.get(FCPMessage.OUTPUT_BANDWIDTH_CLASS)));
    assertEquals(
        capacityUsage,
        Float.parseFloat(fields.get(FCPMessage.OVERALL_BULK_OUTPUT_CAPACITY_USAGE)),
        0.0001f);
  }

  @Test
  void constructor_whenIdentifierNull_omitsIdentifierButRetainsCapacityFields() {
    byte bandwidthClass = (byte) -5;
    float capacityUsage = 1.0f;

    ProbeOverallBulkOutputCapacityUsage response =
        new ProbeOverallBulkOutputCapacityUsage(null, bandwidthClass, capacityUsage);

    SimpleFieldSet fields = response.getFieldSet();
    assertNull(fields.get(FCPMessage.IDENTIFIER));
    assertEquals(bandwidthClass, Byte.parseByte(fields.get(FCPMessage.OUTPUT_BANDWIDTH_CLASS)));
    assertEquals(
        capacityUsage,
        Float.parseFloat(fields.get(FCPMessage.OVERALL_BULK_OUTPUT_CAPACITY_USAGE)),
        0.0001f);
  }

  @Test
  void getName_whenCalled_returnsProbeOverallBulkOutputCapacityUsageLiteral() {
    ProbeOverallBulkOutputCapacityUsage response =
        new ProbeOverallBulkOutputCapacityUsage("req", (byte) 1, 0.5f);

    assertEquals("ProbeOverallBulkOutputCapacityUsage", response.getName());
  }
}
