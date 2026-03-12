package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
class ProbeBandwidthTest {

  @Test
  void constructor_whenIdentifierProvided_populatesIdentifierAndBandwidthField() {
    String identifier = "req-123";
    float outputBandwidth = 1024.25f;

    ProbeBandwidth response = new ProbeBandwidth(identifier, outputBandwidth);

    SimpleFieldSet fieldSet = response.getFieldSet();
    assertEquals(identifier, fieldSet.get(FCPMessage.IDENTIFIER));
    assertEquals(
        outputBandwidth, Float.parseFloat(fieldSet.get(FCPMessage.OUTPUT_BANDWIDTH)), 0.0001f);
  }

  @Test
  void constructor_whenIdentifierNull_doesNotPopulateIdentifierField() {
    float outputBandwidth = 512.5f;

    ProbeBandwidth response = new ProbeBandwidth(null, outputBandwidth);

    SimpleFieldSet fieldSet = response.getFieldSet();
    assertNull(fieldSet.get(FCPMessage.IDENTIFIER));
    assertEquals(
        outputBandwidth, Float.parseFloat(fieldSet.get(FCPMessage.OUTPUT_BANDWIDTH)), 0.0001f);
  }

  @Test
  void getName_whenCalled_returnsProbeBandwidthLiteral() {
    ProbeBandwidth response = new ProbeBandwidth("any", 1.0f);

    assertEquals("ProbeBandwidth", response.getName());
  }
}
