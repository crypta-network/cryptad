package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class ProbeLinkLengthsTest {

  @Test
  void constructor_whenIdentifierProvided_populatesIdentifierAndLinkLengths() {
    String identifier = "probe-identifier";
    float[] linkLengths = {0.5f, 1.25f, 64.0f};

    ProbeLinkLengths response = new ProbeLinkLengths(identifier, linkLengths);

    SimpleFieldSet fields = response.getFieldSet();
    assertEquals(identifier, fields.get(FCPMessage.IDENTIFIER));
    assertArrayEquals(
        linkLengths, parseFloatValues(fields.getAll(FCPMessage.LINK_LENGTHS)), 1.0e-6f);
  }

  @Test
  void constructor_whenIdentifierNull_omitsIdentifierButPreservesLinkLengths() {
    float[] linkLengths = {42.0f};

    ProbeLinkLengths response = new ProbeLinkLengths(null, linkLengths);

    SimpleFieldSet fields = response.getFieldSet();
    assertNull(fields.get(FCPMessage.IDENTIFIER));
    assertArrayEquals(
        linkLengths, parseFloatValues(fields.getAll(FCPMessage.LINK_LENGTHS)), 1.0e-6f);
  }

  @Test
  void constructor_whenLinkLengthsEmpty_doesNotAddLinkLengthsField() {
    ProbeLinkLengths response = new ProbeLinkLengths("req", new float[0]);

    SimpleFieldSet fields = response.getFieldSet();
    assertNull(fields.get(FCPMessage.LINK_LENGTHS));
  }

  @Test
  void constructor_whenLinkLengthsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new ProbeLinkLengths("req", null));
  }

  @Test
  void getName_whenCalled_returnsProbeLinkLengthsLiteral() {
    ProbeLinkLengths response = new ProbeLinkLengths("req", new float[] {1.0f});

    assertEquals("ProbeLinkLengths", response.getName());
  }

  private static float[] parseFloatValues(String[] values) {
    if (values == null) {
      return new float[0];
    }
    float[] result = new float[values.length];
    for (int i = 0; i < values.length; i++) {
      result[i] = Float.parseFloat(values[i]);
    }
    return result;
  }
}
