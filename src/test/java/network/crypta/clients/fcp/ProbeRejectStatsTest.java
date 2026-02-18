package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ProbeRejectStatsTest {

  @Test
  @DisplayName("constructor with valid stats populates identifier and reject counters")
  void constructor_whenStatsProvided_setsAllRejectFields() {
    byte[] stats = new byte[] {10, 20, 30, 40};

    ProbeRejectStats response = new ProbeRejectStats("probe-1", stats);
    SimpleFieldSet fields = response.getFieldSet();

    assertEquals("probe-1", fields.get(FCPMessage.IDENTIFIER));
    assertEquals(10, fields.getInt(FCPMessage.BULK_CHK_REQUEST_REJECTS, -1));
    assertEquals(20, fields.getInt(FCPMessage.BULK_SSK_REQUEST_REJECTS, -1));
    assertEquals(30, fields.getInt(FCPMessage.BULK_CHK_INSERT_REJECTS, -1));
    assertEquals(40, fields.getInt(FCPMessage.BULK_SSK_INSERT_REJECTS, -1));
  }

  @Test
  @DisplayName("constructor uses signed byte semantics when writing stats")
  void constructor_whenStatsContainNegativeValues_preservesSign() {
    byte[] stats = new byte[] {-1, -2, 0, 127};

    ProbeRejectStats response = new ProbeRejectStats("probe-2", stats);
    SimpleFieldSet fields = response.getFieldSet();

    assertEquals(-1, fields.getInt(FCPMessage.BULK_CHK_REQUEST_REJECTS, 0));
    assertEquals(-2, fields.getInt(FCPMessage.BULK_SSK_REQUEST_REJECTS, 0));
    assertEquals(0, fields.getInt(FCPMessage.BULK_CHK_INSERT_REJECTS, 99));
    assertEquals(127, fields.getInt(FCPMessage.BULK_SSK_INSERT_REJECTS, 0));
  }

  @Test
  @DisplayName("constructor fails fast when stats array too short")
  void constructor_whenStatsTooShort_throwsException() {
    byte[] stats = new byte[] {1, 2, 3};

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> new ProbeRejectStats("id", stats));
  }

  @Test
  @DisplayName("getName returns ProbeRejectStats")
  void getName_whenCalled_returnsConstant() {
    ProbeRejectStats response = new ProbeRejectStats("probe-name", new byte[] {0, 0, 0, 0});

    assertEquals("ProbeRejectStats", response.getName());
  }
}
