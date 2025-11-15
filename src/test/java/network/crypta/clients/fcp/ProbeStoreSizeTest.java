package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ProbeStoreSizeTest {

  @Test
  @DisplayName("constructor with identifier stores store size and identifier")
  void constructor_whenIdentifierProvided_setsFields() {
    String identifier = "probe-identifier";
    float storeSize = 12.75f;

    ProbeStoreSize response = new ProbeStoreSize(identifier, storeSize);
    SimpleFieldSet fields = response.getFieldSet();

    assertEquals(identifier, fields.get(FCPMessage.IDENTIFIER));
    assertEquals(storeSize, fields.getDouble(FCPMessage.STORE_SIZE, -1), 1e-6);
  }

  @Test
  @DisplayName("constructor without identifier omits IDENTIFIER but keeps store size")
  void constructor_whenIdentifierNull_omitsIdentifier() {
    float storeSize = -0.5f;

    ProbeStoreSize response = new ProbeStoreSize(null, storeSize);
    SimpleFieldSet fields = response.getFieldSet();

    assertNull(fields.get(FCPMessage.IDENTIFIER));
    assertEquals(storeSize, fields.getDouble(FCPMessage.STORE_SIZE, 0), 1e-6);
  }

  @Test
  @DisplayName("getName always returns ProbeStoreSize")
  void getName_whenCalled_returnsProbeStoreSize() {
    ProbeStoreSize response = new ProbeStoreSize("abc", 1.0f);

    assertEquals("ProbeStoreSize", response.getName());
  }
}
