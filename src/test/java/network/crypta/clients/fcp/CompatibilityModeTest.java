package network.crypta.clients.fcp;

import network.crypta.client.InsertContext;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CompatibilityModeTest {

  @Mock private CompatibilityAnalyser analyser;

  @Test
  void getFieldSet_whenCryptoKeyPresent_expectAllFieldsWritten() {
    when(analyser.min()).thenReturn(InsertContext.CompatibilityMode.COMPAT_1250);
    when(analyser.max()).thenReturn(InsertContext.CompatibilityMode.COMPAT_1468);
    byte[] cryptoKey = new byte[] {0x00, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
    when(analyser.getCryptoKey()).thenReturn(cryptoKey);
    when(analyser.dontCompress()).thenReturn(true);
    when(analyser.definitive()).thenReturn(true);

    CompatibilityMode message = new CompatibilityMode("alpha", true, analyser);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("COMPAT_1250", result.get("Min"));
    assertEquals("3", result.get("Min.Number"));
    assertEquals("COMPAT_1468", result.get("Max"));
    assertEquals("7", result.get("Max.Number"));
    assertEquals("alpha", result.get("Identifier"));
    assertEquals("true", result.get("Global"));
    assertEquals("00abcdef", result.get("SplitfileCryptoKey"));
    assertEquals("true", result.get("DontCompress"));
    assertEquals("true", result.get("Definitive"));
  }

  @Test
  void getFieldSet_whenCryptoKeyMissing_expectOptionalKeyOmitted() {
    when(analyser.min()).thenReturn(InsertContext.CompatibilityMode.COMPAT_1251);
    when(analyser.max()).thenReturn(InsertContext.CompatibilityMode.COMPAT_1255);
    when(analyser.getCryptoKey()).thenReturn(null);
    when(analyser.dontCompress()).thenReturn(false);
    when(analyser.definitive()).thenReturn(false);

    CompatibilityMode message = new CompatibilityMode("beta", false, analyser);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("false", result.get("Global"));
    assertNull(result.get("SplitfileCryptoKey"));
    assertEquals("false", result.get("DontCompress"));
    assertEquals("false", result.get("Definitive"));
  }

  @Test
  void getName_whenCalled_returnsCompatibilityMode() {
    CompatibilityMode message = new CompatibilityMode("id", true, analyser);

    assertEquals("CompatibilityMode", message.getName());
  }

  @Test
  void run_whenInvoked_expectUnsupportedOperation() {
    CompatibilityMode message = new CompatibilityMode("id", true, analyser);

    assertThrows(UnsupportedOperationException.class, () -> message.run(null, null));
  }

  @Test
  void getModes_whenCalled_returnsDelegateResult() {
    InsertContext.CompatibilityMode[] expected =
        new InsertContext.CompatibilityMode[] {
          InsertContext.CompatibilityMode.COMPAT_1250, InsertContext.CompatibilityMode.COMPAT_1468
        };
    when(analyser.getModes()).thenReturn(expected);

    CompatibilityMode message = new CompatibilityMode("id", true, analyser);

    assertSame(expected, message.getModes());
    verify(analyser).getModes();
  }
}
