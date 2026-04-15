package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class CompatibilityModeTest {

  @Test
  void getFieldSet_whenCryptoKeyPresent_expectAllFieldsWritten() {
    FcpCompatibilityAnalysis analyser = new FcpCompatibilityAnalysis();
    byte[] cryptoKey = new byte[] {0x00, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
    analyser.merge(
        FcpCompatibilityMode.COMPAT_1250, FcpCompatibilityMode.COMPAT_1468, cryptoKey, true, true);

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
    FcpCompatibilityAnalysis analyser = new FcpCompatibilityAnalysis();
    analyser.merge(
        FcpCompatibilityMode.COMPAT_1251, FcpCompatibilityMode.COMPAT_1255, null, false, false);

    CompatibilityMode message = new CompatibilityMode("beta", false, analyser);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("false", result.get("Global"));
    assertNull(result.get("SplitfileCryptoKey"));
    assertEquals("false", result.get("DontCompress"));
    assertEquals("false", result.get("Definitive"));
  }

  @Test
  void getName_whenCalled_returnsCompatibilityMode() {
    CompatibilityMode message = new CompatibilityMode("id", true, new FcpCompatibilityAnalysis());

    assertEquals("CompatibilityMode", message.getName());
  }

  @Test
  void run_whenInvoked_expectUnsupportedOperation() {
    CompatibilityMode message = new CompatibilityMode("id", true, new FcpCompatibilityAnalysis());

    assertThrows(UnsupportedOperationException.class, () -> message.run(null));
  }

  @Test
  void getModes_whenCalled_returnsDelegateResult() {
    FcpCompatibilityMode[] expected =
        new FcpCompatibilityMode[] {
          FcpCompatibilityMode.COMPAT_1250, FcpCompatibilityMode.COMPAT_1468
        };
    FcpCompatibilityAnalysis analyser = new FcpCompatibilityAnalysis();
    analyser.merge(
        FcpCompatibilityMode.COMPAT_1250, FcpCompatibilityMode.COMPAT_1468, null, true, false);

    CompatibilityMode message = new CompatibilityMode("id", true, analyser);

    assertArrayEquals(expected, message.getModes());
  }
}
