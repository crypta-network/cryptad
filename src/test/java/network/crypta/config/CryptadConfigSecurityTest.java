package network.crypta.config;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CryptadConfigSecurityTest {

  @TempDir Path tmp;

  private Map<String, String> base() {
    Map<String, String> b = new HashMap<>();
    Path root = tmp;
    b.put("configDir", root.resolve("cfg").toString());
    b.put("dataDir", root.resolve("data").toString());
    b.put("stateDir", root.resolve("data").toString());
    b.put("cacheDir", root.resolve("cache").toString());
    b.put("runDir", root.resolve("run").toString());
    b.put("logsDir", root.resolve("logs").toString());
    b.put("home", root.resolve("home").toString());
    b.put("tmp", root.resolve("tmp").toString());
    return b;
  }

  @Test
  void rejectsTraversal_inLeadingTokenForm() {
    Map<String, String> b = base();
    assertThrows(IOException.class, () -> CryptadConfig.expandValue("dataDir/../../etc/passwd", b));
  }

  @Test
  void rejectsTraversal_inPlaceholderForm() {
    Map<String, String> b = base();
    assertThrows(
        IOException.class, () -> CryptadConfig.expandValue("${dataDir}/../../etc/passwd", b));
  }

  @Test
  void allowsNormalization_withinBase() {
    Map<String, String> b = base();
    String expanded = CryptadConfig.expandValue("dataDir/foo/../bar", b);
    assertEquals(expanded, Path.of(b.get("dataDir"), "bar").toString());
  }
}
