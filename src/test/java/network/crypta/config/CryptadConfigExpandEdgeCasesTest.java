package network.crypta.config;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class CryptadConfigExpandEdgeCasesTest {

  @Rule public TemporaryFolder tmp = new TemporaryFolder();

  private Map<String, String> base() {
    Map<String, String> b = new HashMap<>();
    Path root = tmp.getRoot().toPath();
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
  public void leadingToken_backslashes_normalizesWithinBase() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("dataDir\\foo\\..\\bar", b);
    assertEquals(Path.of(b.get("dataDir"), "bar").toString(), out);
  }

  @Test
  public void leadingToken_posixSegments_normalizesWithinBase() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("cacheDir/./tmp/../persist", b);
    assertEquals(Path.of(b.get("cacheDir"), "persist").toString(), out);
  }

  @Test
  public void placeholder_equality_resolvesToBase() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("${logsDir}", b);
    assertEquals(Path.of(b.get("logsDir")).normalize().toString(), out);
  }

  @Test(expected = IOException.class)
  public void placeholder_windowsTraversal_rejectedWhenAnchored() {
    Map<String, String> b = base();
    CryptadConfig.expandValue("${dataDir}\\..\\..\\etc\\passwd", b);
  }

  @Test
  public void placeholder_inMiddle_isReplaced() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("prefix-${cacheDir}-suffix", b);
    assertEquals("prefix-" + b.get("cacheDir") + "-suffix", out);
  }

  @Test(expected = IOException.class)
  public void placeholder_inMiddle_withTraversal_rejected() {
    Map<String, String> b = base();
    CryptadConfig.expandValue("prefix-${dataDir}/../../etc/passwd", b);
  }

  @Test
  public void leadingToken_backslashDot_normalizes() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("runDir\\.", b);
    assertEquals(Path.of(b.get("runDir")).normalize().toString(), out);
  }
}
