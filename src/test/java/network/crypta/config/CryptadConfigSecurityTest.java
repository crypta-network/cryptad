package network.crypta.config;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class CryptadConfigSecurityTest {

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

  @Test(expected = IOException.class)
  public void rejectsTraversal_inLeadingTokenForm() throws IOException {
    Map<String, String> b = base();
    CryptadConfig.expandValue("dataDir/../../etc/passwd", b);
  }

  @Test(expected = IOException.class)
  public void rejectsTraversal_inPlaceholderForm() throws IOException {
    Map<String, String> b = base();
    CryptadConfig.expandValue("${dataDir}/../../etc/passwd", b);
  }

  @Test
  public void allowsNormalization_withinBase() throws IOException {
    Map<String, String> b = base();
    String expanded = CryptadConfig.expandValue("dataDir/foo/../bar", b);
    assertEquals(Path.of(b.get("dataDir"), "bar").toString(), expanded);
  }
}
