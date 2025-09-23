package network.crypta.config;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class CryptadConfigExpandTest {
  @Test
  public void expandsCurlyPlaceholders() {
    Map<String, String> base = new HashMap<>();
    base.put("configDir", "/tmp/cfg");
    String out = CryptadConfig.expandValue("${configDir}", base);
    assertEquals("/tmp/cfg", out.replace('\\', '/'));
  }
}
