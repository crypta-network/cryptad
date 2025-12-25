package network.crypta.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CryptadConfigExpandTest {
  @Test
  void expandsCurlyPlaceholders() {
    Map<String, String> base = new HashMap<>();
    base.put("configDir", "/tmp/cfg");
    String out = CryptadConfig.expandValue("${configDir}", base);
    assertEquals("/tmp/cfg", out.replace('\\', '/'));
  }
}
