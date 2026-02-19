package network.crypta.launcher;

import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WrapperConfUtilsTest {
  @Test
  void upsertAndParseRoundTrip() {
    var updated =
        LauncherUtils.upsertWrapperProperty(
            List.of("wrapper.name=cryptad"), "wrapper.console.flush", "TRUE");
    var props = LauncherUtils.parseWrapperProperties(updated);
    assertEquals("TRUE", props.get("wrapper.console.flush"));
    assertEquals(
        Paths.get("/var/log/cryptad.log"),
        LauncherUtils.computeWrapperLogPath(
            Paths.get("/opt/cryptad/conf/wrapper.conf"), "/var/log/cryptad.log"));
  }
}
