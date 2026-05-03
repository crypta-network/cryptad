package network.crypta.platform.apphost.sandbox;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BubblewrapAvailabilityTest {
  @Test
  void sandboxPreflightCommand_whenBuilt_expectUsesBubblewrapSelfNoop() {
    List<String> command = BubblewrapAvailability.sandboxPreflightCommand("bwrap");

    int separator = command.indexOf("--");

    assertEquals("bwrap", command.getFirst());
    assertTrue(separator > 0);
    assertEquals(
        List.of("/proc/self/exe", "--version"), command.subList(separator + 1, command.size()));
    assertFalse(command.contains("/bin/true"));
  }
}
