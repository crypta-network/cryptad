package network.crypta.platform.devtools.devserver;

import network.crypta.platform.appdist.AppDistributionException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LoopbackHostPolicyTest {
  @Test
  void requireAllowedHost_whenHostIsLoopback_expectNoWarning() throws Exception {
    assertEquals("", LoopbackHostPolicy.requireAllowedHost("127.0.0.1", false));
    assertEquals("", LoopbackHostPolicy.requireAllowedHost(" localhost ", false));
    assertTrue(LoopbackHostPolicy.isLoopback("::1"));
  }

  @Test
  void requireAllowedHost_whenHostIsNonLoopbackWithoutOverride_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> LoopbackHostPolicy.requireAllowedHost("0.0.0.0", false));

    assertTrue(exception.getMessage().contains("refusing non-loopback dev server host"));
  }

  @Test
  void requireAllowedHost_whenHostIsNonLoopbackAllowed_expectWarning() throws Exception {
    String warning = LoopbackHostPolicy.requireAllowedHost("0.0.0.0", true);

    assertTrue(warning.contains("non-loopback host"));
    assertFalse(LoopbackHostPolicy.isLoopback(""));
    assertFalse(LoopbackHostPolicy.isLoopback("not a host name"));
  }
}
