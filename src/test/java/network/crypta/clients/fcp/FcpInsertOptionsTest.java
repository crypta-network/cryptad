package network.crypta.clients.fcp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FcpInsertOptionsTest {

  @Test
  void equals_whenConsecutiveRnfsOverrideDiffers_returnsFalse() {
    FcpInsertOptions defaultOptions = newOptions(null);
    FcpInsertOptions strictOptions = newOptions(0);

    assertNotEquals(defaultOptions, strictOptions);
    assertNotEquals(defaultOptions.hashCode(), strictOptions.hashCode());
  }

  @Test
  void hashCode_whenConsecutiveRnfsOverrideMatches_returnsSameHash() {
    FcpInsertOptions first = newOptions(0);
    FcpInsertOptions second = newOptions(0);

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
  }

  @Test
  void toString_whenConsecutiveRnfsOverridePresent_includesOverride() {
    String value = newOptions(0).toString();

    assertTrue(value.contains("consecutiveRnfsCountAsSuccess=0"));
  }

  private static FcpInsertOptions newOptions(Integer consecutiveRnfsCountAsSuccess) {
    return new FcpInsertOptions(
        new FcpInsertBehaviorOptions(
            false, false, false, 1, consecutiveRnfsCountAsSuccess, false, false, false),
        new FcpInsertTuningOptions(true, false, null, 0, 0, FcpCompatibilityMode.COMPAT_CURRENT),
        null);
  }
}
