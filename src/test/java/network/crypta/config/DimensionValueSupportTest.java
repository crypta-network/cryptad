package network.crypta.config;

import java.util.Map;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ResourceLock("NodeL10n.base")
class DimensionValueSupportTest {
  @Test
  void trimPerSecond_whenStandardQualifiers_expectRemoved() {
    assertEquals("100KiB", DimensionValueSupport.trimPerSecond("100KiB/s"));
    assertEquals("100KiB", DimensionValueSupport.trimPerSecond("100KiB/SEC"));
    assertEquals("100KiB", DimensionValueSupport.trimPerSecond("100KiB/second"));
    assertEquals("100KiB", DimensionValueSupport.trimPerSecond("100KiBps"));
    assertEquals("100KiB", DimensionValueSupport.trimPerSecond("  100KiBps  "));
  }

  @Test
  void trimPerSecond_whenBlankOrMissingQualifier_expectNormalizedValue() {
    assertEquals("", DimensionValueSupport.trimPerSecond("   "));
    assertEquals("100KiB", DimensionValueSupport.trimPerSecond("  100KiB  "));
  }

  @Test
  void trimPerSecond_whenLocalizedQualifier_expectRemoved() {
    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      BaseL10n base = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);
      when(base.getString("FirstTimeWizardToadlet.bandwidthPerSecond")).thenReturn("/sek");

      assertEquals("100KiB", DimensionValueSupport.trimPerSecond("100KiB/SEK"));
    }
  }

  @Test
  void parseInt_whenBandwidthInputs_expectParsedBytes() {
    Map<String, Integer> inputs =
        Map.of(
            "50 KiB/s", 50 * 1024,
            "1.5 MiB/sec", 3 * 1024 * 1024 / 2,
            "128 kbps", (128 / 8) * 1000,
            "20 KiB", 20 * 1024,
            "5800", 5800);

    inputs.forEach(
        (input, expected) ->
            assertEquals(
                expected,
                DimensionValueSupport.parseInt(
                    DimensionValueSupport.trimPerSecond(input), Dimension.SIZE),
                "Input: %s".formatted(input)));
  }

  @Test
  void parseInt_whenDuration_expectMillis() {
    assertEquals(90_000, DimensionValueSupport.parseInt("1m30s", Dimension.DURATION));
  }

  @Test
  void parseInt_whenDurationOverflow_expectArithmeticException() {
    assertThrows(
        ArithmeticException.class,
        () -> DimensionValueSupport.parseInt("10000000000s", Dimension.DURATION));
  }

  @Test
  void intToString_whenDuration_expectFormattedDuration() {
    assertEquals("1h30m", DimensionValueSupport.intToString(5_400_000, Dimension.DURATION));
  }

  @Test
  void intToString_whenSize_expectHumanReadableUnits() {
    assertEquals("2k", DimensionValueSupport.intToString(2000, Dimension.NOT));
    assertEquals("2KiB", DimensionValueSupport.intToString(2048, Dimension.SIZE));
  }
}
