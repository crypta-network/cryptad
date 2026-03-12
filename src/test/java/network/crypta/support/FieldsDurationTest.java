package network.crypta.support;

import java.util.Map;
import network.crypta.config.Dimension;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Tests parsing of duration value. */
class FieldsDurationTest {

  /** Duration input with and without various d|h|min|s. With correct result in millis */
  private static final Map<String, Integer> durations =
      Map.ofEntries(
          Map.entry("2d", 172_800_000),
          Map.entry("3h", 10_800_000),
          Map.entry("20m", 1_200_000),
          Map.entry("56s", 56_000),
          Map.entry("1h30m", 5_400_000));

  @Test
  void test() {
    durations.forEach(
        (duration, millis) -> {
          Integer parsed = Fields.parseInt(Fields.trimPerSecond(duration), Dimension.DURATION);
          assertEquals(
              millis,
              parsed,
              "Input: %s; Intended: %d; Parsed: %d".formatted(duration, millis, parsed));

          String packed = Fields.intToString(millis, Dimension.DURATION);
          assertEquals(
              duration,
              packed,
              "Input: %d; Intended: %s; Packed: %s".formatted(millis, duration, packed));
        });
  }
}
