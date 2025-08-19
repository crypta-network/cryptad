package network.crypta.support;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;
import network.crypta.config.Dimension;
import org.junit.Test;

/** Tests parsing of duration value. */
public class FieldsDurationTest {

  /** Duration input with and without various d|h|min|s. With correct result in millis */
  private static final Map<String, Integer> durations =
      new HashMap<String, Integer>() {
        {
          put("2d", 172_800_000);
          put("3h", 10_800_000);
          put("20m", 1_200_000);
          put("56s", 56_000);
          put("1h30m", 5_400_000);
        }
      };

  @Test
  public void test() {
    durations.forEach(
        (duration, millis) -> {
          Integer parsed = Fields.parseInt(Fields.trimPerSecond(duration), Dimension.DURATION);
          assertEquals(
              "Input: %s; Intended: %d; Parsed: %d".formatted(duration, millis, parsed),
              millis,
              parsed);

          String packed = Fields.intToString(millis, Dimension.DURATION);
          assertEquals(
              "Input: %d; Intended: %s; Packed: %s".formatted(millis, duration, packed),
              duration,
              packed);
        });
  }
}
