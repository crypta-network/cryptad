package network.crypta.client.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class EnterFiniteCooldownEventTest {

  private static final String PREFIX = "Wake up in ";

  @Test
  void getCode_whenInvoked_expectConstantCode() {
    // Arrange
    long wakeup = System.currentTimeMillis() + 1000L;
    EnterFiniteCooldownEvent event = new EnterFiniteCooldownEvent(wakeup);

    // Act
    int code = event.getCode();

    // Assert
    assertEquals(0x10, code, "Event code should match the defined constant");
  }

  @Test
  void getDescription_whenFutureWithinSeconds_expectFractionalSeconds() {
    // Arrange
    long targetDeltaMs = 1500L; // ~1.5s in the future
    long wakeup = System.currentTimeMillis() + targetDeltaMs;
    EnterFiniteCooldownEvent event = new EnterFiniteCooldownEvent(wakeup);

    String desc = event.getDescription();

    // Assert
    assertNotNull(desc);
    assertTrue(desc.startsWith(PREFIX), "Description should start with the fixed prefix");

    double seconds = extractTrailingSeconds(desc);
    // Allow a generous range to avoid flakiness due to scheduling/CPU variance.
    assertTrue(
        seconds > 0.9 && seconds <= 1.6,
        () -> "Expected seconds within (0.9, 1.6], got: " + seconds + " for: " + desc);
  }

  @Test
  void getDescription_whenInPast_expectNegativeFractionalSeconds() {
    // Arrange
    long wakeup = System.currentTimeMillis() - 250L; // 0.25s in the past
    EnterFiniteCooldownEvent event = new EnterFiniteCooldownEvent(wakeup);

    // Act
    String desc = event.getDescription();

    // Assert
    assertNotNull(desc);
    assertTrue(desc.startsWith(PREFIX), "Description should start with the fixed prefix");

    double seconds = extractTrailingSeconds(desc);
    assertTrue(
        seconds < 0.0 && seconds >= -1.0,
        () -> "Expected a small negative seconds value, got: " + seconds + " for: " + desc);
  }

  @Test
  void getDescription_whenMinutePlusSeconds_expectMinuteAndFractionalSeconds() {
    // Arrange
    long targetDeltaMs = 60_000L + 2_500L; // ~1m 2.5s in the future
    long wakeup = System.currentTimeMillis() + targetDeltaMs;
    EnterFiniteCooldownEvent event = new EnterFiniteCooldownEvent(wakeup);

    // Act
    String desc = event.getDescription();

    // Assert
    assertNotNull(desc);
    assertTrue(
        desc.startsWith(PREFIX + "1m"),
        () -> "Expected description to include '1m' prefix, got: " + desc);

    double seconds = extractTrailingSeconds(desc);
    assertTrue(
        seconds > 1.5 && seconds <= 3.0,
        () -> "Expected roughly 2.5s remaining after minutes, got: " + seconds + " for: " + desc);
  }

  // Extracts the trailing seconds component (with optional leading minus sign) from the
  // description string. The format is guaranteed by TimeUtil to use a dot as the decimal
  // separator with exactly three fractional digits when fractions are present.
  private static double extractTrailingSeconds(String description) {
    String tail = description.substring(PREFIX.length());
    Pattern p = Pattern.compile("(-?\\d+(?:\\.\\d{3})?)s$");
    Matcher m = p.matcher(tail);
    if (!m.find()) {
      throw new AssertionError("Could not parse seconds from description: " + description);
    }
    return Double.parseDouble(m.group(1));
  }
}
