package network.crypta.runtime.spi;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AlertSeverityTest {

  @ParameterizedTest
  @MethodSource("knownPriorityClasses")
  void fromPriorityClass_whenKnownValueProvided_expectMatchingSeverityAndRoundTrip(
      short priorityClass, AlertSeverity expectedSeverity) {
    AlertSeverity severity = AlertSeverity.fromPriorityClass(priorityClass);

    assertEquals(expectedSeverity, severity);
    assertEquals(priorityClass, severity.priorityClass());
  }

  @Test
  void fromPriorityClass_whenUnknownValueProvided_expectIllegalArgumentException() {
    IllegalArgumentException error =
        assertThrows(
            IllegalArgumentException.class, () -> AlertSeverity.fromPriorityClass((short) 9));

    assertEquals("Unknown alert priority class: 9", error.getMessage());
  }

  private static Stream<Arguments> knownPriorityClasses() {
    return Stream.of(
        Arguments.of((short) 0, AlertSeverity.CRITICAL_ERROR),
        Arguments.of((short) 1, AlertSeverity.ERROR),
        Arguments.of((short) 2, AlertSeverity.WARNING),
        Arguments.of((short) 3, AlertSeverity.MINOR));
  }
}
