package network.crypta.client.events;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100") // test method naming with underscores
class FinishedCompressionEventTest {

  @Test
  @DisplayName("constructor sets fields as provided")
  void constructor_whenGivenValues_setsFields() {
    // Arrange
    int codec = 7;
    long orig = 1_234_567L;
    long comp = 987_654L;

    // Act
    FinishedCompressionEvent event = new FinishedCompressionEvent(codec, orig, comp);

    // Assert
    assertAll(
        () -> assertEquals(codec, event.codec, "codec should match constructor arg"),
        () -> assertEquals(orig, event.originalSize, "originalSize should match constructor arg"),
        () ->
            assertEquals(
                comp, event.compressedSize, "compressedSize should match constructor arg"));
  }

  @ParameterizedTest(name = "codec={0}, orig={1}, comp={2}")
  @MethodSource("descriptionCases")
  void getDescription_whenVariousValues_formatsCorrectly(int codec, long orig, long comp) {
    // Arrange
    FinishedCompressionEvent event = new FinishedCompressionEvent(codec, orig, comp);

    // Act
    String description = event.getDescription();

    // Assert
    String expected =
        "Compressed data: codec=" + codec + ", origSize=" + orig + ", compressedSize=" + comp;
    assertEquals(expected, description);
  }

  static Stream<Arguments> descriptionCases() {
    return Stream.of(
        Arguments.of(1, 1000L, 500L), // typical compression
        Arguments.of(-1, 123L, 123L), // uncompressed marker
        Arguments.of(0, 0L, 0L), // zeros
        Arguments.of(Integer.MAX_VALUE, Long.MAX_VALUE, Long.MIN_VALUE) // extremes
        );
  }

  @Test
  void getCode_returnsStableConstant() {
    // Arrange
    FinishedCompressionEvent event = new FinishedCompressionEvent(3, 10L, 8L);

    // Act
    int actualCode = event.getCode();

    // Assert
    assertEquals(0x09, actualCode, "event code must remain stable (0x09)");
  }
}
