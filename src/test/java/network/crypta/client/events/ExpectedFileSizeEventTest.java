package network.crypta.client.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ExpectedFileSizeEventTest {

  @Test
  void getCode_whenInvoked_expectConstantCode() {
    // Arrange
    ExpectedFileSizeEvent event = new ExpectedFileSizeEvent(123L);

    // Act
    int code = event.getCode();

    // Assert
    assertEquals(0x0C, code, "Event code should match the defined constant");
  }

  @ParameterizedTest(name = "size={0}")
  @CsvSource({"0", "1", "-1", "1024", "-1024", "9223372036854775807", "-9223372036854775808"})
  void constructor_andField_whenGivenValue_expectStored(long size) {
    // Arrange & Act
    ExpectedFileSizeEvent event = new ExpectedFileSizeEvent(size);

    // Assert
    assertEquals(size, event.expectedSize, "Expected size field must reflect constructor value");
  }

  @ParameterizedTest(name = "desc for size={0}")
  @CsvSource({"0", "1", "-1", "1024", "-1024", "9223372036854775807", "-9223372036854775808"})
  void getDescription_whenVariousSizes_expectFormattedString(long size) {
    // Arrange
    ExpectedFileSizeEvent event = new ExpectedFileSizeEvent(size);

    // Act
    String desc = event.getDescription();

    // Assert
    assertNotNull(desc, "Description must be non-null");
    assertEquals(
        "Expected file size: " + size,
        desc,
        "Description must embed the expected size with the exact prefix");
  }
}
