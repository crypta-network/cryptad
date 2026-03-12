package network.crypta.client.events;

import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class StartedCompressionEventTest {

  @ParameterizedTest
  @EnumSource(COMPRESSOR_TYPE.class)
  void getDescription_whenCodecProvided_matchesCodecName(COMPRESSOR_TYPE codec) {
    // Arrange
    StartedCompressionEvent event = new StartedCompressionEvent(codec);

    // Act
    String description = event.getDescription();

    // Assert
    assertEquals(
        "Started compression attempt with " + codec.codecName,
        description,
        "Description should include the codec's human-readable name");
  }

  @Test
  void getDescription_whenCodecIsNull_throwsNullPointerException() {
    // Arrange
    StartedCompressionEvent event = new StartedCompressionEvent(null);

    // Act + Assert
    assertThrows(NullPointerException.class, event::getDescription);
  }

  @ParameterizedTest
  @EnumSource(value = COMPRESSOR_TYPE.class)
  void getCode_whenCalled_returnsExpectedConstant(COMPRESSOR_TYPE codec) {
    // Arrange
    StartedCompressionEvent event = new StartedCompressionEvent(codec);

    // Act
    int code = event.getCode();

    // Assert
    assertEquals(0x08, code, "Event code must be the stable constant 0x08");
  }

  @Test
  void codecField_whenConstructed_isSameInstance() {
    // Arrange
    COMPRESSOR_TYPE codec = COMPRESSOR_TYPE.BZIP2;

    // Act
    StartedCompressionEvent event = new StartedCompressionEvent(codec);

    // Assert
    assertSame(codec, event.codec, "Codec field must reference the constructor argument");
  }
}
