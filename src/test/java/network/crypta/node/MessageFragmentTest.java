package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class MessageFragmentTest {

  @ParameterizedTest(name = "length short={0}, fragmented={1}, dataLen={2} -> expected={3}")
  @CsvSource({
    // shortMessage, isFragmented, dataLen, expected
    "true,  true,   10, 14", // 2 + 1 + 1 + 10 = 14
    "true,  false,  10, 13", // 2 + 1 + 0 + 10 = 13
    "false, true,   10, 16", // 2 + 2 + 2 + 10 = 16
    "false, false,  10, 14", // 2 + 2 + 0 + 10 = 14
    "true,  true,    0,  4", // 2 + 1 + 1 + 0 = 4 (empty payload)
  })
  @DisplayName("length() computes header + payload size for all flag combinations")
  void length_whenFlagsVary_expectCalculatedSize(
      boolean shortMessage, boolean isFragmented, int dataLen, int expected) {
    // Arrange
    byte[] data = new byte[dataLen];
    MessageWrapper wrapper = mock(MessageWrapper.class);
    MessageFragment fragment =
        new MessageFragment(
            new MessageFragmentHeader(shortMessage, isFragmented, /* firstFragment= */ true, 123),
            new MessageFragmentSizes(dataLen, dataLen, 0),
            new MessageFragmentPayload(data, wrapper));

    // Act
    int actual = fragment.length();

    // Assert
    assertEquals(expected, actual);
    verifyNoInteractions(wrapper);
  }

  @Test
  @DisplayName("toString() includes message id, offset and payload length")
  void toString_whenCalled_expectFormattedSummary() {
    // Arrange
    byte[] data = new byte[7];
    MessageWrapper wrapper = mock(MessageWrapper.class);
    MessageFragment fragment =
        new MessageFragment(
            new MessageFragmentHeader(true, true, /* firstFragment= */ false, 42),
            new MessageFragmentSizes(999, 12345, 1234),
            new MessageFragmentPayload(data, wrapper));

    // Act
    String s = fragment.toString();

    // Assert
    assertEquals("Fragment from message 42: offset 1234, data length 7", s);
    verifyNoInteractions(wrapper);
  }

  @Test
  @DisplayName("length() uses fragmentData length, not fragmentLength field")
  void length_whenFragmentLengthDiffersFromData_expectDataLengthUsed() {
    // Arrange
    // Mismatch: fragmentLength=100, actual payload length=3
    byte[] data = new byte[] {1, 2, 3};
    MessageWrapper wrapper = mock(MessageWrapper.class);
    MessageFragment fragment =
        new MessageFragment(
            new MessageFragmentHeader(false, false, /* firstFragment= */ true, 77),
            new MessageFragmentSizes(100, 1000, 0),
            new MessageFragmentPayload(data, wrapper));

    // Act
    int actual = fragment.length();

    // Assert
    // For non-short, non-fragmented: 2 (id+flags) + 2 (frag length) + 0 + payload(3) = 7
    assertEquals(7, actual);
    verifyNoInteractions(wrapper);
  }
}
