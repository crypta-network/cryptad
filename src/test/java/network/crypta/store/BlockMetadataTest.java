package network.crypta.store;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class BlockMetadataTest {

  @Test
  @DisplayName("isOldBlock is false for a new instance")
  void isOldBlock_whenNewInstance_expectFalse() {
    // Arrange
    BlockMetadata metadata = new BlockMetadata();

    // Act
    boolean result = metadata.isOldBlock();

    // Assert
    assertFalse(result, "New BlockMetadata should default to not old");
  }

  @Test
  @DisplayName("setOldBlock sets the flag to true")
  void setOldBlock_whenCalled_expectTrue() {
    // Arrange
    BlockMetadata metadata = new BlockMetadata();

    // Act
    metadata.setOldBlock();

    // Assert
    assertTrue(metadata.isOldBlock(), "setOldBlock should mark block as old");
  }

  @Test
  @DisplayName("reset clears the old flag after being set")
  void reset_whenAfterSetOldBlock_expectFalse() {
    // Arrange
    BlockMetadata metadata = new BlockMetadata();
    metadata.setOldBlock();

    // Act
    metadata.reset();

    // Assert
    assertFalse(metadata.isOldBlock(), "reset should clear the old flag");
  }

  @ParameterizedTest(name = "ops={0} -> isOldBlock={1}")
  @CsvSource({
    "'', false",
    "S, true",
    "R, false",
    "SS, true",
    "RR, false",
    "SR, false",
    "RS, true",
    "SRS, true",
    "RSR, false"
  })
  @DisplayName("Final state after operation sequence matches expectation")
  void finalState_afterOperationSequence_expectExpectedValue(String ops, boolean expected) {
    // Arrange
    BlockMetadata metadata = new BlockMetadata();

    // Act
    applyOps(metadata, ops == null ? "" : ops);

    // Assert
    if (expected) {
      assertTrue(metadata.isOldBlock(), "Expected old=true after ops: " + ops);
    } else {
      assertFalse(metadata.isOldBlock(), "Expected old=false after ops: " + ops);
    }
  }

  private static void applyOps(BlockMetadata metadata, String ops) {
    for (int i = 0; i < ops.length(); i++) {
      char c = ops.charAt(i);
      if (c == 'S') {
        metadata.setOldBlock();
      } else if (c == 'R') {
        metadata.reset();
      } else {
        throw new IllegalArgumentException("Unknown op '" + c + "' in sequence: " + ops);
      }
    }
  }
}
