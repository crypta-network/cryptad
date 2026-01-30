package network.crypta.node.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100") // test naming style: method_whenCondition_expectOutcome
class TypeTest {

  @ParameterizedTest
  @EnumSource(Type.class)
  @DisplayName("valueOf(code) round-trips for all declared enum constants")
  void valueOf_whenGivenKnownCode_expectSameEnum(Type expected) {
    // Arrange
    byte code = expected.code;
    // Act
    boolean valid = Type.isValid(code);
    Type actual = Type.valueOf(code);
    // Assert
    assertTrue(valid, "isValid should be true for all declared codes");
    assertEquals(expected, actual, "valueOf(code) must return the same enum constant");
    assertEquals(code, actual.code, "Returned enum should expose the same code");
  }

  @ParameterizedTest
  @MethodSource("invalidCodes")
  @DisplayName("valueOf(code) throws for invalid codes and isValid is false")
  void valueOf_whenInvalidCode_expectIllegalArgumentException(byte code) {
    // Arrange - none
    // Act + Assert
    assertFalse(Type.isValid(code), "isValid must be false for invalid code");
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> Type.valueOf(code));
    assertEquals("There is no ProbeType with code " + code + ".", ex.getMessage());
  }

  static Stream<Byte> invalidCodes() {
    return Stream.of((byte) -1, Byte.MIN_VALUE, (byte) Type.values().length, Byte.MAX_VALUE);
  }

  @Test
  @DisplayName("isValid honors lower/upper boundaries around declared range")
  void isValid_whenBoundaryCodes_expectCorrectBooleans() {
    // Arrange
    byte lowest = 0;
    byte highest = (byte) (Type.values().length - 1);
    byte justAbove = (byte) (highest + 1);
    byte justBelow = -1;
    // Act + Assert
    assertTrue(Type.isValid(lowest));
    assertTrue(Type.isValid(highest));
    assertFalse(Type.isValid(justAbove));
    assertFalse(Type.isValid(justBelow));
  }
}
