package network.crypta.node.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Tests conversion from code and code validity. */
@SuppressWarnings("java:S100")
class ErrorTest {

  @Test
  void isValid_whenCodeIsEnumCode_expectTrue() {
    for (Error t : Error.values()) {
      final byte code = t.code;
      assertTrue(
          Error.isValid(code),
          "isValid() returned false for valid code " + code + " (" + t.name() + ")");
      assertEquals(code, Error.valueOf(code).code, "valueOf() round-trip should preserve code");
    }
  }

  @Test
  void isValid_whenCodeIsNotAnEnumCode_expectFalse() {
    HashSet<Byte> validCodes = new HashSet<>();
    for (Error error : Error.values()) {
      validCodes.add(error.code);
    }

    for (byte code = Byte.MIN_VALUE; ; code++) {
      if (!validCodes.contains(code)) {
        assertFalse(Error.isValid(code), "isValid() returned true for invalid code " + code);
        final byte theCode = code;
        assertThrows(
            IllegalArgumentException.class,
            () -> Error.valueOf(theCode),
            "valueOf() should throw for invalid code " + code);
      }
      if (code == Byte.MAX_VALUE) break;
    }
  }

  static Stream<Arguments> codeToEnumProvider() {
    return Stream.of(
        Arguments.of((byte) 0, Error.DISCONNECTED),
        Arguments.of((byte) 1, Error.OVERLOAD),
        Arguments.of((byte) 2, Error.TIMEOUT),
        Arguments.of((byte) 3, Error.UNKNOWN),
        Arguments.of((byte) 4, Error.UNRECOGNIZED_TYPE),
        Arguments.of((byte) 5, Error.CANNOT_FORWARD));
  }

  @ParameterizedTest
  @MethodSource("codeToEnumProvider")
  void valueOf_whenValidCode_expectExpectedEnum(byte code, Error expected) {
    Error actual = Error.valueOf(code);
    assertEquals(expected, actual, "valueOf() should map code to expected enum constant");
    assertEquals(code, actual.code, "Enum constant should expose the same code value");
  }

  @ParameterizedTest
  @MethodSource("invalidCodesProvider")
  void valueOf_whenInvalidCode_expectException(byte invalid) {
    assertThrows(IllegalArgumentException.class, () -> Error.valueOf(invalid));
  }

  static Stream<Arguments> invalidCodesProvider() {
    return Stream.of(
        Arguments.of((byte) -1),
        Arguments.of((byte) 6),
        Arguments.of(Byte.MIN_VALUE),
        Arguments.of(Byte.MAX_VALUE));
  }
}
