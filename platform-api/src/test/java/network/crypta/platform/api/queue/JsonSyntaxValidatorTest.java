package network.crypta.platform.api.queue;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class JsonSyntaxValidatorTest {
  @Test
  void validate_whenJsonIsValid_expectNoException() {
    List<String> validDocuments =
        List.of(
            "{\"schema\":\"crypta.profile.v1\",\"tags\":[\"crypta\",\"profile\"]}",
            "[0,-12,3.14,6.02e23,true,false,null]",
            "\"escaped \\\"quote\\\" and unicode \\u0041\"",
            " \n\r\t{\"nested\":{\"array\":[1,{\"ok\":true}]}} \t");

    for (String document : validDocuments) {
      assertDoesNotThrow(() -> JsonSyntaxValidator.validate(document), document);
    }
  }

  @Test
  void validate_whenJsonIsInvalid_expectIllegalArgumentException() {
    List<String> invalidDocuments =
        List.of("", "01", "1.", "{\"a\":}", "[1,]", "\"raw\nnewline\"", "١");

    for (String document : invalidDocuments) {
      assertThrows(
          IllegalArgumentException.class, () -> JsonSyntaxValidator.validate(document), document);
    }
  }

  @Test
  void validate_whenUnicodeEscapeUsesNonAsciiDigits_expectIllegalArgumentException() {
    String arabicIndicZero = Character.toString('٠');
    String document = "\"\\u" + arabicIndicZero.repeat(4) + "\"";

    assertThrows(IllegalArgumentException.class, () -> JsonSyntaxValidator.validate(document));
  }

  @Test
  void validate_whenNestingAtBoundary_expectOnlyTooDeepRejected() {
    String boundaryJson = "[".repeat(64) + "0" + "]".repeat(64);
    String tooDeepJson = "[".repeat(65) + "0" + "]".repeat(65);

    assertDoesNotThrow(() -> JsonSyntaxValidator.validate(boundaryJson));

    assertThrows(IllegalArgumentException.class, () -> JsonSyntaxValidator.validate(tooDeepJson));
  }
}
