package org.bitpedia.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100")
class Base32Test {

  @Nested
  @DisplayName("encode")
  class Encode {

    @ParameterizedTest
    @MethodSource("org.bitpedia.util.Base32Test#rfcVectors")
    void encode_whenUsingRfcVectors_expectExpectedBase32(String plain, String expectedBase32) {
      // Arrange
      byte[] input = plain.getBytes(StandardCharsets.UTF_8);

      // Act
      String encoded = Base32.encode(input);

      // Assert
      assertEquals(expectedBase32, encoded);
    }

    @Test
    void encode_whenInputIsEmpty_returnsEmptyString() {
      // Arrange
      byte[] input = new byte[0];

      // Act
      String encoded = Base32.encode(input);

      // Assert
      assertEquals("", encoded);
    }

    @Test
    void encode_whenBytesContainNegativeValues_preservesAllBits() {
      // Arrange
      byte[] input = new byte[] {(byte) 0xFF, (byte) 0x00, (byte) 0x7F, (byte) 0x80};

      // Act
      String encoded = Base32.encode(input);
      byte[] roundTripped = Base32.decode(encoded);

      // Assert
      assertArrayEquals(input, roundTripped);
    }
  }

  @Nested
  @DisplayName("decode")
  class Decode {

    @ParameterizedTest
    @MethodSource("org.bitpedia.util.Base32Test#rfcVectors")
    void decode_whenUsingRfcVectors_expectOriginalBytes(String plain, String base32) {
      // Act
      byte[] decoded = Base32.decode(base32);

      // Assert
      assertArrayEquals(plain.getBytes(StandardCharsets.UTF_8), decoded);
    }

    @Test
    void decode_whenInputIsLowerCase_expectCaseInsensitivity() {
      // Arrange
      String base32 = "mzxw6ytboi"; // "foobar" in lowercase

      // Act
      byte[] decoded = Base32.decode(base32);

      // Assert
      assertEquals("foobar", new String(decoded, StandardCharsets.UTF_8));
    }

    @Test
    void decode_whenInputIsEmpty_returnsEmptyArray() {
      // Act
      byte[] decoded = Base32.decode("");

      // Assert
      assertArrayEquals(new byte[0], decoded);
    }

    @Test
    void decode_whenInputContainsInvalidCharacters_ignoresThem() {
      // Arrange
      String base32WithNoise = "M!Y"; // equivalent to "MY" ("f") with an ignored character

      // Act
      byte[] decoded = Base32.decode(base32WithNoise);

      // Assert
      assertEquals("f", new String(decoded, StandardCharsets.UTF_8));
    }
  }

  static Stream<Arguments> rfcVectors() {
    return Stream.of(
        Arguments.of("f", "MY"),
        Arguments.of("fo", "MZXQ"),
        Arguments.of("foo", "MZXW6"),
        Arguments.of("foob", "MZXW6YQ"),
        Arguments.of("fooba", "MZXW6YTB"),
        Arguments.of("foobar", "MZXW6YTBOI"));
  }
}
