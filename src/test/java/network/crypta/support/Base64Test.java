package network.crypta.support;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

/**
 * Tests for {@link Base64}. AAA style, deterministic, parameterized where useful. Includes Mockito
 * for simple I/O and time mocking without changing production code.
 */
class Base64Test {

  private static final String ILLEGAL_CHAR_MSG = "illegal Base64 character";

  // ----------------------------
  // Happy-path round trips
  // ----------------------------

  @Test
  @DisplayName("encode_whenEmpty_expectEmptyString")
  void encodeWhenEmptyExpectEmptyString() {
    // Arrange
    byte[] input = new byte[0];

    // Act
    String modified = Base64.encode(input);
    String standard = Base64.encodeStandard(input);

    // Assert
    assertEquals("", modified);
    assertEquals("", standard);
  }

  @Test
  @DisplayName("decode_whenEmpty_expectEmptyArray")
  void decodeWhenEmptyExpectEmptyArray() throws IllegalBase64Exception {
    // Arrange
    String empty = "";

    // Act
    byte[] modified = Base64.decode(empty);
    byte[] standard = Base64.decodeStandard(empty);

    // Assert
    assertArrayEquals(new byte[0], modified);
    assertArrayEquals(new byte[0], standard);
  }

  @Test
  @DisplayName("encodeUTF8_whenRoundTripUnicode_expectOriginalString")
  void encodeUtf8WhenRoundTripUnicodeExpectOriginalString() throws IllegalBase64Exception {
    // Arrange
    String original = "Hello, 世界 🌍 — Crypta";

    // Act
    String enc = Base64.encodeUTF8(original);
    String dec = Base64.decodeUTF8(enc);

    // Assert
    assertEquals(original, dec);
  }

  @ParameterizedTest(name = "len={0}, equalsPad={1}, standardAlphabet={2}")
  @MethodSource("lengthsAndAlphabetsData")
  @DisplayName("encode_whenVariousLengths_expectRoundTrip")
  void encodeWhenVariousLengthsExpectRoundTrip(
      int length, boolean equalsPad, boolean standardAlphabet) throws IllegalBase64Exception {
    // Arrange
    byte[] input = generate(length, 42);

    // Act
    String encoded;
    byte[] decoded;
    if (standardAlphabet) {
      encoded = Base64.encodeStandard(input);
      decoded = Base64.decodeStandard(encoded);
    } else {
      encoded = Base64.encode(input, equalsPad);
      decoded = Base64.decode(encoded);
    }

    // Assert
    assertArrayEquals(input, decoded);
    if (!standardAlphabet && equalsPad) {
      assertEquals(0, encoded.length() % 4, "Padded output must be multiple of 4");
    }
  }

  static Stream<Arguments> lengthsAndAlphabetsData() {
    // lengths 0..5; both alphabets; equalsPad true/false for modified alphabet
    Stream<Arguments> modified =
        IntStream.rangeClosed(0, 5)
            .boxed()
            .flatMap(
                len -> Stream.of(Arguments.of(len, false, false), Arguments.of(len, true, false)));
    Stream<Arguments> standard =
        IntStream.rangeClosed(0, 5).mapToObj(len -> Arguments.of(len, true, true));
    return Stream.concat(modified, standard);
  }

  // ----------------------------
  // Alphabet-specific expectations
  // ----------------------------

  @Test
  @DisplayName("encodeStandard_whenAllFF_expectSlashes")
  void encodeStandardWhenAllFFExpectSlashes() throws IllegalBase64Exception {
    // Arrange
    byte[] input = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

    // Act
    String encoded = Base64.encodeStandard(input);
    byte[] decoded = Base64.decodeStandard(encoded);

    // Assert
    assertEquals("////", encoded);
    assertArrayEquals(input, decoded);
  }

  @Test
  @DisplayName("encodeNonStandard_whenAllFF_expectDashes")
  void encodeNonStandardWhenAllFFExpectDashes() throws IllegalBase64Exception {
    // Arrange
    byte[] input = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

    // Act
    String encoded = Base64.encode(input);
    byte[] decoded = Base64.decode(encoded);

    // Assert
    assertEquals("----", encoded);
    assertArrayEquals(input, decoded);
  }

  // ----------------------------
  // Padding behavior
  // ----------------------------

  @ParameterizedTest(name = "len={0}")
  @ValueSource(ints = {1, 2, 3, 4, 5})
  @DisplayName("encode_whenEqualsPadTrue_expectMultipleOfFour")
  void encodeWhenEqualsPadTrueExpectMultipleOfFour(int len) {
    // Arrange
    byte[] input = generate(len, 7);

    // Act
    String encoded = Base64.encode(input, true);

    // Assert
    assertEquals(0, encoded.length() % 4);
  }

  @Test
  @DisplayName("encode_whenEqualsPadTrue_singleByte_expectTwoCharsPlusPadding")
  void encodeWhenEqualsPadTrueSingleByteExpectTwoCharsPlusPadding() throws IllegalBase64Exception {
    // Arrange
    byte[] input = new byte[] {0x4D}; // 'M'

    // Act
    String modifiedPadded = Base64.encode(input, true);
    String modifiedUnpadded = Base64.encode(input, false);

    // Assert
    assertEquals(4, modifiedPadded.length());
    assertEquals(2, modifiedUnpadded.length());
    assertEquals(modifiedUnpadded + "==", modifiedPadded);
    assertArrayEquals(input, Base64.decode(modifiedPadded));
    assertArrayEquals(input, Base64.decode(modifiedUnpadded));
  }

  @Test
  @DisplayName("decodeStandard_whenKnownExamples_expectManFamily")
  void decodeStandardWhenKnownExamplesExpectManFamily() throws IllegalBase64Exception {
    // Arrange
    String man = "TWFu"; // "Man"
    String ma = "TWE="; // "Ma"
    String m = "TQ=="; // "M"

    // Act
    byte[] outMan = Base64.decodeStandard(man);
    byte[] outMa = Base64.decodeStandard(ma);
    byte[] outM = Base64.decodeStandard(m);

    // Assert
    assertEquals("Man", new String(outMan, StandardCharsets.UTF_8));
    assertEquals("Ma", new String(outMa, StandardCharsets.UTF_8));
    assertEquals("M", new String(outM, StandardCharsets.UTF_8));
  }

  // ----------------------------
  // Error paths
  // ----------------------------

  @ParameterizedTest
  @ValueSource(strings = {"abcd=fgh", "abcd=fghilmn", "YW*J", "YW_J"})
  @DisplayName("decode_whenIllegalCharacters_expectIllegalBase64Character")
  void decodeWhenIllegalCharactersExpectIllegalBase64Character(String illegal) {
    // Arrange & Act
    IllegalBase64Exception ex =
        assertThrows(IllegalBase64Exception.class, () -> Base64.decode(illegal));
    // Assert
    assertEquals(ILLEGAL_CHAR_MSG, ex.getMessage());
  }

  @Test
  @DisplayName("decode_whenLengthModFourIsOne_expectIllegalBase64Length")
  void decodeWhenLengthModFourIsOneExpectIllegalBase64Length() {
    // Arrange
    String illegalLength = "a";

    // Act
    IllegalBase64Exception ex =
        assertThrows(IllegalBase64Exception.class, () -> Base64.decode(illegalLength));

    // Assert
    assertEquals("illegal Base64 length", ex.getMessage());
  }

  @Test
  @DisplayName("decodeStandard_whenWhitespacePresent_expectIllegalBase64Length")
  void decodeStandardWhenWhitespacePresentExpectIllegalBase64Length() {
    // Arrange
    String withSpace = "Y WJj"; // spaces in base64 are illegal here

    // Act & Assert
    IllegalBase64Exception ex =
        assertThrows(IllegalBase64Exception.class, () -> Base64.decodeStandard(withSpace));
    assertEquals("illegal Base64 length", ex.getMessage());
  }

  @Test
  @DisplayName("decodeNonStandard_whenStandardAlphabetString_expectIllegalBase64Character")
  void decodeNonStandardWhenStandardAlphabetStringExpectIllegalBase64Character() {
    // Arrange
    String standardEncoded = "////"; // index 63 is '/'

    // Act & Assert
    IllegalBase64Exception ex =
        assertThrows(IllegalBase64Exception.class, () -> Base64.decode(standardEncoded));
    assertEquals(ILLEGAL_CHAR_MSG, ex.getMessage());
  }

  @Test
  @DisplayName("decodeStandard_whenModifiedAlphabetString_expectIllegalBase64Character")
  void decodeStandardWhenModifiedAlphabetStringExpectIllegalBase64Character() {
    // Arrange
    String modifiedEncoded = "----"; // index 63 is '-'

    // Act & Assert
    IllegalBase64Exception ex =
        assertThrows(IllegalBase64Exception.class, () -> Base64.decodeStandard(modifiedEncoded));
    assertEquals(ILLEGAL_CHAR_MSG, ex.getMessage());
  }

  // ----------------------------
  // Null handling
  // ----------------------------

  @Test
  @DisplayName("encode_whenNullBytes_expectNullPointerException")
  void encodeWhenNullBytesExpectNullPointerException() {
    // Arrange & Act & Assert
    assertThrows(NullPointerException.class, () -> Base64.encode(null));
  }

  @Test
  @DisplayName("encodeUTF8_whenNull_expectNullPointerException")
  void encodeUtf8WhenNullExpectNullPointerException() {
    // Arrange & Act & Assert
    assertThrows(NullPointerException.class, () -> Base64.encodeUTF8(null));
  }

  @Test
  @DisplayName("decode_whenNull_expectNullPointerException")
  void decodeWhenNullExpectNullPointerException() {
    // Arrange & Act & Assert
    assertThrows(NullPointerException.class, () -> Base64.decode(null));
  }

  @Test
  @DisplayName("decodeStandard_whenNull_expectNullPointerException")
  void decodeStandardWhenNullExpectNullPointerException() {
    // Arrange & Act & Assert
    assertThrows(NullPointerException.class, () -> Base64.decodeStandard(null));
  }

  @Test
  @DisplayName("decodeUTF8_whenNull_expectNullPointerException")
  void decodeUtf8WhenNullExpectNullPointerException() {
    // Arrange & Act & Assert
    assertThrows(NullPointerException.class, () -> Base64.decodeUTF8(null));
  }

  // ----------------------------
  // Mockito: I/O and time
  // ----------------------------

  @Test
  @DisplayName("encode_whenBytesProvidedByInputStream_expectCorrectOutput")
  void encodeWhenBytesProvidedByInputStreamExpectCorrectOutput()
      throws IOException, IllegalBase64Exception {
    // Arrange
    byte[] data = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05};
    InputStream is = mock(InputStream.class);
    when(is.read(any(byte[].class)))
        .thenAnswer(
            new Answer<Integer>() {
              int offset = 0;

              @Override
              public Integer answer(InvocationOnMock inv) {
                byte[] dst = inv.getArgument(0);
                if (offset >= data.length) return -1;
                int len = Math.min(dst.length, data.length - offset);
                System.arraycopy(data, offset, dst, 0, len);
                offset += len;
                return len;
              }
            });

    // Act
    byte[] readAll = readAll(is);
    String encoded = Base64.encode(readAll, true);
    byte[] decoded = Base64.decode(encoded);

    // Assert
    assertArrayEquals(data, readAll);
    assertArrayEquals(data, decoded);
    verify(is, atLeastOnce()).read(any(byte[].class));
  }

  @Test
  @DisplayName("random_whenSeededByMockedTime_expectDeterministicRoundTrip")
  @SuppressWarnings("java:S2245")
  void randomWhenSeededByMockedTimeExpectDeterministicRoundTrip() throws IllegalBase64Exception {
    // Arrange
    long seed = 987654321L;
    AtomicInteger calls = new AtomicInteger();
    LongSupplier time =
        () -> {
          calls.incrementAndGet();
          return seed;
        };
    Random r = new Random(time.getAsLong());
    byte[] input = new byte[32];
    for (int i = 0; i < input.length; i++) input[i] = (byte) r.nextInt(256);

    // Act
    String encoded = Base64.encode(input);
    byte[] decoded = Base64.decode(encoded);

    // Assert
    assertArrayEquals(input, decoded);
    assertEquals(1, calls.get());
  }

  // ----------------------------
  // Helpers
  // ----------------------------

  @SuppressWarnings("java:S2245")
  private static byte[] generate(int length, long seed) {
    Random r = new Random(seed + length);
    byte[] out = new byte[length];
    for (int i = 0; i < length; i++) out[i] = (byte) r.nextInt(256);
    return out;
  }

  private static byte[] readAll(InputStream in) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buf = new byte[4];
    int n;
    while ((n = in.read(buf)) != -1) baos.write(buf, 0, n);
    return baos.toByteArray();
  }
}
