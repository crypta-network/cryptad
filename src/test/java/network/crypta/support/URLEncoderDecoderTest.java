package network.crypta.support;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.test.UTFUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises URL encoding and decoding behavior against representative inputs and edge cases.
 *
 * <p>This test suite focuses on the contract between {@link URLEncoder} and {@link URLDecoder} by
 * checking that round-trips preserve data across ASCII-safe characters, mixed printable ranges, and
 * non-ASCII Unicode samples. It also validates how the encoder behaves when asked to force escaping
 * of otherwise safe characters, and how the decoder reacts to malformed or borderline escape
 * sequences. The goal is to keep observable behavior stable for both strict and tolerant decoding
 * paths without asserting implementation details.
 *
 * <p>Because these tests operate only on in-memory strings, they are deterministic and
 * side-effect-free. The class is not intended for concurrent access; JUnit creates a new instance
 * per test by default. The inputs are fixed byte sequences sourced from {@link UTFUtil} so that
 * regressions are easy to reproduce.
 *
 * <ul>
 *   <li>Verify strict and tolerant decoding round-trip expected inputs.
 *   <li>Assert forced escaping for all safe URL characters.
 *   <li>Reject malformed escape sequences while allowing bare percent signs in tolerant mode.
 * </ul>
 *
 * @author Alberto Bacchelli &lt;sback@freenetproject.org&gt;
 */
class URLEncoderDecoderTest {

  /**
   * Creates a test instance with no mutable state.
   *
   * <p>JUnit constructs a new instance per test method, so the constructor intentionally performs
   * no work beyond default initialization.
   */
  URLEncoderDecoderTest() {}

  /** Printable US-ASCII sample used to validate safe-path encoding and decoding. */
  static final String PRINTABLE_ASCII = new String(UTFUtil.printableAscii());

  /** Stress sample containing non-ASCII characters to exercise UTF-8 percent encoding paths. */
  static final String STRESSED_UTF_8_CHARS = new String(UTFUtil.stressedUtf());

  /**
   * Full Unicode sample with the null character removed, used to ensure round-trip safety in strict
   * decoding mode.
   */
  static final String ALL_CHARS_EXCEPT_NULL =
      new String(UTFUtil.allCharacters()).replace("\u0000", "");

  /** Full Unicode sample including null, used when testing URI acceptance of encoded output. */
  static final String ALL_CHARS = new String(UTFUtil.allCharacters());

  /**
   * Encodes a full Unicode sample without the null character and validates strict and tolerant
   * decoding round-trips.
   *
   * <p>This test uses the widest sample that does not contain {@code '\u0000'} because the encoder
   * rejects a null code point. The encoded output is then decoded in both strict and tolerant modes
   * to ensure the original string is preserved.
   *
   * @throws URLEncodedFormatException if strict decoding rejects a generated escape sequence
   */
  @Test
  void encodeDecode_whenAllCharsExceptNull_expectRoundTrip() throws URLEncodedFormatException {
    String[] toEncode = {ALL_CHARS_EXCEPT_NULL};

    boolean strictResult = areCorrectlyEncodedDecoded(toEncode, true);
    boolean tolerantResult = areCorrectlyEncodedDecoded(toEncode, false);

    assertTrue(strictResult);
    assertTrue(tolerantResult);
  }

  /**
   * Verifies strict and tolerant round-trips for safe URL characters and ASCII-base inputs.
   *
   * <p>The sample includes the full safe-character set, a printable ASCII range, a sequence of
   * percent signs that would be invalid if incorrectly encoded, and an empty string to confirm
   * zero-length handling. The test uses both decoding modes to ensure consistency.
   */
  @Test
  void encodeDecode_whenSafeAndAsciiBaseChars_expectRoundTrip() {
    String[] toEncode = {
      // safe chars
      URLEncoder.safeURLCharacters,
      PRINTABLE_ASCII,
      // triple % char, if badly encoded it will generate an exception
      "%%%",
      // no chars
      ""
    };

    boolean strictResult = assertDoesNotThrow(() -> areCorrectlyEncodedDecoded(toEncode, true));
    boolean tolerantResult = assertDoesNotThrow(() -> areCorrectlyEncodedDecoded(toEncode, false));

    assertTrue(strictResult);
    assertTrue(tolerantResult);
  }

  /**
   * Verifies strict and tolerant round-trips for non-ASCII inputs.
   *
   * <p>The stressed UTF-8 sample includes characters that must be percent encoded. The test
   * confirms that both decoding paths produce the original string without loss or truncation.
   */
  @Test
  void encodeDecode_whenNonAsciiChars_expectRoundTrip() {
    String[] toEncode = {STRESSED_UTF_8_CHARS};

    boolean strictResult = assertDoesNotThrow(() -> areCorrectlyEncodedDecoded(toEncode, true));
    boolean tolerantResult = assertDoesNotThrow(() -> areCorrectlyEncodedDecoded(toEncode, false));

    assertTrue(strictResult);
    assertTrue(tolerantResult);
  }

  /**
   * Forces encoding of safe characters and checks for consistent percent-encoding output.
   *
   * <p>Each safe character is encoded twice, once with ASCII letters preserved and once with
   * uppercase hex letters forced. The expected output is the percent-encoded US-ASCII byte for the
   * character, so both modes should yield the same sequence.
   */
  @Test
  void encode_whenForceOnSafeChars_expectPercentEncoded() {
    for (int i = 0; i < URLEncoder.safeURLCharacters.length(); i++) {
      char eachChar = URLEncoder.safeURLCharacters.charAt(i);
      String toEncode = String.valueOf(eachChar);
      String expectedResult =
          "%"
              + HexUtil.bytesToHex(
                  // since safe chars are only US-ASCII
                  toEncode.getBytes(StandardCharsets.US_ASCII));

      String encodedWithoutLetters = URLEncoder.encode(toEncode, toEncode, false);
      String encodedWithLetters = URLEncoder.encode(toEncode, toEncode, true);

      assertEquals(expectedResult, encodedWithoutLetters);
      assertEquals(expectedResult, encodedWithLetters);
    }
  }

  /**
   * Ensures strict decoding rejects a null byte encoded as {@code %00}.
   *
   * <p>Null bytes are disallowed by the decoder, so a strict decode is expected to raise an {@link
   * URLEncodedFormatException}.
   */
  @Test
  void decode_whenNullCharPercentEncoded_expectException() {
    String toDecode = "%00";

    boolean exceptionRaised = isDecodeRaisingEncodedException(toDecode);

    assertTrue(exceptionRaised);
  }

  /**
   * Ensures strict decoding rejects invalid percent-escape sequences.
   *
   * <p>Each candidate string is formed with a percent sign and a single invalid character, so the
   * decoder must detect the malformed escape and raise an {@link URLEncodedFormatException}.
   */
  @Test
  void decode_whenInvalidHexDigits_expectException() {
    String toDecode = "123456789abcde" + PRINTABLE_ASCII + STRESSED_UTF_8_CHARS;

    for (int i = 0; i < toDecode.length(); i++) {
      String invalidEncoded = "%" + toDecode.charAt(i);

      boolean exceptionRaised = isDecodeRaisingEncodedException(invalidEncoded);

      assertTrue(exceptionRaised);
    }
  }

  /**
   * Verifies tolerant decoding preserves bare percent characters without throwing.
   *
   * <p>Tolerant mode is intended to accept user-pasted URLs that include percent signs not part of
   * valid escapes, so the decoder should return the original input unchanged.
   */
  @Test
  void decode_whenTolerantAndBarePercents_expectOriginal() {
    String toDecode = "%%%";

    String decoded = assertDoesNotThrow(() -> URLDecoder.decode(toDecode, true));

    assertEquals(toDecode, decoded);
  }

  /**
   * Confirms that a fully encoded Unicode string produces a URI-safe fragment.
   *
   * <p>The {@link URI} constructor is a strict parser for allowed characters. This test wraps the
   * encoded output in a fragment prefix and asserts that it is accepted without error.
   */
  @Test
  void encode_whenAllChars_expectUriAcceptsEncodedOutput() {
    String encoded = URLEncoder.encode(ALL_CHARS, false);

    assertDoesNotThrow(() -> new URI("#" + encoded));
  }

  /**
   * Encodes each input string and verifies that decoding returns the original value.
   *
   * <p>This helper method runs a two-phase check: it first encodes each input string and then
   * decodes the encoded value using the specified decoding mode. When a mismatch is detected, it
   * performs a character-by-character comparison to surface the first divergence and returns {@code
   * false} without throwing. The method is deterministic and has no side effects beyond the
   * returned boolean.
   *
   * @param toEncode array of input strings to encode and then decode in order
   * @param withLetters whether the encoder and decoder should allow ASCII letters in escapes
   * @return {@code true} when every input round-trips to the original value, otherwise {@code
   *     false}
   * @throws URLEncodedFormatException if decoding rejects an encoded value in strict mode
   */
  private boolean areCorrectlyEncodedDecoded(String[] toEncode, boolean withLetters)
      throws URLEncodedFormatException {
    String[] encoded = new String[toEncode.length];
    // encoding
    for (int i = 0; i < encoded.length; i++) {
      encoded[i] = URLEncoder.encode(toEncode[i], withLetters);
    }
    // decoding
    for (int i = 0; i < encoded.length; i++) {
      final String orig = toEncode[i];
      final String coded = encoded[i];
      final String decoded = URLDecoder.decode(coded, withLetters);
      if (!orig.equals(decoded)) {
        for (int c = 0; c < orig.length(); ++c) {
          final char origChar = orig.charAt(c);
          if (c >= decoded.length()) {
            return false; // Set your debugger breakpoint here
          }
          final char decodedChar = decoded.charAt(c);
          if (origChar != decodedChar) {
            return false; // Set your debugger breakpoint here
          }
        }
        return false;
      }
    }
    return true;
  }

  /**
   * Attempts strict decoding and reports whether a {@link URLEncodedFormatException} is raised.
   *
   * <p>This helper only exercises the strict decoding path. It catches the expected exception and
   * returns a boolean so tests can remain explicit about the failure condition being asserted.
   *
   * @param toDecode the raw string to decode, expected to contain malformed escapes
   * @return {@code true} if strict decoding throws, otherwise {@code false}
   */
  private boolean isDecodeRaisingEncodedException(String toDecode) {
    boolean retValue = false;
    try {
      URLDecoder.decode(toDecode, false);
    } catch (URLEncodedFormatException _) {
      retValue = true;
    }
    return retValue;
  }
}
