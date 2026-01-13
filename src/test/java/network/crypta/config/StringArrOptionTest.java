package network.crypta.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.support.api.StringArrCallback;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class StringArrOptionTest {

  @Mock private SubConfig subConfig;
  @Mock private StringArrCallback callback;

  private StringArrOption newOption(String[] deflt) {
    // Common constructor wiring for tests
    return new StringArrOption(
        subConfig,
        "test.string.array",
        deflt,
        new Option.Meta(10, false, false, "short.desc.key", "long.desc.key"),
        callback);
  }

  @Test
  void parseString_whenEmptyInput_returnsEmptyArray() throws Exception {
    StringArrOption opt = newOption(new String[] {"a"});
    String[] out = opt.parseString("");
    assertEquals(0, out.length);
  }

  @Test
  void parseString_whenHasEncodedValuesAndColonTokens_decodesAndMapsEmpty() throws Exception {
    StringArrOption opt = newOption(new String[] {});
    // "hello%20world" => "hello world"
    // ":" => empty string
    // "%E2%9C%93" => ✓ (check mark)
    // "%3b" => ';' within a value
    // "%25" => '%'
    // "%F0%9F%98%80" => 😀
    String val =
        "hello%20world"
            + StringArrOption.VALUE_DELIMITER
            + ":"
            + StringArrOption.VALUE_DELIMITER
            + "%E2%9C%93"
            + StringArrOption.VALUE_DELIMITER
            + "%3b"
            + StringArrOption.VALUE_DELIMITER
            + "%25"
            + StringArrOption.VALUE_DELIMITER
            + "%F0%9F%98%80";

    String[] out = opt.parseString(val);
    assertArrayEquals(new String[] {"hello world", "", "✓", ";", "%", "😀"}, out);
  }

  @Test
  void parseString_whenMalformedAfterSuccessfulDecode_throwsInvalidConfigValue() {
    StringArrOption opt = newOption(new String[] {});
    // The first escape decoded (":"), the second is malformed — tolerant mode now throws
    String malformed = "%3a%zz";
    assertThrows(InvalidConfigValueException.class, () -> opt.parseString(malformed));
  }

  @Test
  void parseString_whenTruncatedPercentAtEnd_throwsInvalidConfigValue() {
    StringArrOption opt = newOption(new String[] {});
    assertThrows(InvalidConfigValueException.class, () -> opt.parseString("abc%"));
  }

  @Test
  void toString_whenNull_returnsNull() {
    StringArrOption opt = newOption(new String[] {});
    assertNull(opt.toString(null));
  }

  @Test
  void toString_whenContainsEmptyAndSpecials_encodesAsSpecified() {
    StringArrOption opt = newOption(new String[] {});
    String[] in = new String[] {"", "a b", "✓", ";", ":", "%"};
    String str = opt.toString(in);
    // Empty string => ":"; space => %20; ';' => %3b; ':' => %3a; '%' => %25; Unicode ✓ passes
    // through
    String expected =
        ":"
            + StringArrOption.VALUE_DELIMITER
            + "a%20b"
            + StringArrOption.VALUE_DELIMITER
            + "✓"
            + StringArrOption.VALUE_DELIMITER
            + "%3b"
            + StringArrOption.VALUE_DELIMITER
            + "%3a"
            + StringArrOption.VALUE_DELIMITER
            + "%25";
    assertEquals(expected, str);
  }

  @Test
  void roundTrip_whenVariousValues_preservesValues() throws Exception {
    StringArrOption opt = newOption(new String[] {});
    String[] in = new String[] {"", ":", " semi;colon", "white space", "✓"};
    String s = opt.toString(in);
    String[] out = opt.parseString(s);
    assertArrayEquals(in, out);
  }

  @Test
  void decode_whenMalformed_returnsNull() {
    assertNull(StringArrOption.decode("abc%"));
  }

  @Test
  void decode_whenValid_returnsDecodedString() {
    assertEquals(":", StringArrOption.decode("%3a"));
    assertEquals("✓", StringArrOption.decode("%E2%9C%93"));
  }

  @Test
  void isDefault_whenNotInitialized_usesCurrentValue() throws Exception {
    when(subConfig.hasFinishedInitialization()).thenReturn(false);
    String[] deflt = new String[] {"x", "y"};
    StringArrOption opt = newOption(deflt);

    assertTrue(opt.isDefault());

    String[] other = new String[] {"z"};
    // Use typed overload to avoid invoking the callback
    opt.setInitialValue(other);
    assertFalse(opt.isDefault());
    // Callback shouldn't be touched for setInitialValue(T)
    verify(callback, never()).set(other);
  }

  @Test
  void isDefault_whenInitialized_usesCallbackValue() {
    when(subConfig.hasFinishedInitialization()).thenReturn(true);
    String[] deflt = new String[] {"a"};
    StringArrOption opt = newOption(deflt);

    when(callback.get()).thenReturn(deflt);
    assertTrue(opt.isDefault());

    when(callback.get()).thenReturn(new String[] {"different"});
    assertFalse(opt.isDefault());
    // get() must be consulted each time when initialized
    verify(callback, times(2)).get();
  }
}
