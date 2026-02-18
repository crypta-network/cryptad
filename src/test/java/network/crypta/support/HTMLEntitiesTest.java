package network.crypta.support;

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // allow method names with underscores for clarity
class HTMLEntitiesTest {

  @Test
  void maps_whenInitialized_expectNonEmptyAndSameSize() {
    assertNotNull(HTMLEntities.encodeMap);
    assertNotNull(HTMLEntities.decodeMap);
    assertFalse(HTMLEntities.encodeMap.isEmpty(), "encodeMap should not be empty");
    assertFalse(HTMLEntities.decodeMap.isEmpty(), "decodeMap should not be empty");
    assertEquals(
        HTMLEntities.encodeMap.size(),
        HTMLEntities.decodeMap.size(),
        "encodeMap and decodeMap must have the same number of entries");
  }

  @ParameterizedTest
  @MethodSource("wellKnownMappings")
  @DisplayName("encodeMap/decodeMap contain known HTML entity pairs")
  void maps_whenQueriedForKnownPairs_expectBidirectionalConsistency(char ch, String name) {
    assertEquals(name, HTMLEntities.encodeMap.get(ch));
    assertEquals(Character.valueOf(ch), HTMLEntities.decodeMap.get(name));
  }

  static Stream<Arguments> wellKnownMappings() {
    return Stream.of(
        Arguments.of('\u0000', "#0"),
        Arguments.of('\'', "#39"),
        Arguments.of('"', "quot"),
        Arguments.of('&', "amp"),
        Arguments.of('<', "lt"),
        Arguments.of('>', "gt"),
        Arguments.of('©', "copy"),
        Arguments.of('€', "euro"),
        Arguments.of('α', "alpha"),
        Arguments.of('Ω', "Omega"));
  }

  @Test
  void maps_whenCrossCheckingAllEntries_expectPerfectBijection() {
    // Every encode entry must be present (and identical) in decodeMap and vice versa
    for (Map.Entry<Character, String> e : HTMLEntities.encodeMap.entrySet()) {
      Character ch = e.getKey();
      String name = e.getValue();
      assertNotNull(name, () -> "Null entity name for char U+" + Integer.toHexString(ch));
      assertEquals(ch, HTMLEntities.decodeMap.get(name), () -> "decodeMap missing name: " + name);
    }
    for (Map.Entry<String, Character> e : HTMLEntities.decodeMap.entrySet()) {
      String name = e.getKey();
      Character ch = e.getValue();
      assertNotNull(ch, () -> "Null char for entity name: " + name);
      assertEquals(name, HTMLEntities.encodeMap.get(ch), () -> "encodeMap missing char: " + ch);
    }
  }

  @Test
  void maps_whenInspectingEntityNames_expectNoAmpersandOrSemicolon() {
    // Internal representation must be bare names (no leading '&' or trailing ';')
    for (String name : HTMLEntities.encodeMap.values()) {
      assertFalse(name.contains("&"), () -> "Unexpected '&' in name: " + name);
      assertFalse(name.contains(";"), () -> "Unexpected ';' in name: " + name);
      assertEquals(name.trim(), name, () -> "Name has surrounding whitespace: '" + name + "'");
    }
    for (String name : HTMLEntities.decodeMap.keySet()) {
      assertFalse(name.contains("&"), () -> "Unexpected '&' in key: " + name);
      assertFalse(name.contains(";"), () -> "Unexpected ';' in key: " + name);
      assertEquals(name.trim(), name, () -> "Key has surrounding whitespace: '" + name + "'");
    }
  }

  @Test
  void numericEntities_whenPresent_expectHashFollowedByDecimalDigits() {
    Pattern numeric = Pattern.compile("^#\\d+$");
    Set<Map.Entry<Character, String>> entries = HTMLEntities.encodeMap.entrySet();
    for (Map.Entry<Character, String> e : entries) {
      String name = e.getValue();
      if (name.startsWith("#")) {
        assertTrue(numeric.matcher(name).matches(), () -> "Invalid numeric entity: " + name);
        // Also verify decode round-trip again specifically for numeric ones
        assertEquals(e.getKey(), HTMLEntities.decodeMap.get(name));
      }
    }
  }
}
