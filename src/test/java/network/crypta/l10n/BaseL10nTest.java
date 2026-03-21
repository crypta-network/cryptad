package network.crypta.l10n;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.Set;
import java.util.stream.Stream;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TestProperty;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@SuppressWarnings("java:S100") // allow descriptive test method names
class BaseL10nTest {

  static BaseL10n createL10n(LANGUAGE lang) {
    File overrideFile =
        new File(TestProperty.L10N_PATH_MAIN, "crypta.l10n.${lang}.override.properties");
    return new BaseL10n(
        "network/crypta/l10n/", "crypta.l10n.${lang}.properties", overrideFile.getPath(), lang);
  }

  static BaseL10n createTestL10n(LANGUAGE lang) {
    File overrideFile =
        new File(TestProperty.L10N_PATH_TEST, "crypta.l10n.${lang}.override.properties");
    return new BaseL10n(
        "network/crypta/l10n/",
        "crypta.l10n.${lang}.test.properties",
        overrideFile.getPath(),
        lang);
  }

  /**
   * Installs a {@link #createTestL10n(LANGUAGE) BaseL10n} with translations read from the test
   * classpath into the global {@link NodeL10n}, allowing tests for translation keys.
   */
  static void useTestTranslation() {
    NodeL10n.setBase(createTestL10n(LANGUAGE.ENGLISH));
  }

  @Test
  void addL10nSubstitution_whenValidPattern_expectHtmlInserted() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode boldNode = new HTMLNode("b");

    // Act
    l10n.addL10nSubstitution(
        node, "test.substitution", new String[] {"bold"}, new HTMLNode[] {boldNode});

    // Assert
    String actual = node.generateChildren();
    String expected = "Text with <b>loud</b> string";
    assertEquals(expected, actual);
  }

  @Test
  void addL10nSubstitution_whenExtraPatternUnused_expectIgnored() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode boldNode = new HTMLNode("b");
    HTMLNode extraNode = new HTMLNode("extra");

    // Act
    l10n.addL10nSubstitution(
        node,
        "test.substitution",
        new String[] {"bold", "extra"},
        new HTMLNode[] {boldNode, extraNode});

    // Assert
    String expected = "Text with <b>loud</b> string";
    String actual = node.generateChildren();
    assertEquals(expected, actual);
  }

  @Test
  void addL10nSubstitution_whenUnclosedReplacement_expectEmptyNode() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode imgNode = new HTMLNode("img");

    // Act
    l10n.addL10nSubstitution(
        node, "test.unclosedSubstitution", new String[] {"image"}, new HTMLNode[] {imgNode});

    // Assert
    String expected = "Text with <img /> unclosed substitution";
    String actual = node.generateChildren();
    assertEquals(expected, actual);
  }

  @Test
  void addL10nSubstitution_whenUnclosedAndMissingPattern_expectGap() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");

    // Act
    l10n.addL10nSubstitution(node, "test.unclosedSubstitution", new String[] {}, new HTMLNode[] {});

    // Assert
    String expected = "Text with  unclosed substitution";
    assertEquals(expected, node.generateChildren());
  }

  @Test
  void addL10nSubstitution_whenMultiplePatterns_expectAllInserted() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode rep1Node = new HTMLNode("r1");
    HTMLNode rep2Node = new HTMLNode("r2");
    HTMLNode rep3Node = new HTMLNode("r3");

    // Act
    l10n.addL10nSubstitution(
        node,
        "test.multipleSubstitution",
        new String[] {"rep2", "rep1", "rep3"},
        new HTMLNode[] {rep2Node, rep1Node, rep3Node});

    // Assert
    String expected = "<r1>Rep 1</r1><r2>Rep 2</r2> and <r3>Rep 3</r3>";
    assertEquals(expected, node.generateChildren());
  }

  @Test
  void addL10nSubstitution_whenMissingOnePattern_expectFallbackText() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode rep2Node = new HTMLNode("r2");
    HTMLNode rep3Node = new HTMLNode("r3");

    // Act
    l10n.addL10nSubstitution(
        node,
        "test.multipleSubstitution",
        new String[] {"rep2", "rep3"},
        new HTMLNode[] {rep2Node, rep3Node});

    // Assert
    String expected = "Rep 1<r2>Rep 2</r2> and <r3>Rep 3</r3>";
    assertEquals(expected, node.generateChildren());
  }

  @Test
  void addL10nSubstitution_whenNestedPatterns_expectNestedNodes() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode innerNode = new HTMLNode("in");
    HTMLNode outerNode = new HTMLNode("out");

    // Act
    l10n.addL10nSubstitution(
        node,
        "test.nestedSubstitution",
        new String[] {"inner", "outer"},
        new HTMLNode[] {innerNode, outerNode});

    // Assert
    assertEquals("<out>Text and <in>replacement</in></out>", node.generateChildren());
  }

  // Parameterized replacement for three individual tests at previous lines 184, 313, and 347
  enum L10nCase {
    DOUBLE_SUB,
    GET_STRING_FALLBACK,
    GET_DEFAULT_BROKEN
  }

  static Stream<Arguments> l10n_cases() {
    return Stream.of(
        Arguments.of(L10nCase.DOUBLE_SUB, "<tag></tag>content<tag></tag>"),
        Arguments.of(L10nCase.GET_STRING_FALLBACK, "Sane"),
        Arguments.of(L10nCase.GET_DEFAULT_BROKEN, "Fallback ${tag}"));
  }

  @ParameterizedTest
  @MethodSource("l10n_cases")
  void l10n_parameterized_whenDifferentScenarios_expectExpectedOutput(L10nCase c, String expected) {
    // Arrange
    String actual;

    // Act
    switch (c) {
      case DOUBLE_SUB -> {
        BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
        HTMLNode node = new HTMLNode("div");
        HTMLNode tagNode = new HTMLNode("tag");
        l10n.addL10nSubstitution(
            node, "test.doubleSubstitution", new String[] {"tag"}, new HTMLNode[] {tagNode});
        actual = node.generateChildren();
      }
      case GET_STRING_FALLBACK -> {
        BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
        actual = l10n.getString("test.sanity");
      }
      case GET_DEFAULT_BROKEN -> {
        BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
        actual = l10n.getDefaultString("test.badSubstitutionFallback");
      }
      default -> throw new IllegalStateException("Unexpected case: " + c);
    }

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  void addL10nSubstitution_whenSelfNested_expectKeyFallback() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode tagNode = new HTMLNode("tag");

    // Act
    l10n.addL10nSubstitution(
        node, "test.selfNestedSubstitution", new String[] {"tag"}, new HTMLNode[] {tagNode});

    // Assert (fallback to key string)
    assertEquals("test.selfNestedSubstitution", node.generateChildren());
  }

  @Test
  void addL10nSubstitution_whenSelfNestedInnerEmpty_expectRendered() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode tagNode = new HTMLNode("tag");

    // Act
    l10n.addL10nSubstitution(
        node, "test.emptySelfNestedSubstitution", new String[] {"tag"}, new HTMLNode[] {tagNode});

    // Assert
    assertEquals("<tag>content <tag></tag>nested</tag>", node.generateChildren());
  }

  @Test
  void addL10nSubstitution_whenMissingBrace_expectKeyFallback() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode okNode = new HTMLNode("ok");

    // Act
    l10n.addL10nSubstitution(
        node, "test.missingBraceSubstitution", new String[] {"ok"}, new HTMLNode[] {okNode});

    // Assert
    assertEquals("test.missingBraceSubstitution", node.generateChildren());
  }

  @Test
  void addL10nSubstitution_whenUnmatchedClose_expectKeyFallback() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = new HTMLNode("div");
    HTMLNode okNode = new HTMLNode("ok");

    // Act
    l10n.addL10nSubstitution(
        node, "test.unmatchedCloseSubstitution", new String[] {"ok"}, new HTMLNode[] {okNode});

    // Assert
    assertEquals("test.unmatchedCloseSubstitution", node.generateChildren());
  }

  @Test
  void addL10nSubstitution_whenCurrentBroken_usesFallback() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
    HTMLNode node = new HTMLNode("div");
    HTMLNode tagNode = new HTMLNode("tag");

    // Act
    l10n.addL10nSubstitution(
        node, "test.badSubstitutionFallback", new String[] {"tag"}, new HTMLNode[] {tagNode});

    // Assert
    assertEquals("Fallback <tag></tag>", node.generateChildren());
  }

  @Test
  void addL10nSubstitution_whenFallbackFound_expectRendered() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
    HTMLNode node = new HTMLNode("div");
    HTMLNode boldNode = new HTMLNode("b");

    // Act
    l10n.addL10nSubstitution(
        node, "test.substitution", new String[] {"bold"}, new HTMLNode[] {boldNode});

    // Assert
    assertEquals("Text with <b>loud</b> string", node.generateChildren());
  }

  @Test
  void getString_whenPresentInCurrent_expectValue() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);

    // Act
    String actual = l10n.getString("test.sanity");

    // Assert
    assertEquals("Sane", actual);
  }

  @Test
  void getString_whenOverridden_expectOverride() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);

    // Act
    String actual = l10n.getString("test.override");

    // Assert
    assertEquals("Overridden", actual);
  }

  @Test
  void getString_whenOverrideNotSetForFallback_expectFallbackOriginal() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);

    // Act
    String actual = l10n.getString("test.override");

    // Assert
    assertEquals("Not overridden", actual);
  }

  @Test
  void getString_whenMissingEverywhere_expectKey() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
    // Act
    String actual = l10n.getString("test.nonexistent");
    // Assert
    assertEquals("test.nonexistent", actual);
  }

  @Test
  void getDefaultString_whenPresentInFallback_expectValue() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
    // Act
    String actual = l10n.getDefaultString("test.sanity");
    // Assert
    assertEquals("Sane", actual);
  }

  @Test
  void getDefaultString_whenMissingEverywhere_expectKey() {
    // Arrange
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
    // Act
    String actual = l10n.getDefaultString("test.nonexistent");
    // Assert
    assertEquals("test.nonexistent", actual);
  }

  @Test
  void language_mapToLanguage_byCodeFullIsoAndAlias_expectEnglish() {
    assertEquals(LANGUAGE.ENGLISH, LANGUAGE.mapToLanguage("en"));
    assertEquals(LANGUAGE.ENGLISH, LANGUAGE.mapToLanguage("English"));
    assertEquals(LANGUAGE.ENGLISH, LANGUAGE.mapToLanguage("eng"));
    assertEquals(LANGUAGE.ENGLISH, LANGUAGE.mapToLanguage("windows0409"));
    assertNull(LANGUAGE.mapToLanguage("zz-UNKNOWN"));
  }

  @Test
  void language_valuesWithFullNames_sortedAndUnlistedLast() {
    String[] names = LANGUAGE.valuesWithFullNames();
    assertEquals("unlisted", names[names.length - 1]);
    String[] head = Arrays.copyOf(names, names.length - 1);
    String[] sorted = Arrays.copyOf(head, head.length);
    Arrays.sort(sorted);
    assertArrayEquals(sorted, head);
  }

  @Test
  void getL10nFileName_whenFormatting_expectCorrectPaths(@TempDir Path tmp) {
    String base = "network/crypta/l10n"; // missing trailing slash
    String mask = "crypta.l10n.${lang}.test.properties";
    String overrideMask = tmp.resolve("crypta.l10n.${lang}.override.properties").toString();
    BaseL10n l10n = new BaseL10n(base, mask, overrideMask, LANGUAGE.ENGLISH);

    assertEquals(
        "network/crypta/l10n/crypta.l10n.en.test.properties",
        l10n.getL10nFileName(LANGUAGE.ENGLISH));

    assertEquals(
        tmp.resolve("crypta.l10n.en.override.properties").toString(),
        l10n.getL10nOverrideFileName(LANGUAGE.ENGLISH));
  }

  @Test
  void setLanguage_whenNull_expectMissingResourceException() {
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    assertThrows(MissingResourceException.class, () -> l10n.setLanguage(null));
  }

  @Test
  void getString_whenReturnNullIfNotFoundTrue_expectNull() {
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
    assertNull(l10n.getString("test.nonexistent", true));
    // Even though a fallback exists, the boolean variant returns null when missing in current
    assertNull(l10n.getString("test.sanity", true));
  }

  @Test
  void getString_whenUsingReplacementValue_expectAllVariablesReplaced() {
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    assertEquals("X", l10n.getString("test.multipleSubstitution", "X"));
  }

  @Test
  void getString_whenReplacingWithSpecials_expectEscapedReplacement() {
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    String out =
        l10n.getString(
            "test.badSubstitutionFallback", new String[] {"tag"}, new String[] {"$1\\end"});
    assertEquals("Fallback $1\\end", out);
  }

  @Test
  void getDefaultString_whenReplacementNull_expectLiteralNullString() {
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
    String out =
        l10n.getDefaultString(
            "test.badSubstitutionFallback", new String[] {"tag"}, new String[] {null});
    assertEquals("Fallback (null)", out);
  }

  @Test
  void getString_whenUsingSinglePatternHelper_expectReplaced() {
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    assertEquals("Fallback X", l10n.getString("test.badSubstitutionFallback", "tag", "X"));
  }

  @Test
  void getHTMLNode_whenMissingKey_expectTranslateItBlock() {
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    HTMLNode node = l10n.getHTMLNode("test.nonexistent");
    String html = node.generate();
    assertEquals(
        "<span class=\"translate_it\">test.nonexistent<a"
            + " href=\"/translation/?translate=test.nonexistent\"><small> (translate it in your"
            + " native language!)</small></a></span>",
        html);
  }

  @Test
  void setOverride_whenSetRemovedOrSameAsCurrent_expectOverrideRemoved(@TempDir Path tmp) {
    String base = "network/crypta/l10n/";
    String mask = "crypta.l10n.${lang}.test.properties";
    String overrideMask = tmp.resolve("crypta.l10n.${lang}.override.properties").toString();
    BaseL10n l10n = new BaseL10n(base, mask, overrideMask, LANGUAGE.ENGLISH);

    assertFalse(l10n.isOverridden("new.override"));
    l10n.setOverride("new.override", "Value");
    assertTrue(l10n.isOverridden("new.override"));

    l10n.setOverride("new.override", " "); // trims to empty -> removal
    assertFalse(l10n.isOverridden("new.override"));

    assertEquals("Sane", l10n.getString("test.sanity"));
    l10n.setOverride(" test.sanity ", " Sane ");
    assertFalse(l10n.isOverridden("test.sanity"));
  }

  @Test
  void setOverride_whenNewValue_expectPersistedOverrideFile(@TempDir Path tmp) throws Exception {
    BaseL10n l10n =
        new BaseL10n(
            "network/crypta/l10n/",
            "crypta.l10n.${lang}.test.properties",
            tmp.resolve("crypta.l10n.${lang}.override.properties").toString(),
            LANGUAGE.ENGLISH);

    l10n.setOverride("new.override", "Value");

    Path overrideFile = tmp.resolve("crypta.l10n.en.override.properties");
    assertTrue(Files.exists(overrideFile));
    assertEquals(
        "Value", SimpleFieldSet.readFrom(overrideFile.toFile(), false, false).get("new.override"));
  }

  @Test
  void translations_whenModifyingCopies_expectOriginalLookupsUnaffected() {
    BaseL10n l10n = createTestL10n(LANGUAGE.GERMAN);
    SimpleFieldSet fallbackCopy = l10n.getDefaultLanguageTranslation();
    assertNotNull(fallbackCopy);
    // Mutate the copy with a brand-new key; original lookups must be unaffected
    fallbackCopy.putOverwrite("new.section.key", "Modified");
    assertEquals("new.section.key", l10n.getDefaultString("new.section.key"));

    SimpleFieldSet currentCopy = l10n.getCurrentLanguageTranslation();
    assertNotNull(currentCopy);
    currentCopy.putOverwrite("current.only.key", "Broken");
    assertEquals("current.only.key", l10n.getString("current.only.key"));
  }

  @Test
  void getAllNamesWithPrefix_whenFallbackNotLoaded_returnsEmpty() {
    BaseL10n l10n =
        new BaseL10n("no/such/path/", "missing.${lang}", "ignored.${lang}", LANGUAGE.ENGLISH);
    assertArrayEquals(new String[] {}, l10n.getAllNamesWithPrefix("test."));
  }

  @Test
  void getAllNamesWithPrefix_whenLoaded_returnsKeysWithPrefix() {
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    l10n.getDefaultLanguageTranslation(); // ensure fallback is loaded
    String[] keys = l10n.getAllNamesWithPrefix("test.");
    Set<String> set = new HashSet<>(Arrays.asList(keys));
    assertTrue(set.contains("test.sanity"));
    assertFalse(set.contains("pebble-utils-tests.testKey"));
  }

  @Test
  void attemptParse_whenSyntaxErrors_expectException() {
    BaseL10n l10n = createTestL10n(LANGUAGE.ENGLISH);
    assertThrows(L10nParseException.class, () -> l10n.attemptParse("Text ${unterminated"));
    assertThrows(L10nParseException.class, () -> l10n.attemptParse("${/bad}"));
  }

  @Test
  void getString_whenNoResourcesForCurrentOrFallback_returnsKey() {
    BaseL10n l10n =
        new BaseL10n("no/such/path/", "missing.${lang}", "ignored.${lang}", LANGUAGE.ENGLISH);
    assertNull(l10n.getCurrentLanguageTranslation());
    assertEquals("unknown.key", l10n.getString("unknown.key"));
    assertEquals("unknown.key", l10n.getDefaultString("unknown.key"));
  }

  @Test
  void iterateLanguageValues_whenAttemptParseAll_expectNoErrors() {
    for (LANGUAGE lang : LANGUAGE.values()) {
      BaseL10n l10n = createL10n(lang);
      SimpleFieldSet fields = l10n.getCurrentLanguageTranslation();
      if (fields != null) {
        for (Iterator<String> itr = fields.keyIterator(); itr.hasNext(); ) {
          String key = itr.next();
          String value = fields.get(key);
          try {
            l10n.attemptParse(value);
          } catch (L10nParseException e) {
            fail("Error in " + key + " for " + lang + ": " + e.getMessage());
          }
        }
      }
    }
  }
}
