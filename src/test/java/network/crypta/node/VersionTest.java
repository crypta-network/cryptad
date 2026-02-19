package network.crypta.node;

import org.junit.jupiter.api.Test;

import static network.crypta.node.Version.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link Version}, focusing on compareBuildNumbers(), isBuildAtLeast(), and
 * parseNodeNameFromVersionStr().
 */
public class VersionTest {

  // Constants for testing with the same values exposed by Version.
  private static final String CRYPTAD_NODE_NAME = "Cryptad";
  private static final String FRED_NODE_NAME = "Fred";
  private static final int MIN_CRYPTAD_BUILD = 1;
  private static final int MIN_FRED_BUILD = 1475;

  // Test version strings
  private static final String VALID_CRYPTAD_VERSION = "Cryptad,1504,1.0,1504";
  private static final String VALID_FRED_VERSION = "Fred,0.7,1.0,1503";
  private static final String MINIMAL_CRYPTAD_VERSION = "Cryptad,1,1.0";
  private static final String MINIMAL_FRED_VERSION = "Fred,0.7,1.0,1";
  private static final String MALFORMED_VERSION_SHORT = "Cryptad,1504";
  private static final String MALFORMED_VERSION_EMPTY = "";
  private static final String MALFORMED_VERSION_WRONG_SEPARATOR = "Cryptad;1504;1.0";

  @Test
  public void testCompareBuildNumbers_CryptadVsFred() {
    // Cryptad should always be considered newer than Fred regardless of build numbers
    assertTrue(
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1, FRED_NODE_NAME, 9999) > 0,
        "Cryptad should be newer than Fred with lower build number");
    assertTrue(
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1500, FRED_NODE_NAME, 1500) > 0,
        "Cryptad should be newer than Fred with same build number");
    assertTrue(
        compareBuildNumbers(CRYPTAD_NODE_NAME, 9999, FRED_NODE_NAME, 1) > 0,
        "Cryptad should be newer than Fred with higher build number");

    // Fred should be older than Cryptad
    assertTrue(
        compareBuildNumbers(FRED_NODE_NAME, 1, CRYPTAD_NODE_NAME, 9999) < 0,
        "Fred should be older than Cryptad with lower build number");
    assertTrue(
        compareBuildNumbers(FRED_NODE_NAME, 1500, CRYPTAD_NODE_NAME, 1500) < 0,
        "Fred should be older than Cryptad with same build number");
    assertTrue(
        compareBuildNumbers(FRED_NODE_NAME, 9999, CRYPTAD_NODE_NAME, 1) < 0,
        "Fred should be older than Cryptad with higher build number");
  }

  @Test
  public void testCompareBuildNumbers_SameNodeType() {
    // Same node type - should compare build numbers numerically

    // Cryptad vs Cryptad
    assertTrue(
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1505, CRYPTAD_NODE_NAME, 1504) > 0,
        "Higher Cryptad build should be newer");
    assertTrue(
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1504, CRYPTAD_NODE_NAME, 1505) < 0,
        "Lower Cryptad build should be older");
    assertEquals(
        0,
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1504, CRYPTAD_NODE_NAME, 1504),
        "Same Cryptad build should be equal");

    // Fred vs Fred
    assertTrue(
        compareBuildNumbers(FRED_NODE_NAME, 1503, FRED_NODE_NAME, 1502) > 0,
        "Higher Fred build should be newer");
    assertTrue(
        compareBuildNumbers(FRED_NODE_NAME, 1502, FRED_NODE_NAME, 1503) < 0,
        "Lower Fred build should be older");
    assertEquals(
        0,
        compareBuildNumbers(FRED_NODE_NAME, 1503, FRED_NODE_NAME, 1503),
        "Same Fred build should be equal");
  }

  @Test
  public void testCompareBuildNumbers_NullNodeNames() {
    // When node names are null, should fall back to build number comparison
    assertTrue(
        compareBuildNumbers(null, 1505, null, 1504) > 0,
        "Higher build number should win with null node names");
    assertTrue(
        compareBuildNumbers(null, 1504, null, 1505) < 0,
        "Lower build number should lose with null node names");
    assertEquals(
        0,
        compareBuildNumbers(null, 1504, null, 1504),
        "Same build number should be equal with null node names");

    // One null, one not null - should fall back to build number comparison
    assertTrue(
        compareBuildNumbers(null, 1505, FRED_NODE_NAME, 1504) > 0,
        "Higher build number should win with one null node name");
    assertTrue(
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1504, null, 1505) < 0,
        "Lower build number should lose with one null node name");
  }

  @Test
  public void testCompareBuildNumbers_EdgeCases() {
    // Test with zero and negative build numbers
    assertTrue(
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1, CRYPTAD_NODE_NAME, 0) > 0,
        "Positive should be greater than zero");
    assertTrue(
        compareBuildNumbers(FRED_NODE_NAME, 0, FRED_NODE_NAME, -1) > 0,
        "Zero should be greater than negative");

    // Test with very large build numbers
    assertTrue(
        compareBuildNumbers(
                CRYPTAD_NODE_NAME, Integer.MAX_VALUE, CRYPTAD_NODE_NAME, Integer.MAX_VALUE - 1)
            > 0,
        "Large build number comparison should work");
  }

  @Test
  public void testCompareBuildNumbers_UnknownNodeTypes() {
    // Unknown node types should fall back to build number comparison
    assertTrue(
        compareBuildNumbers("Unknown", 1505, "AnotherUnknown", 1504) > 0,
        "Unknown node type should compare by build number");
    assertTrue(
        compareBuildNumbers("Unknown", 1505, "SomeOther", 1504) > 0,
        "Unknown vs known should compare by build number when not Cryptad/Fred");
  }

  @Test
  public void testIsBuildAtLeast_CryptadNode() {
    // Cryptad nodes should always meet Fred minimum requirements
    assertTrue(
        isBuildAtLeast(CRYPTAD_NODE_NAME, 1, MIN_FRED_BUILD),
        "Cryptad should always meet Fred minimum build requirement");
    assertTrue(
        isBuildAtLeast(CRYPTAD_NODE_NAME, 1, 9999),
        "Cryptad with low build should still meet Fred minimum");
    assertTrue(
        isBuildAtLeast(CRYPTAD_NODE_NAME, 0, MIN_FRED_BUILD),
        "Cryptad with zero build should still meet Fred minimum");
    assertTrue(
        isBuildAtLeast(CRYPTAD_NODE_NAME, -1, MIN_FRED_BUILD),
        "Cryptad with negative build should still meet Fred minimum");
  }

  @Test
  public void testIsBuildAtLeast_FredNode() {
    // Fred nodes should be checked against the minimum build number
    assertTrue(
        isBuildAtLeast(FRED_NODE_NAME, MIN_FRED_BUILD, MIN_FRED_BUILD),
        "Fred node with sufficient build should meet minimum");
    assertTrue(
        isBuildAtLeast(FRED_NODE_NAME, MIN_FRED_BUILD + 1, MIN_FRED_BUILD),
        "Fred node with higher build should meet minimum");
    assertFalse(
        isBuildAtLeast(FRED_NODE_NAME, MIN_FRED_BUILD - 1, MIN_FRED_BUILD),
        "Fred node with insufficient build should not meet minimum");
    assertFalse(
        isBuildAtLeast(FRED_NODE_NAME, 0, MIN_FRED_BUILD),
        "Fred node with zero build should not meet minimum");
  }

  @Test
  public void testIsBuildAtLeast_NullAndUnknownNodeNames() {
    // Null node names should be treated like Fred nodes
    assertTrue(
        isBuildAtLeast(null, MIN_FRED_BUILD, MIN_FRED_BUILD),
        "Null node name with sufficient build should meet minimum");
    assertFalse(
        isBuildAtLeast(null, MIN_FRED_BUILD - 1, MIN_FRED_BUILD),
        "Null node name with insufficient build should not meet minimum");

    // Unknown node names should be treated like Fred nodes
    assertTrue(
        isBuildAtLeast("UnknownNode", MIN_FRED_BUILD, MIN_FRED_BUILD),
        "Unknown node name with sufficient build should meet minimum");
    assertFalse(
        isBuildAtLeast("UnknownNode", MIN_FRED_BUILD - 1, MIN_FRED_BUILD),
        "Unknown node name with insufficient build should not meet minimum");
  }

  @Test
  public void testIsBuildAtLeast_EdgeCases() {
    // Test boundary conditions
    assertTrue(isBuildAtLeast(FRED_NODE_NAME, 1000, 1000), "Exact minimum should meet requirement");
    assertFalse(
        isBuildAtLeast(FRED_NODE_NAME, 999, 1000), "One below minimum should not meet requirement");
    assertTrue(
        isBuildAtLeast(FRED_NODE_NAME, 1001, 1000), "One above minimum should meet requirement");

    // Test with zero minimum
    assertTrue(isBuildAtLeast(FRED_NODE_NAME, 0, 0), "Any build should meet zero minimum");
    assertTrue(isBuildAtLeast(FRED_NODE_NAME, 1, 0), "Positive build should meet zero minimum");
    assertFalse(
        isBuildAtLeast(FRED_NODE_NAME, -1, 0), "Negative build should not meet zero minimum");
  }

  @Test
  public void testParseNodeNameFromVersionStr_ValidVersions() {
    // Test valid Cryptad version strings
    assertEquals(
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr(VALID_CRYPTAD_VERSION),
        "Should extract Cryptad node name");
    assertEquals(
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr(MINIMAL_CRYPTAD_VERSION),
        "Should extract Cryptad from minimal version");

    // Test valid Fred version strings
    assertEquals(
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr(VALID_FRED_VERSION),
        "Should extract Fred node name");
    assertEquals(
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr(MINIMAL_FRED_VERSION),
        "Should extract Fred from minimal version");

    // Test single component version (edge case)
    assertEquals(
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr("Cryptad"),
        "Should extract node name from single component");
    assertEquals(
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr("Fred"),
        "Should extract node name from single component");
  }

  @Test
  public void testParseNodeNameFromVersionStr_NullAndEmptyInputs() {
    // Test null input
    assertNull(parseNodeNameFromVersionStr(null), "Null version string should return null");

    // Test empty input - Fields.commaList("") returns empty array, so we get null
    assertNull(
        parseNodeNameFromVersionStr(MALFORMED_VERSION_EMPTY),
        "Empty version string should return null");

    // Test whitespace-only input - Fields.commaList("   ") returns [""] (one empty string)
    assertEquals(
        "",
        parseNodeNameFromVersionStr("   "),
        "Whitespace-only version string should return empty string");
  }

  @Test
  public void testParseNodeNameFromVersionStr_MalformedVersions() {
    // Test version with wrong separator - semicolon is not a comma, so whole string becomes one
    // element
    assertEquals(
        MALFORMED_VERSION_WRONG_SEPARATOR,
        parseNodeNameFromVersionStr(MALFORMED_VERSION_WRONG_SEPARATOR),
        "Version with wrong separator should return the whole string as node name");

    // Test version that's too short but has a node name
    assertEquals(
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr(MALFORMED_VERSION_SHORT),
        "Should still extract node name from short version");

    // Test version with only commas - StringTokenizer skips empty tokens, so array is empty and
    // returns null
    assertNull(parseNodeNameFromVersionStr(",,,"), "Version with only commas should return null");

    // Test version starting with comma - StringTokenizer skips empty token, so first real token is
    // "Cryptad"
    assertEquals(
        "Cryptad",
        parseNodeNameFromVersionStr(",Cryptad,1504,1.0"),
        "Version starting with comma should return first non-empty token");
  }

  @Test
  public void testParseNodeNameFromVersionStr_UnknownNodeNames() {
    // Test with unknown node names
    assertEquals(
        "UnknownNode",
        parseNodeNameFromVersionStr("UnknownNode,1504,1.0,1504"),
        "Should extract unknown node name");
    assertEquals(
        "123", parseNodeNameFromVersionStr("123,1504,1.0"), "Should extract numeric node name");

    // Test with special characters in node name
    assertEquals(
        "Node-v2.0",
        parseNodeNameFromVersionStr("Node-v2.0,1504,1.0,1504"),
        "Should extract node name with special characters");
  }

  @Test
  public void testParseNodeNameFromVersionStr_EdgeCasesAndBoundaries() {
    // Test very long node name
    String longNodeName = "VeryLongNodeNameThatExceedsNormalExpectations";
    assertEquals(
        longNodeName,
        parseNodeNameFromVersionStr(longNodeName + ",1504,1.0,1504"),
        "Should extract very long node name");

    // Test node name with spaces (even though this would be unusual)
    assertEquals(
        "Node Name",
        parseNodeNameFromVersionStr("Node Name,1504,1.0,1504"),
        "Should extract node name with spaces");

    // Test version string with trailing commas
    assertEquals(
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr("Cryptad,1504,1.0,1504,"),
        "Should extract node name with trailing commas");

    // Test version string with extra components
    assertEquals(
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr("Fred,0.7,1.0,1503,extra,data"),
        "Should extract node name with extra components");
  }

  @Test
  public void testParseNodeNameFromVersionStr_IntegrationWithOtherFunctions() {
    // Test that extracted node names work correctly with other functions
    String cryptadName = parseNodeNameFromVersionStr(VALID_CRYPTAD_VERSION);
    String fredName = parseNodeNameFromVersionStr(VALID_FRED_VERSION);

    assertNotNull(cryptadName, "Should extract valid Cryptad node name");
    assertNotNull(fredName, "Should extract valid Fred node name");

    // Test with compareBuildNumbers
    assertTrue(
        compareBuildNumbers(cryptadName, 1504, fredName, 1503) > 0,
        "Extracted Cryptad name should work with compareBuildNumbers");

    // Test with isBuildAtLeast
    assertTrue(
        isBuildAtLeast(cryptadName, 1, MIN_FRED_BUILD),
        "Extracted Cryptad name should work with isBuildAtLeast");
    assertTrue(
        isBuildAtLeast(fredName, MIN_FRED_BUILD, MIN_FRED_BUILD),
        "Extracted Fred name should work with isBuildAtLeast");
  }

  @Test
  public void testParseNodeNameFromVersionStr_RealWorldVersionStrings() {
    // Test with realistic version strings that might be encountered
    assertEquals(
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr("Cryptad,1504,1.0,1504"),
        "Should handle typical Cryptad version");
    assertEquals(
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr("Fred,0.7,1.0,1503"),
        "Should handle typical Fred version");

    // Test with version strings that might come from different Freenet forks
    assertEquals(
        "Freenet",
        parseNodeNameFromVersionStr("Freenet,0.7,1.0,1475"),
        "Should handle Freenet version");
    assertEquals(
        "Hyphanet",
        parseNodeNameFromVersionStr("Hyphanet,1.0,1.0,2000"),
        "Should handle other fork names");
  }
}
