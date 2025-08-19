package network.crypta.node;

import static network.crypta.node.Version.*;
import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit tests for the Version.kt functions, focusing on the new functions: - compareBuildNumbers() -
 * isBuildAtLeast() - parseNodeNameFromVersionStr()
 */
public class VersionTest {

  // Constants for testing - using the same constants from Version.kt
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
        "Cryptad should be newer than Fred with lower build number",
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1, FRED_NODE_NAME, 9999) > 0);
    assertTrue(
        "Cryptad should be newer than Fred with same build number",
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1500, FRED_NODE_NAME, 1500) > 0);
    assertTrue(
        "Cryptad should be newer than Fred with higher build number",
        compareBuildNumbers(CRYPTAD_NODE_NAME, 9999, FRED_NODE_NAME, 1) > 0);

    // Fred should be older than Cryptad
    assertTrue(
        "Fred should be older than Cryptad with lower build number",
        compareBuildNumbers(FRED_NODE_NAME, 1, CRYPTAD_NODE_NAME, 9999) < 0);
    assertTrue(
        "Fred should be older than Cryptad with same build number",
        compareBuildNumbers(FRED_NODE_NAME, 1500, CRYPTAD_NODE_NAME, 1500) < 0);
    assertTrue(
        "Fred should be older than Cryptad with higher build number",
        compareBuildNumbers(FRED_NODE_NAME, 9999, CRYPTAD_NODE_NAME, 1) < 0);
  }

  @Test
  public void testCompareBuildNumbers_SameNodeType() {
    // Same node type - should compare build numbers numerically

    // Cryptad vs Cryptad
    assertTrue(
        "Higher Cryptad build should be newer",
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1505, CRYPTAD_NODE_NAME, 1504) > 0);
    assertTrue(
        "Lower Cryptad build should be older",
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1504, CRYPTAD_NODE_NAME, 1505) < 0);
    assertEquals(
        "Same Cryptad build should be equal",
        0,
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1504, CRYPTAD_NODE_NAME, 1504));

    // Fred vs Fred
    assertTrue(
        "Higher Fred build should be newer",
        compareBuildNumbers(FRED_NODE_NAME, 1503, FRED_NODE_NAME, 1502) > 0);
    assertTrue(
        "Lower Fred build should be older",
        compareBuildNumbers(FRED_NODE_NAME, 1502, FRED_NODE_NAME, 1503) < 0);
    assertEquals(
        "Same Fred build should be equal",
        0,
        compareBuildNumbers(FRED_NODE_NAME, 1503, FRED_NODE_NAME, 1503));
  }

  @Test
  public void testCompareBuildNumbers_NullNodeNames() {
    // When node names are null, should fall back to build number comparison
    assertTrue(
        "Higher build number should win with null node names",
        compareBuildNumbers(null, 1505, null, 1504) > 0);
    assertTrue(
        "Lower build number should lose with null node names",
        compareBuildNumbers(null, 1504, null, 1505) < 0);
    assertEquals(
        "Same build number should be equal with null node names",
        0,
        compareBuildNumbers(null, 1504, null, 1504));

    // One null, one not null - should fall back to build number comparison
    assertTrue(
        "Higher build number should win with one null node name",
        compareBuildNumbers(null, 1505, FRED_NODE_NAME, 1504) > 0);
    assertTrue(
        "Lower build number should lose with one null node name",
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1504, null, 1505) < 0);
  }

  @Test
  public void testCompareBuildNumbers_EdgeCases() {
    // Test with zero and negative build numbers
    assertTrue(
        "Positive should be greater than zero",
        compareBuildNumbers(CRYPTAD_NODE_NAME, 1, CRYPTAD_NODE_NAME, 0) > 0);
    assertTrue(
        "Zero should be greater than negative",
        compareBuildNumbers(FRED_NODE_NAME, 0, FRED_NODE_NAME, -1) > 0);

    // Test with very large build numbers
    assertTrue(
        "Large build number comparison should work",
        compareBuildNumbers(
                CRYPTAD_NODE_NAME, Integer.MAX_VALUE, CRYPTAD_NODE_NAME, Integer.MAX_VALUE - 1)
            > 0);
  }

  @Test
  public void testCompareBuildNumbers_UnknownNodeTypes() {
    // Unknown node types should fall back to build number comparison
    assertTrue(
        "Unknown node type should compare by build number",
        compareBuildNumbers("Unknown", 1505, "AnotherUnknown", 1504) > 0);
    assertTrue(
        "Unknown vs known should compare by build number when not Cryptad/Fred",
        compareBuildNumbers("Unknown", 1505, "SomeOther", 1504) > 0);
  }

  @Test
  public void testIsBuildAtLeast_CryptadNode() {
    // Cryptad nodes should always meet Fred minimum requirements
    assertTrue(
        "Cryptad should always meet Fred minimum build requirement",
        isBuildAtLeast(CRYPTAD_NODE_NAME, 1, MIN_FRED_BUILD));
    assertTrue(
        "Cryptad with low build should still meet Fred minimum",
        isBuildAtLeast(CRYPTAD_NODE_NAME, 1, 9999));
    assertTrue(
        "Cryptad with zero build should still meet Fred minimum",
        isBuildAtLeast(CRYPTAD_NODE_NAME, 0, MIN_FRED_BUILD));
    assertTrue(
        "Cryptad with negative build should still meet Fred minimum",
        isBuildAtLeast(CRYPTAD_NODE_NAME, -1, MIN_FRED_BUILD));
  }

  @Test
  public void testIsBuildAtLeast_FredNode() {
    // Fred nodes should be checked against the minimum build number
    assertTrue(
        "Fred node with sufficient build should meet minimum",
        isBuildAtLeast(FRED_NODE_NAME, MIN_FRED_BUILD, MIN_FRED_BUILD));
    assertTrue(
        "Fred node with higher build should meet minimum",
        isBuildAtLeast(FRED_NODE_NAME, MIN_FRED_BUILD + 1, MIN_FRED_BUILD));
    assertFalse(
        "Fred node with insufficient build should not meet minimum",
        isBuildAtLeast(FRED_NODE_NAME, MIN_FRED_BUILD - 1, MIN_FRED_BUILD));
    assertFalse(
        "Fred node with zero build should not meet minimum",
        isBuildAtLeast(FRED_NODE_NAME, 0, MIN_FRED_BUILD));
  }

  @Test
  public void testIsBuildAtLeast_NullAndUnknownNodeNames() {
    // Null node names should be treated like Fred nodes
    assertTrue(
        "Null node name with sufficient build should meet minimum",
        isBuildAtLeast(null, MIN_FRED_BUILD, MIN_FRED_BUILD));
    assertFalse(
        "Null node name with insufficient build should not meet minimum",
        isBuildAtLeast(null, MIN_FRED_BUILD - 1, MIN_FRED_BUILD));

    // Unknown node names should be treated like Fred nodes
    assertTrue(
        "Unknown node name with sufficient build should meet minimum",
        isBuildAtLeast("UnknownNode", MIN_FRED_BUILD, MIN_FRED_BUILD));
    assertFalse(
        "Unknown node name with insufficient build should not meet minimum",
        isBuildAtLeast("UnknownNode", MIN_FRED_BUILD - 1, MIN_FRED_BUILD));
  }

  @Test
  public void testIsBuildAtLeast_EdgeCases() {
    // Test boundary conditions
    assertTrue("Exact minimum should meet requirement", isBuildAtLeast(FRED_NODE_NAME, 1000, 1000));
    assertFalse(
        "One below minimum should not meet requirement", isBuildAtLeast(FRED_NODE_NAME, 999, 1000));
    assertTrue(
        "One above minimum should meet requirement", isBuildAtLeast(FRED_NODE_NAME, 1001, 1000));

    // Test with zero minimum
    assertTrue("Any build should meet zero minimum", isBuildAtLeast(FRED_NODE_NAME, 0, 0));
    assertTrue("Positive build should meet zero minimum", isBuildAtLeast(FRED_NODE_NAME, 1, 0));
    assertFalse(
        "Negative build should not meet zero minimum", isBuildAtLeast(FRED_NODE_NAME, -1, 0));
  }

  @Test
  public void testParseNodeNameFromVersionStr_ValidVersions() {
    // Test valid Cryptad version strings
    assertEquals(
        "Should extract Cryptad node name",
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr(VALID_CRYPTAD_VERSION));
    assertEquals(
        "Should extract Cryptad from minimal version",
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr(MINIMAL_CRYPTAD_VERSION));

    // Test valid Fred version strings
    assertEquals(
        "Should extract Fred node name",
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr(VALID_FRED_VERSION));
    assertEquals(
        "Should extract Fred from minimal version",
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr(MINIMAL_FRED_VERSION));

    // Test single component version (edge case)
    assertEquals(
        "Should extract node name from single component",
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr("Cryptad"));
    assertEquals(
        "Should extract node name from single component",
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr("Fred"));
  }

  @Test
  public void testParseNodeNameFromVersionStr_NullAndEmptyInputs() {
    // Test null input
    assertNull("Null version string should return null", parseNodeNameFromVersionStr(null));

    // Test empty input - Fields.commaList("") returns empty array, so we get null
    assertNull(
        "Empty version string should return null",
        parseNodeNameFromVersionStr(MALFORMED_VERSION_EMPTY));

    // Test whitespace-only input - Fields.commaList("   ") returns [""] (one empty string)
    assertEquals(
        "Whitespace-only version string should return empty string",
        "",
        parseNodeNameFromVersionStr("   "));
  }

  @Test
  public void testParseNodeNameFromVersionStr_MalformedVersions() {
    // Test version with wrong separator - semicolon is not a comma, so whole string becomes one
    // element
    assertEquals(
        "Version with wrong separator should return the whole string as node name",
        MALFORMED_VERSION_WRONG_SEPARATOR,
        parseNodeNameFromVersionStr(MALFORMED_VERSION_WRONG_SEPARATOR));

    // Test version that's too short but has a node name
    assertEquals(
        "Should still extract node name from short version",
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr(MALFORMED_VERSION_SHORT));

    // Test version with only commas - StringTokenizer skips empty tokens, so array is empty and
    // returns null
    assertNull("Version with only commas should return null", parseNodeNameFromVersionStr(",,,"));

    // Test version starting with comma - StringTokenizer skips empty token, so first real token is
    // "Cryptad"
    assertEquals(
        "Version starting with comma should return first non-empty token",
        "Cryptad",
        parseNodeNameFromVersionStr(",Cryptad,1504,1.0"));
  }

  @Test
  public void testParseNodeNameFromVersionStr_UnknownNodeNames() {
    // Test with unknown node names
    assertEquals(
        "Should extract unknown node name",
        "UnknownNode",
        parseNodeNameFromVersionStr("UnknownNode,1504,1.0,1504"));
    assertEquals(
        "Should extract numeric node name", "123", parseNodeNameFromVersionStr("123,1504,1.0"));

    // Test with special characters in node name
    assertEquals(
        "Should extract node name with special characters",
        "Node-v2.0",
        parseNodeNameFromVersionStr("Node-v2.0,1504,1.0,1504"));
  }

  @Test
  public void testParseNodeNameFromVersionStr_EdgeCasesAndBoundaries() {
    // Test very long node name
    String longNodeName = "VeryLongNodeNameThatExceedsNormalExpectations";
    assertEquals(
        "Should extract very long node name",
        longNodeName,
        parseNodeNameFromVersionStr(longNodeName + ",1504,1.0,1504"));

    // Test node name with spaces (even though this would be unusual)
    assertEquals(
        "Should extract node name with spaces",
        "Node Name",
        parseNodeNameFromVersionStr("Node Name,1504,1.0,1504"));

    // Test version string with trailing commas
    assertEquals(
        "Should extract node name with trailing commas",
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr("Cryptad,1504,1.0,1504,"));

    // Test version string with extra components
    assertEquals(
        "Should extract node name with extra components",
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr("Fred,0.7,1.0,1503,extra,data"));
  }

  @Test
  public void testParseNodeNameFromVersionStr_IntegrationWithOtherFunctions() {
    // Test that extracted node names work correctly with other functions
    String cryptadName = parseNodeNameFromVersionStr(VALID_CRYPTAD_VERSION);
    String fredName = parseNodeNameFromVersionStr(VALID_FRED_VERSION);

    assertNotNull("Should extract valid Cryptad node name", cryptadName);
    assertNotNull("Should extract valid Fred node name", fredName);

    // Test with compareBuildNumbers
    assertTrue(
        "Extracted Cryptad name should work with compareBuildNumbers",
        compareBuildNumbers(cryptadName, 1504, fredName, 1503) > 0);

    // Test with isBuildAtLeast
    assertTrue(
        "Extracted Cryptad name should work with isBuildAtLeast",
        isBuildAtLeast(cryptadName, 1, MIN_FRED_BUILD));
    assertTrue(
        "Extracted Fred name should work with isBuildAtLeast",
        isBuildAtLeast(fredName, MIN_FRED_BUILD, MIN_FRED_BUILD));
  }

  @Test
  public void testParseNodeNameFromVersionStr_RealWorldVersionStrings() {
    // Test with realistic version strings that might be encountered
    assertEquals(
        "Should handle typical Cryptad version",
        CRYPTAD_NODE_NAME,
        parseNodeNameFromVersionStr("Cryptad,1504,1.0,1504"));
    assertEquals(
        "Should handle typical Fred version",
        FRED_NODE_NAME,
        parseNodeNameFromVersionStr("Fred,0.7,1.0,1503"));

    // Test with version strings that might come from different Freenet forks
    assertEquals(
        "Should handle Freenet version",
        "Freenet",
        parseNodeNameFromVersionStr("Freenet,0.7,1.0,1475"));
    assertEquals(
        "Should handle other fork names",
        "Hyphanet",
        parseNodeNameFromVersionStr("Hyphanet,1.0,1.0,2000"));
  }
}
