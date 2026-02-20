package network.crypta.node;

import org.junit.jupiter.api.Test;

import static network.crypta.node.Version.compareBuildNumbers;
import static network.crypta.node.Version.isBuildAtLeast;
import static network.crypta.node.Version.parseNodeNameFromVersionStr;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link Version}, focusing on compareBuildNumbers(), isBuildAtLeast(), and
 * parseNodeNameFromVersionStr().
 */
@SuppressWarnings("java:S100")
class VersionTest {

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
  void compareBuildNumbers_whenComparingCryptadAndFred_expectCryptadToBeNewer() {
    // Arrange
    int cryptadBuildLow = 1;
    int cryptadBuildSame = 1500;
    int cryptadBuildHigh = 9999;
    int fredBuildLow = 1;
    int fredBuildSame = 1500;
    int fredBuildHigh = 9999;

    // Act
    int cryptadVsFredLow =
        compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadBuildLow, FRED_NODE_NAME, fredBuildHigh);
    int cryptadVsFredSame =
        compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadBuildSame, FRED_NODE_NAME, fredBuildSame);
    int cryptadVsFredHigh =
        compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadBuildHigh, FRED_NODE_NAME, fredBuildLow);

    int fredVsCryptadLow =
        compareBuildNumbers(FRED_NODE_NAME, fredBuildLow, CRYPTAD_NODE_NAME, cryptadBuildHigh);
    int fredVsCryptadSame =
        compareBuildNumbers(FRED_NODE_NAME, fredBuildSame, CRYPTAD_NODE_NAME, cryptadBuildSame);
    int fredVsCryptadHigh =
        compareBuildNumbers(FRED_NODE_NAME, fredBuildHigh, CRYPTAD_NODE_NAME, cryptadBuildLow);

    // Assert
    assertTrue(cryptadVsFredLow > 0, "Cryptad should be newer than Fred with lower build number");
    assertTrue(cryptadVsFredSame > 0, "Cryptad should be newer than Fred with same build number");
    assertTrue(cryptadVsFredHigh > 0, "Cryptad should be newer than Fred with higher build number");

    assertTrue(fredVsCryptadLow < 0, "Fred should be older than Cryptad with lower build number");
    assertTrue(fredVsCryptadSame < 0, "Fred should be older than Cryptad with same build number");
    assertTrue(fredVsCryptadHigh < 0, "Fred should be older than Cryptad with higher build number");
  }

  @Test
  void compareBuildNumbers_whenNodeTypeMatches_expectBuildNumberOrdering() {
    // Arrange
    int cryptadNewer = 1505;
    int cryptadOlder = 1504;
    int fredNewer = 1503;
    int fredOlder = 1502;

    // Act
    int cryptadHigher =
        compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadNewer, CRYPTAD_NODE_NAME, cryptadOlder);
    int cryptadLower =
        compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadOlder, CRYPTAD_NODE_NAME, cryptadNewer);
    int cryptadEqual =
        compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadOlder, CRYPTAD_NODE_NAME, cryptadOlder);

    int fredHigher = compareBuildNumbers(FRED_NODE_NAME, fredNewer, FRED_NODE_NAME, fredOlder);
    int fredLower = compareBuildNumbers(FRED_NODE_NAME, fredOlder, FRED_NODE_NAME, fredNewer);
    int fredEqual = compareBuildNumbers(FRED_NODE_NAME, fredNewer, FRED_NODE_NAME, fredNewer);

    // Assert
    assertTrue(cryptadHigher > 0, "Higher Cryptad build should be newer");
    assertTrue(cryptadLower < 0, "Lower Cryptad build should be older");
    assertEquals(0, cryptadEqual, "Same Cryptad build should be equal");

    assertTrue(fredHigher > 0, "Higher Fred build should be newer");
    assertTrue(fredLower < 0, "Lower Fred build should be older");
    assertEquals(0, fredEqual, "Same Fred build should be equal");
  }

  @Test
  void compareBuildNumbers_whenNodeNamesAreNullOrMixed_expectBuildFallbackComparison() {
    // Arrange
    int higherBuild = 1505;
    int lowerBuild = 1504;

    // Act
    int nullVsNullHigher = compareBuildNumbers(null, higherBuild, null, lowerBuild);
    int nullVsNullLower = compareBuildNumbers(null, lowerBuild, null, higherBuild);
    int nullVsNullEqual = compareBuildNumbers(null, lowerBuild, null, lowerBuild);
    int nullVsFred = compareBuildNumbers(null, higherBuild, FRED_NODE_NAME, lowerBuild);
    int cryptadVsNull = compareBuildNumbers(CRYPTAD_NODE_NAME, lowerBuild, null, higherBuild);

    // Assert
    assertTrue(nullVsNullHigher > 0, "Higher build number should win with null node names");
    assertTrue(nullVsNullLower < 0, "Lower build number should lose with null node names");
    assertEquals(0, nullVsNullEqual, "Same build number should be equal with null node names");
    assertTrue(nullVsFred > 0, "Higher build number should win with one null node name");
    assertTrue(cryptadVsNull < 0, "Lower build number should lose with one null node name");
  }

  @Test
  void compareBuildNumbers_whenUsingBoundaryBuildValues_expectConsistentOrdering() {
    // Arrange
    int zero = 0;
    int negativeOne = -1;

    // Act
    int positiveVsZero = compareBuildNumbers(CRYPTAD_NODE_NAME, 1, CRYPTAD_NODE_NAME, zero);
    int zeroVsNegative = compareBuildNumbers(FRED_NODE_NAME, zero, FRED_NODE_NAME, negativeOne);
    int maxVsMaxMinusOne =
        compareBuildNumbers(
            CRYPTAD_NODE_NAME, Integer.MAX_VALUE, CRYPTAD_NODE_NAME, Integer.MAX_VALUE - 1);

    // Assert
    assertTrue(positiveVsZero > 0, "Positive should be greater than zero");
    assertTrue(zeroVsNegative > 0, "Zero should be greater than negative");
    assertTrue(maxVsMaxMinusOne > 0, "Large build number comparison should work");
  }

  @Test
  void compareBuildNumbers_whenNodeTypesUnknown_expectBuildFallbackComparison() {
    // Arrange
    int newerBuild = 1505;
    int olderBuild = 1504;

    // Act
    int unknownVsUnknown = compareBuildNumbers("Unknown", newerBuild, "AnotherUnknown", olderBuild);
    int unknownVsKnown = compareBuildNumbers("Unknown", newerBuild, "SomeOther", olderBuild);

    // Assert
    assertTrue(unknownVsUnknown > 0, "Unknown node type should compare by build number");
    assertTrue(
        unknownVsKnown > 0,
        "Unknown vs known should compare by build number when not Cryptad/Fred");
  }

  @Test
  void isBuildAtLeast_whenNodeIsCryptad_expectAlwaysTrue() {
    // Arrange
    int fredMinimum = MIN_FRED_BUILD;

    // Act
    boolean cryptadWithPositiveBuild =
        isBuildAtLeast(CRYPTAD_NODE_NAME, MIN_CRYPTAD_BUILD, fredMinimum);
    boolean cryptadWithVeryLowBuild = isBuildAtLeast(CRYPTAD_NODE_NAME, 1, 9999);
    boolean cryptadWithZeroBuild = isBuildAtLeast(CRYPTAD_NODE_NAME, 0, fredMinimum);
    boolean cryptadWithNegativeBuild = isBuildAtLeast(CRYPTAD_NODE_NAME, -1, fredMinimum);

    // Assert
    assertTrue(
        cryptadWithPositiveBuild, "Cryptad should always meet Fred minimum build requirement");
    assertTrue(cryptadWithVeryLowBuild, "Cryptad with low build should still meet Fred minimum");
    assertTrue(cryptadWithZeroBuild, "Cryptad with zero build should still meet Fred minimum");
    assertTrue(
        cryptadWithNegativeBuild, "Cryptad with negative build should still meet Fred minimum");
  }

  @Test
  void isBuildAtLeast_whenNodeIsFred_expectMinimumEnforced() {
    // Arrange
    int minimum = MIN_FRED_BUILD;

    // Act
    boolean atMinimum = isBuildAtLeast(FRED_NODE_NAME, minimum, minimum);
    boolean aboveMinimum = isBuildAtLeast(FRED_NODE_NAME, minimum + 1, minimum);
    boolean belowMinimum = isBuildAtLeast(FRED_NODE_NAME, minimum - 1, minimum);
    boolean zeroBuild = isBuildAtLeast(FRED_NODE_NAME, 0, minimum);

    // Assert
    assertTrue(atMinimum, "Fred node with sufficient build should meet minimum");
    assertTrue(aboveMinimum, "Fred node with higher build should meet minimum");
    assertFalse(belowMinimum, "Fred node with insufficient build should not meet minimum");
    assertFalse(zeroBuild, "Fred node with zero build should not meet minimum");
  }

  @Test
  void isBuildAtLeast_whenNodeNameNullOrUnknown_expectFredRules() {
    // Arrange
    int minimum = MIN_FRED_BUILD;

    // Act
    boolean nullNameAtMinimum = isBuildAtLeast(null, minimum, minimum);
    boolean nullNameBelowMinimum = isBuildAtLeast(null, minimum - 1, minimum);
    boolean unknownNameAtMinimum = isBuildAtLeast("UnknownNode", minimum, minimum);
    boolean unknownNameBelowMinimum = isBuildAtLeast("UnknownNode", minimum - 1, minimum);

    // Assert
    assertTrue(nullNameAtMinimum, "Null node name with sufficient build should meet minimum");
    assertFalse(
        nullNameBelowMinimum, "Null node name with insufficient build should not meet minimum");
    assertTrue(unknownNameAtMinimum, "Unknown node name with sufficient build should meet minimum");
    assertFalse(
        unknownNameBelowMinimum,
        "Unknown node name with insufficient build should not meet minimum");
  }

  @Test
  void isBuildAtLeast_whenTestingThresholdBoundaries_expectExpectedBooleanResult() {
    // Arrange
    int minimum = 1000;

    // Act
    boolean exactMinimum = isBuildAtLeast(FRED_NODE_NAME, minimum, minimum);
    boolean oneBelow = isBuildAtLeast(FRED_NODE_NAME, minimum - 1, minimum);
    boolean oneAbove = isBuildAtLeast(FRED_NODE_NAME, minimum + 1, minimum);
    boolean zeroMinimumWithZeroBuild = isBuildAtLeast(FRED_NODE_NAME, 0, 0);
    boolean zeroMinimumWithPositiveBuild = isBuildAtLeast(FRED_NODE_NAME, 1, 0);
    boolean zeroMinimumWithNegativeBuild = isBuildAtLeast(FRED_NODE_NAME, -1, 0);

    // Assert
    assertTrue(exactMinimum, "Exact minimum should meet requirement");
    assertFalse(oneBelow, "One below minimum should not meet requirement");
    assertTrue(oneAbove, "One above minimum should meet requirement");
    assertTrue(zeroMinimumWithZeroBuild, "Any build should meet zero minimum");
    assertTrue(zeroMinimumWithPositiveBuild, "Positive build should meet zero minimum");
    assertFalse(zeroMinimumWithNegativeBuild, "Negative build should not meet zero minimum");
  }

  @Test
  void parseNodeNameFromVersionStr_whenVersionIsValid_expectNodeNameExtracted() {
    // Arrange
    String singleComponentCryptad = "Cryptad";
    String singleComponentFred = "Fred";

    // Act
    String cryptadFromValid = parseNodeNameFromVersionStr(VALID_CRYPTAD_VERSION);
    String cryptadFromMinimal = parseNodeNameFromVersionStr(MINIMAL_CRYPTAD_VERSION);
    String fredFromValid = parseNodeNameFromVersionStr(VALID_FRED_VERSION);
    String fredFromMinimal = parseNodeNameFromVersionStr(MINIMAL_FRED_VERSION);
    String cryptadFromSingle = parseNodeNameFromVersionStr(singleComponentCryptad);
    String fredFromSingle = parseNodeNameFromVersionStr(singleComponentFred);

    // Assert
    assertEquals(CRYPTAD_NODE_NAME, cryptadFromValid, "Should extract Cryptad node name");
    assertEquals(
        CRYPTAD_NODE_NAME, cryptadFromMinimal, "Should extract Cryptad from minimal version");
    assertEquals(FRED_NODE_NAME, fredFromValid, "Should extract Fred node name");
    assertEquals(FRED_NODE_NAME, fredFromMinimal, "Should extract Fred from minimal version");
    assertEquals(
        CRYPTAD_NODE_NAME, cryptadFromSingle, "Should extract node name from single component");
    assertEquals(FRED_NODE_NAME, fredFromSingle, "Should extract node name from single component");
  }

  @Test
  void parseNodeNameFromVersionStr_whenInputNullOrEmpty_expectNullOrEmptyName() {
    // Arrange
    String whitespaceOnly = "   ";

    // Act
    //noinspection ConstantValue
    String nodeFromNull = parseNodeNameFromVersionStr(null);
    String nodeFromEmpty = parseNodeNameFromVersionStr(MALFORMED_VERSION_EMPTY);
    String nodeFromWhitespace = parseNodeNameFromVersionStr(whitespaceOnly);

    // Assert
    //noinspection ConstantValue
    assertNull(nodeFromNull, "Null version string should return null");
    assertNull(nodeFromEmpty, "Empty version string should return null");
    assertEquals(
        "", nodeFromWhitespace, "Whitespace-only version string should return empty string");
  }

  @Test
  void parseNodeNameFromVersionStr_whenVersionMalformed_expectBestEffortExtraction() {
    // Arrange
    String commaOnly = ",,,";
    String leadingComma = ",Cryptad,1504,1.0";

    // Act
    String nodeFromWrongSeparator = parseNodeNameFromVersionStr(MALFORMED_VERSION_WRONG_SEPARATOR);
    String nodeFromShort = parseNodeNameFromVersionStr(MALFORMED_VERSION_SHORT);
    String nodeFromCommasOnly = parseNodeNameFromVersionStr(commaOnly);
    String nodeFromLeadingComma = parseNodeNameFromVersionStr(leadingComma);

    // Assert
    assertEquals(
        MALFORMED_VERSION_WRONG_SEPARATOR,
        nodeFromWrongSeparator,
        "Version with wrong separator should return the whole string as node name");
    assertEquals(
        CRYPTAD_NODE_NAME, nodeFromShort, "Should still extract node name from short version");
    assertNull(nodeFromCommasOnly, "Version with only commas should return null");
    assertEquals(
        "Cryptad",
        nodeFromLeadingComma,
        "Version starting with comma should return first non-empty token");
  }

  @Test
  void parseNodeNameFromVersionStr_whenNodeNameUnknown_expectNameReturned() {
    // Arrange
    String unknownVersion = "UnknownNode,1504,1.0,1504";
    String numericVersion = "123,1504,1.0";
    String specialCharVersion = "Node-v2.0,1504,1.0,1504";

    // Act
    String unknownNode = parseNodeNameFromVersionStr(unknownVersion);
    String numericNode = parseNodeNameFromVersionStr(numericVersion);
    String specialNode = parseNodeNameFromVersionStr(specialCharVersion);

    // Assert
    assertEquals("UnknownNode", unknownNode, "Should extract unknown node name");
    assertEquals("123", numericNode, "Should extract numeric node name");
    assertEquals("Node-v2.0", specialNode, "Should extract node name with special characters");
  }

  @Test
  void parseNodeNameFromVersionStr_whenTestingEdgeCases_expectNodeNamePreserved() {
    // Arrange
    String longNodeName = "VeryLongNodeNameThatExceedsNormalExpectations";
    String longNameVersion = longNodeName + ",1504,1.0,1504";
    String spacedNameVersion = "Node Name,1504,1.0,1504";
    String trailingCommaVersion = "Cryptad,1504,1.0,1504,";
    String extraComponentsVersion = "Fred,0.7,1.0,1503,extra,data";

    // Act
    String longName = parseNodeNameFromVersionStr(longNameVersion);
    String spacedName = parseNodeNameFromVersionStr(spacedNameVersion);
    String trailingCommaName = parseNodeNameFromVersionStr(trailingCommaVersion);
    String extraComponentsName = parseNodeNameFromVersionStr(extraComponentsVersion);

    // Assert
    assertEquals(longNodeName, longName, "Should extract very long node name");
    assertEquals("Node Name", spacedName, "Should extract node name with spaces");
    assertEquals(
        CRYPTAD_NODE_NAME, trailingCommaName, "Should extract node name with trailing commas");
    assertEquals(
        FRED_NODE_NAME, extraComponentsName, "Should extract node name with extra components");
  }

  @Test
  void parseNodeNameFromVersionStr_whenUsedWithOtherVersionApis_expectInteroperability() {
    // Arrange
    int cryptadBuild = 1504;
    int fredBuild = 1503;

    // Act
    String cryptadName = parseNodeNameFromVersionStr(VALID_CRYPTAD_VERSION);
    String fredName = parseNodeNameFromVersionStr(VALID_FRED_VERSION);
    int compareResult = compareBuildNumbers(cryptadName, cryptadBuild, fredName, fredBuild);
    boolean cryptadAtLeast = isBuildAtLeast(cryptadName, 1, MIN_FRED_BUILD);
    boolean fredAtLeast = isBuildAtLeast(fredName, MIN_FRED_BUILD, MIN_FRED_BUILD);

    // Assert
    assertNotNull(cryptadName, "Should extract valid Cryptad node name");
    assertNotNull(fredName, "Should extract valid Fred node name");
    assertTrue(compareResult > 0, "Extracted Cryptad name should work with compareBuildNumbers");
    assertTrue(cryptadAtLeast, "Extracted Cryptad name should work with isBuildAtLeast");
    assertTrue(fredAtLeast, "Extracted Fred name should work with isBuildAtLeast");
  }

  @Test
  void parseNodeNameFromVersionStr_whenUsingRealWorldExamples_expectExpectedNodeNames() {
    // Arrange
    String typicalCryptadVersion = "Cryptad,1504,1.0,1504";
    String typicalFredVersion = "Fred,0.7,1.0,1503";
    String freenetVersion = "Freenet,0.7,1.0,1475";
    String hyphanetVersion = "Hyphanet,1.0,1.0,2000";

    // Act
    String cryptadName = parseNodeNameFromVersionStr(typicalCryptadVersion);
    String fredName = parseNodeNameFromVersionStr(typicalFredVersion);
    String freenetName = parseNodeNameFromVersionStr(freenetVersion);
    String hyphanetName = parseNodeNameFromVersionStr(hyphanetVersion);

    // Assert
    assertEquals(CRYPTAD_NODE_NAME, cryptadName, "Should handle typical Cryptad version");
    assertEquals(FRED_NODE_NAME, fredName, "Should handle typical Fred version");
    assertEquals("Freenet", freenetName, "Should handle Freenet version");
    assertEquals("Hyphanet", hyphanetName, "Should handle other fork names");
  }
}
