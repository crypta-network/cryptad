package network.crypta.node

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Unit tests for the Version.kt functions, focusing on the new functions:
 * - compareBuildNumbers()
 * - isBuildAtLeast()
 * - parseNodeNameFromVersionStr()
 */
class VersionTest {

  @Test
  fun compareBuildNumbers_whenComparingCryptadAndFred_expectCryptadPreferred() {
    val lowerBuild = 1
    val higherBuild = 9999
    val sameBuild = 1500

    val cryptadLowerVsFredHigher =
      compareBuildNumbers(CRYPTAD_NODE_NAME, lowerBuild, FRED_NODE_NAME, higherBuild)
    val cryptadSameVsFredSame =
      compareBuildNumbers(CRYPTAD_NODE_NAME, sameBuild, FRED_NODE_NAME, sameBuild)
    val cryptadHigherVsFredLower =
      compareBuildNumbers(CRYPTAD_NODE_NAME, higherBuild, FRED_NODE_NAME, lowerBuild)
    val fredLowerVsCryptadHigher =
      compareBuildNumbers(FRED_NODE_NAME, lowerBuild, CRYPTAD_NODE_NAME, higherBuild)
    val fredSameVsCryptadSame =
      compareBuildNumbers(FRED_NODE_NAME, sameBuild, CRYPTAD_NODE_NAME, sameBuild)
    val fredHigherVsCryptadLower =
      compareBuildNumbers(FRED_NODE_NAME, higherBuild, CRYPTAD_NODE_NAME, lowerBuild)

    assertTrue(
      cryptadLowerVsFredHigher > 0,
      "Cryptad should be newer than Fred with lower build number",
    )
    assertTrue(
      cryptadSameVsFredSame > 0,
      "Cryptad should be newer than Fred with same build number",
    )
    assertTrue(
      cryptadHigherVsFredLower > 0,
      "Cryptad should be newer than Fred with higher build number",
    )
    assertTrue(
      fredLowerVsCryptadHigher < 0,
      "Fred should be older than Cryptad with lower build number",
    )
    assertTrue(
      fredSameVsCryptadSame < 0,
      "Fred should be older than Cryptad with same build number",
    )
    assertTrue(
      fredHigherVsCryptadLower < 0,
      "Fred should be older than Cryptad with higher build number",
    )
  }

  @Test
  fun compareBuildNumbers_whenSameNodeType_expectNumericComparison() {
    val cryptadHigher = 1505
    val cryptadLower = 1504
    val fredHigher = 1503
    val fredLower = 1502

    val cryptadHigherVsLower =
      compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadHigher, CRYPTAD_NODE_NAME, cryptadLower)
    val cryptadLowerVsHigher =
      compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadLower, CRYPTAD_NODE_NAME, cryptadHigher)
    val cryptadSameVsSame =
      compareBuildNumbers(CRYPTAD_NODE_NAME, cryptadLower, CRYPTAD_NODE_NAME, cryptadLower)
    val fredHigherVsLower =
      compareBuildNumbers(FRED_NODE_NAME, fredHigher, FRED_NODE_NAME, fredLower)
    val fredLowerVsHigher =
      compareBuildNumbers(FRED_NODE_NAME, fredLower, FRED_NODE_NAME, fredHigher)
    val fredSameVsSame = compareBuildNumbers(FRED_NODE_NAME, fredHigher, FRED_NODE_NAME, fredHigher)

    assertTrue(cryptadHigherVsLower > 0, "Higher Cryptad build should be newer")
    assertTrue(cryptadLowerVsHigher < 0, "Lower Cryptad build should be older")
    assertEquals(0, cryptadSameVsSame, "Same Cryptad build should be equal")
    assertTrue(fredHigherVsLower > 0, "Higher Fred build should be newer")
    assertTrue(fredLowerVsHigher < 0, "Lower Fred build should be older")
    assertEquals(0, fredSameVsSame, "Same Fred build should be equal")
  }

  @Test
  fun compareBuildNumbers_whenNodeNamesNull_expectBuildNumberComparison() {
    val higherBuild = 1505
    val lowerBuild = 1504

    val higherVsLowerBothNull = compareBuildNumbers(null, higherBuild, null, lowerBuild)
    val lowerVsHigherBothNull = compareBuildNumbers(null, lowerBuild, null, higherBuild)
    val sameVsSameBothNull = compareBuildNumbers(null, lowerBuild, null, lowerBuild)
    val higherVsLowerOneNull = compareBuildNumbers(null, higherBuild, FRED_NODE_NAME, lowerBuild)
    val lowerVsHigherOneNull = compareBuildNumbers(CRYPTAD_NODE_NAME, lowerBuild, null, higherBuild)

    assertTrue(higherVsLowerBothNull > 0, "Higher build number should win with null node names")
    assertTrue(lowerVsHigherBothNull < 0, "Lower build number should lose with null node names")
    assertEquals(0, sameVsSameBothNull, "Same build number should be equal with null node names")
    assertTrue(higherVsLowerOneNull > 0, "Higher build number should win with one null node name")
    assertTrue(lowerVsHigherOneNull < 0, "Lower build number should lose with one null node name")
  }

  @Test
  fun compareBuildNumbers_whenEdgeCases_expectNumericHandling() {
    val positive = 1
    val zero = 0
    val negative = -1
    val max = Int.MAX_VALUE
    val maxMinusOne = Int.MAX_VALUE - 1

    val positiveVsZero = compareBuildNumbers(CRYPTAD_NODE_NAME, positive, CRYPTAD_NODE_NAME, zero)
    val zeroVsNegative = compareBuildNumbers(FRED_NODE_NAME, zero, FRED_NODE_NAME, negative)
    val maxVsMaxMinusOne =
      compareBuildNumbers(CRYPTAD_NODE_NAME, max, CRYPTAD_NODE_NAME, maxMinusOne)

    assertTrue(positiveVsZero > 0, "Positive should be greater than zero")
    assertTrue(zeroVsNegative > 0, "Zero should be greater than negative")
    assertTrue(maxVsMaxMinusOne > 0, "Large build number comparison should work")
  }

  @Test
  fun compareBuildNumbers_whenUnknownNodeTypes_expectBuildNumberComparison() {
    val unknown = "Unknown"
    val anotherUnknown = "AnotherUnknown"
    val someOther = "SomeOther"

    val unknownVsAnotherUnknown = compareBuildNumbers(unknown, 1505, anotherUnknown, 1504)
    val unknownVsSomeOther = compareBuildNumbers(unknown, 1505, someOther, 1504)

    assertTrue(unknownVsAnotherUnknown > 0, "Unknown node type should compare by build number")
    assertTrue(
      unknownVsSomeOther > 0,
      "Unknown vs known should compare by build number when not Cryptad/Fred",
    )
  }

  @Test
  fun isBuildAtLeast_whenCryptadNode_expectAlwaysMeetsFredMinimum() {
    val lowBuild = 1
    val zeroBuild = 0
    val negativeBuild = -1

    val lowBuildAgainstFredMin = isBuildAtLeast(CRYPTAD_NODE_NAME, lowBuild, MIN_FRED_BUILD)
    val lowBuildAgainstHighMin = isBuildAtLeast(CRYPTAD_NODE_NAME, lowBuild, 9999)
    val zeroBuildAgainstFredMin = isBuildAtLeast(CRYPTAD_NODE_NAME, zeroBuild, MIN_FRED_BUILD)
    val negativeBuildAgainstFredMin =
      isBuildAtLeast(CRYPTAD_NODE_NAME, negativeBuild, MIN_FRED_BUILD)

    assertTrue(lowBuildAgainstFredMin, "Cryptad should always meet Fred minimum build requirement")
    assertTrue(lowBuildAgainstHighMin, "Cryptad with low build should still meet Fred minimum")
    assertTrue(zeroBuildAgainstFredMin, "Cryptad with zero build should still meet Fred minimum")
    assertTrue(
      negativeBuildAgainstFredMin,
      "Cryptad with negative build should still meet Fred minimum",
    )
  }

  @Test
  fun isBuildAtLeast_whenFredNode_expectMinimumCheck() {
    @Suppress("UnnecessaryLocalVariable") val sufficientBuild = MIN_FRED_BUILD
    val higherBuild = MIN_FRED_BUILD + 1
    val insufficientBuild = MIN_FRED_BUILD - 1
    val zeroBuild = 0

    val sufficientBuildMeets = isBuildAtLeast(FRED_NODE_NAME, sufficientBuild, MIN_FRED_BUILD)
    val higherBuildMeets = isBuildAtLeast(FRED_NODE_NAME, higherBuild, MIN_FRED_BUILD)
    val insufficientBuildMeets = isBuildAtLeast(FRED_NODE_NAME, insufficientBuild, MIN_FRED_BUILD)
    val zeroBuildMeets = isBuildAtLeast(FRED_NODE_NAME, zeroBuild, MIN_FRED_BUILD)

    assertTrue(sufficientBuildMeets, "Fred node with sufficient build should meet minimum")
    assertTrue(higherBuildMeets, "Fred node with higher build should meet minimum")
    assertFalse(insufficientBuildMeets, "Fred node with insufficient build should not meet minimum")
    assertFalse(zeroBuildMeets, "Fred node with zero build should not meet minimum")
  }

  @Test
  fun isBuildAtLeast_whenNullOrUnknownNodeName_expectFredRules() {
    val unknownNode = "UnknownNode"
    val sufficientBuild = MIN_FRED_BUILD
    val insufficientBuild = MIN_FRED_BUILD - 1

    val nullSufficient = isBuildAtLeast(null, sufficientBuild, MIN_FRED_BUILD)
    val nullInsufficient = isBuildAtLeast(null, insufficientBuild, MIN_FRED_BUILD)
    val unknownSufficient = isBuildAtLeast(unknownNode, sufficientBuild, MIN_FRED_BUILD)
    val unknownInsufficient = isBuildAtLeast(unknownNode, insufficientBuild, MIN_FRED_BUILD)

    assertTrue(nullSufficient, "Null node name with sufficient build should meet minimum")
    assertFalse(nullInsufficient, "Null node name with insufficient build should not meet minimum")
    assertTrue(unknownSufficient, "Unknown node name with sufficient build should meet minimum")
    assertFalse(
      unknownInsufficient,
      "Unknown node name with insufficient build should not meet minimum",
    )
  }

  @Test
  fun isBuildAtLeast_whenBoundaryValues_expectCorrectEvaluation() {
    val minimum = 1000
    val exactMinimum = 1000
    val belowMinimum = 999
    val aboveMinimum = 1001
    val zeroMinimum = 0

    val exactMinimumMeets = isBuildAtLeast(FRED_NODE_NAME, exactMinimum, minimum)
    val belowMinimumMeets = isBuildAtLeast(FRED_NODE_NAME, belowMinimum, minimum)
    val aboveMinimumMeets = isBuildAtLeast(FRED_NODE_NAME, aboveMinimum, minimum)
    val zeroMeetsZeroMinimum = isBuildAtLeast(FRED_NODE_NAME, 0, zeroMinimum)
    val positiveMeetsZeroMinimum = isBuildAtLeast(FRED_NODE_NAME, 1, zeroMinimum)
    val negativeMeetsZeroMinimum = isBuildAtLeast(FRED_NODE_NAME, -1, zeroMinimum)

    assertTrue(exactMinimumMeets, "Exact minimum should meet requirement")
    assertFalse(belowMinimumMeets, "One below minimum should not meet requirement")
    assertTrue(aboveMinimumMeets, "One above minimum should meet requirement")
    assertTrue(zeroMeetsZeroMinimum, "Any build should meet zero minimum")
    assertTrue(positiveMeetsZeroMinimum, "Positive build should meet zero minimum")
    assertFalse(negativeMeetsZeroMinimum, "Negative build should not meet zero minimum")
  }

  @Test
  fun parseNodeNameFromVersionStr_whenValidVersions_expectNodeName() {
    val singleCryptad = "Cryptad"
    val singleFred = "Fred"

    val cryptadFromFull = parseNodeNameFromVersionStr(VALID_CRYPTAD_VERSION)
    val cryptadFromMinimal = parseNodeNameFromVersionStr(MINIMAL_CRYPTAD_VERSION)
    val fredFromFull = parseNodeNameFromVersionStr(VALID_FRED_VERSION)
    val fredFromMinimal = parseNodeNameFromVersionStr(MINIMAL_FRED_VERSION)
    val cryptadFromSingle = parseNodeNameFromVersionStr(singleCryptad)
    val fredFromSingle = parseNodeNameFromVersionStr(singleFred)

    assertEquals(CRYPTAD_NODE_NAME, cryptadFromFull, "Should extract Cryptad node name")
    assertEquals(
      CRYPTAD_NODE_NAME,
      cryptadFromMinimal,
      "Should extract Cryptad from minimal version",
    )
    assertEquals(FRED_NODE_NAME, fredFromFull, "Should extract Fred node name")
    assertEquals(FRED_NODE_NAME, fredFromMinimal, "Should extract Fred from minimal version")
    assertEquals(
      CRYPTAD_NODE_NAME,
      cryptadFromSingle,
      "Should extract node name from single component",
    )
    assertEquals(FRED_NODE_NAME, fredFromSingle, "Should extract node name from single component")
  }

  @Test
  fun parseNodeNameFromVersionStr_whenNullOrEmpty_expectNullOrEmpty() {
    val whitespaceOnly = "   "

    val nullResult = parseNodeNameFromVersionStr(null)
    val emptyResult = parseNodeNameFromVersionStr(MALFORMED_VERSION_EMPTY)
    val whitespaceResult = parseNodeNameFromVersionStr(whitespaceOnly)

    assertNull(nullResult, "Null version string should return null")
    assertNull(emptyResult, "Empty version string should return null")
    assertEquals("", whitespaceResult, "Whitespace-only version string should return empty string")
  }

  @Test
  fun parseNodeNameFromVersionStr_whenMalformedVersions_expectBestEffort() {
    val onlyCommas = ",,,"
    val leadingComma = ",Cryptad,1504,1.0"

    val wrongSeparatorResult = parseNodeNameFromVersionStr(MALFORMED_VERSION_WRONG_SEPARATOR)
    val shortVersionResult = parseNodeNameFromVersionStr(MALFORMED_VERSION_SHORT)
    val onlyCommasResult = parseNodeNameFromVersionStr(onlyCommas)
    val leadingCommaResult = parseNodeNameFromVersionStr(leadingComma)

    assertEquals(
      MALFORMED_VERSION_WRONG_SEPARATOR,
      wrongSeparatorResult,
      "Version with wrong separator should return the whole string as node name",
    )
    assertEquals(
      CRYPTAD_NODE_NAME,
      shortVersionResult,
      "Should still extract node name from short version",
    )
    assertNull(onlyCommasResult, "Version with only commas should return null")
    assertEquals(
      "Cryptad",
      leadingCommaResult,
      "Version starting with comma should return first non-empty token",
    )
  }

  @Test
  fun parseNodeNameFromVersionStr_whenUnknownNodeNames_expectFirstToken() {
    val unknownVersion = "UnknownNode,1504,1.0,1504"
    val numericVersion = "123,1504,1.0"
    val specialVersion = "Node-v2.0,1504,1.0,1504"

    val unknownResult = parseNodeNameFromVersionStr(unknownVersion)
    val numericResult = parseNodeNameFromVersionStr(numericVersion)
    val specialResult = parseNodeNameFromVersionStr(specialVersion)

    assertEquals("UnknownNode", unknownResult, "Should extract unknown node name")
    assertEquals("123", numericResult, "Should extract numeric node name")
    assertEquals("Node-v2.0", specialResult, "Should extract node name with special characters")
  }

  @Test
  fun parseNodeNameFromVersionStr_whenEdgeCases_expectNodeName() {
    val longNodeName = "VeryLongNodeNameThatExceedsNormalExpectations"
    val longNodeVersion = "$longNodeName,1504,1.0,1504"
    val spaceNodeVersion = "Node Name,1504,1.0,1504"
    val trailingCommaVersion = "Cryptad,1504,1.0,1504,"
    val extraComponentVersion = "Fred,0.7,1.0,1503,extra,data"

    val longNodeResult = parseNodeNameFromVersionStr(longNodeVersion)
    val spaceNodeResult = parseNodeNameFromVersionStr(spaceNodeVersion)
    val trailingCommaResult = parseNodeNameFromVersionStr(trailingCommaVersion)
    val extraComponentResult = parseNodeNameFromVersionStr(extraComponentVersion)

    assertEquals(longNodeName, longNodeResult, "Should extract very long node name")
    assertEquals("Node Name", spaceNodeResult, "Should extract node name with spaces")
    assertEquals(
      CRYPTAD_NODE_NAME,
      trailingCommaResult,
      "Should extract node name with trailing commas",
    )
    assertEquals(
      FRED_NODE_NAME,
      extraComponentResult,
      "Should extract node name with extra components",
    )
  }

  @Test
  @Suppress("UnnecessaryLocalVariable")
  fun parseNodeNameFromVersionStr_whenUsedWithOtherFunctions_expectCompatible() {
    val cryptadVersion = VALID_CRYPTAD_VERSION
    val fredVersion = VALID_FRED_VERSION

    val cryptadName = parseNodeNameFromVersionStr(cryptadVersion)
    val fredName = parseNodeNameFromVersionStr(fredVersion)
    val cryptadNameWorks = compareBuildNumbers(cryptadName, 1504, fredName, 1503) > 0
    val cryptadMeetsFredMinimum = isBuildAtLeast(cryptadName, 1, MIN_FRED_BUILD)
    val fredMeetsFredMinimum = isBuildAtLeast(fredName, MIN_FRED_BUILD, MIN_FRED_BUILD)

    assertNotNull(cryptadName, "Should extract valid Cryptad node name")
    assertNotNull(fredName, "Should extract valid Fred node name")
    assertTrue(cryptadNameWorks, "Extracted Cryptad name should work with compareBuildNumbers")
    assertTrue(cryptadMeetsFredMinimum, "Extracted Cryptad name should work with isBuildAtLeast")
    assertTrue(fredMeetsFredMinimum, "Extracted Fred name should work with isBuildAtLeast")
  }

  @Test
  fun parseNodeNameFromVersionStr_whenRealWorldVersions_expectNodeName() {
    val cryptadVersion = "Cryptad,1504,1.0,1504"
    val fredVersion = "Fred,0.7,1.0,1503"
    val freenetVersion = "Freenet,0.7,1.0,1475"
    val hyphanetVersion = "Hyphanet,1.0,1.0,2000"

    val cryptadResult = parseNodeNameFromVersionStr(cryptadVersion)
    val fredResult = parseNodeNameFromVersionStr(fredVersion)
    val freenetResult = parseNodeNameFromVersionStr(freenetVersion)
    val hyphanetResult = parseNodeNameFromVersionStr(hyphanetVersion)

    assertEquals(CRYPTAD_NODE_NAME, cryptadResult, "Should handle typical Cryptad version")
    assertEquals(FRED_NODE_NAME, fredResult, "Should handle typical Fred version")
    assertEquals("Freenet", freenetResult, "Should handle Freenet version")
    assertEquals("Hyphanet", hyphanetResult, "Should handle other fork names")
  }

  private companion object {
    const val CRYPTAD_NODE_NAME = "Cryptad"
    const val FRED_NODE_NAME = "Fred"
    const val MIN_FRED_BUILD = 1475

    const val VALID_CRYPTAD_VERSION = "Cryptad,1504,1.0,1504"
    const val VALID_FRED_VERSION = "Fred,0.7,1.0,1503"
    const val MINIMAL_CRYPTAD_VERSION = "Cryptad,1,1.0"
    const val MINIMAL_FRED_VERSION = "Fred,0.7,1.0,1"
    const val MALFORMED_VERSION_SHORT = "Cryptad,1504"
    const val MALFORMED_VERSION_EMPTY = ""
    const val MALFORMED_VERSION_WRONG_SEPARATOR = "Cryptad;1504;1.0"
  }
}
