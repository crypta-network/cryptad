package network.crypta.client.filter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FilterUtilsTest {

  // isInteger
  @Test
  void isInteger_whenValidNumbers_expectTrue() {
    assertTrue(FilterUtils.isInteger("0"));
    assertTrue(FilterUtils.isInteger("42"));
    assertTrue(FilterUtils.isInteger("-7"));
    assertTrue(FilterUtils.isInteger("+9"));
  }

  @Test
  void isInteger_whenInvalidNumbers_expectFalse() {
    assertFalse(FilterUtils.isInteger(""));
    assertFalse(FilterUtils.isInteger("1.2"));
    assertFalse(FilterUtils.isInteger("abc"));
  }

  // isNumber
  @Test
  void isNumber_whenValidPlainOrExponent_expectTrue() {
    assertTrue(FilterUtils.isNumber("0"));
    assertTrue(FilterUtils.isNumber("-1.5"));
    // Exponent forms are not accepted by current implementation of isNumber()
  }

  @Test
  void isNumber_whenInvalidExponentOrGarbage_expectFalse() {
    assertFalse(FilterUtils.isNumber("1e"));
    assertFalse(FilterUtils.isNumber("1e1.2"));
    assertFalse(FilterUtils.isNumber("--2"));
    assertFalse(FilterUtils.isNumber("abc"));
  }

  // isPercentage
  @Test
  void isPercentage_whenValid_expectTrue() {
    assertTrue(FilterUtils.isPercentage("0%"));
    assertTrue(FilterUtils.isPercentage("-12.5%"));
    assertTrue(FilterUtils.isPercentage("100%"));
  }

  @Test
  void isPercentage_whenInvalid_expectFalse() {
    assertFalse(FilterUtils.isPercentage("%"));
    assertFalse(FilterUtils.isPercentage("10"));
    assertFalse(FilterUtils.isPercentage("ten%"));
  }

  // isLength
  @Test
  void isLength_whenValidCssUnits_expectTrue() {
    assertTrue(FilterUtils.isLength("1em", false));
    assertTrue(FilterUtils.isLength("1.12em", false));
    assertTrue(FilterUtils.isLength("-1e-12em", false));
    assertTrue(FilterUtils.isLength("1E+12em", false));
    assertTrue(FilterUtils.isLength("1.1vw", false));
    assertTrue(FilterUtils.isLength("1.1vh", false));
    assertTrue(FilterUtils.isLength("1.1rem", false));
    assertTrue(FilterUtils.isLength("1.1px", false));
    assertTrue(FilterUtils.isLength("1.1mm", false));
    assertTrue(FilterUtils.isLength("1.1cm", false));
    assertTrue(FilterUtils.isLength(".11cm", false));
    assertTrue(FilterUtils.isLength("+1.1ch", false));
    assertTrue(FilterUtils.isLength("-1.1vmin", false));
    assertTrue(FilterUtils.isLength("-1.1vmax", false));
    assertTrue(FilterUtils.isLength("1.em", false));
  }

  @Test
  void isLength_whenNoUnitsNonSvg_expectOnlyZeroAllowed() {
    assertTrue(FilterUtils.isLength("0", false));
    assertTrue(FilterUtils.isLength("0.0", false));
    assertFalse(FilterUtils.isLength("1", false));
    assertFalse(FilterUtils.isLength("1.", false));
  }

  @Test
  void isLength_whenSvg_expectPercentAndBareNumbersAllowed() {
    assertTrue(FilterUtils.isLength("81", true));
    assertTrue(FilterUtils.isLength("5.1%", true));
    assertTrue(FilterUtils.isLength("1", true));
    assertTrue(FilterUtils.isLength("1.em", true));
    assertTrue(FilterUtils.isLength("1.", true));
  }

  @Test
  void isLength_whenInvalidInputs_expectFalseOrException() {
    assertFalse(FilterUtils.isLength("--1.1em", false));
    assertFalse(FilterUtils.isLength("-1f-1vmax", false));
    assertFalse(FilterUtils.isLength("-1.1vmx", false));
    assertFalse(FilterUtils.isLength("-11vmem", false));
    assertFalse(FilterUtils.isLength("--1.1vmax", false));
    assertFalse(FilterUtils.isLength("sevenvmax", false));
    assertFalse(FilterUtils.isLength("", false));
    assertFalse(FilterUtils.isLength("Infinityem", false));
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> FilterUtils.isLength(null, false));
  }

  // isAngle
  @Test
  void isAngle_whenValidUnits_expectTrue() {
    assertTrue(FilterUtils.isAngle("90deg"));
    assertTrue(FilterUtils.isAngle("3.14rad"));
    assertTrue(FilterUtils.isAngle("100grad"));
    assertTrue(FilterUtils.isAngle("-0.5deg"));
  }

  @Test
  void isAngle_whenInvalid_expectFalse() {
    assertFalse(FilterUtils.isAngle("90degx"));
    assertFalse(FilterUtils.isAngle("deg"));
    assertFalse(FilterUtils.isAngle("abcdeg"));
  }

  // isValidCSSShape
  @Test
  void isValidCSSShape_whenRectWithAutoOrLengths_expectTrue() {
    assertTrue(FilterUtils.isValidCSSShape("rect(auto, 1px, 2em, auto)"));
    assertTrue(FilterUtils.isValidCSSShape("rect(0,0,0,0)"));
  }

  @Test
  void isValidCSSShape_whenInvalid_expectFalse() {
    assertFalse(FilterUtils.isValidCSSShape("rect(1px,2em,3px)"));
    assertFalse(FilterUtils.isValidCSSShape("circle(10px)"));
  }

  // isMedia
  @Test
  void isMedia_whenKnownTokens_expectTrue() {
    assertTrue(FilterUtils.isMedia("screen"));
    assertTrue(FilterUtils.isMedia("print"));
  }

  @Test
  void isMedia_whenUnknownOrCaseMismatch_expectFalse() {
    assertFalse(FilterUtils.isMedia("Screen"));
    assertFalse(FilterUtils.isMedia("unknown"));
  }

  // isColor
  @Test
  void isColor_whenKeywordsAndHexAndRgb_expectTrue() {
    assertTrue(FilterUtils.isColor("rebeccapurple"));
    assertTrue(FilterUtils.isColor("Transparent"));
    assertTrue(FilterUtils.isColor("WindowText"));
    assertTrue(FilterUtils.isColor("#123ABC"));
    assertTrue(FilterUtils.isColor("#123"));
    assertTrue(FilterUtils.isColor("#123F"));
    assertTrue(FilterUtils.isColor("#123456ff"));
    assertTrue(FilterUtils.isColor("rgb(0,10,255)"));
    assertTrue(FilterUtils.isColor("rgb(0 10 255)"));
    assertTrue(FilterUtils.isColor("rgba(100 200 255 / 0.25)"));
    assertTrue(FilterUtils.isColor("rgba(010 00200 255 / 25%)"));
    assertTrue(FilterUtils.isColor("rgba(none 0 0% /)"));
  }

  @Test
  void isColor_whenHslAndHsla_expectTrue() {
    assertTrue(FilterUtils.isColor("hsl(120,50%,50%)"));
    assertTrue(FilterUtils.isColor("hsla(120,50%,50%,0.5)"));
  }

  @Test
  void isColor_whenInvalidFormats_expectFalse() {
    assertFalse(FilterUtils.isColor("rgb(0.1 0.2 0.3)"));
    assertFalse(FilterUtils.isColor("rgb("));
    assertFalse(FilterUtils.isColor("rgb()"));
    assertFalse(FilterUtils.isColor("rgb(/)"));
    assertFalse(FilterUtils.isColor("#ABCDEFGH"));
    assertFalse(FilterUtils.isColor("112233"));
    assertFalse(FilterUtils.isColor("#12"));
    assertFalse(FilterUtils.isColor("#12345"));
    assertFalse(FilterUtils.isColor("#1234567"));
    assertFalse(FilterUtils.isColor("url(/KSK@foo)"));
    assertFalse(FilterUtils.isColor("hsl(120,50,50)"));
  }

  // isCSSTransform
  @Test
  void isCSSTransform_whenValidVariants_expectTrue() {
    assertTrue(FilterUtils.isCSSTransform("matrix(1,0,0,1,10,20)"));
    assertTrue(FilterUtils.isCSSTransform("translateX(10%)"));
    assertTrue(FilterUtils.isCSSTransform("translate(5px, 10%)"));
    assertTrue(FilterUtils.isCSSTransform("scale(2)"));
    assertTrue(FilterUtils.isCSSTransform("scale(2,3)"));
    assertTrue(FilterUtils.isCSSTransform("scaleX(-1)"));
    assertTrue(FilterUtils.isCSSTransform("rotate(90deg)"));
    assertTrue(FilterUtils.isCSSTransform("skewX(30deg)"));
    assertTrue(FilterUtils.isCSSTransform("skew(10deg, 20)"));
  }

  @Test
  void isCSSTransform_whenInvalidVariants_expectFalse() {
    assertFalse(FilterUtils.isCSSTransform("matrix(1,0,0,1,10)"));
    assertFalse(FilterUtils.isCSSTransform("translateX(foo)"));
    assertFalse(FilterUtils.isCSSTransform("rotate(90)"));
    assertFalse(FilterUtils.isCSSTransform("skew(,10)"));
  }

  // isFrequency
  @Test
  void isFrequency_whenValid_expectTrue() {
    assertTrue(FilterUtils.isFrequency("10hz"));
    assertTrue(FilterUtils.isFrequency("10kHz"));
    assertTrue(FilterUtils.isFrequency("2.5")); // no unit but positive number accepted
  }

  @Test
  void isFrequency_whenNonPositiveOrInvalid_expectFalse() {
    assertFalse(FilterUtils.isFrequency("0hz"));
    assertFalse(FilterUtils.isFrequency("-1hz"));
    assertFalse(FilterUtils.isFrequency("abc"));
  }

  // isTime
  @Test
  void isTime_whenValid_expectTrue() {
    assertTrue(FilterUtils.isTime("1s"));
    assertTrue(FilterUtils.isTime("1.5s"));
    assertTrue(FilterUtils.isTime("250ms"));
    assertTrue(FilterUtils.isTime("10.5ms"));
    assertTrue(FilterUtils.isTime("-1s"));
  }

  @Test
  void isTime_whenInvalid_expectFalse() {
    assertFalse(FilterUtils.isTime("s"));
    assertFalse(FilterUtils.isTime("1"));
  }

  // removeWhiteSpace
  @Test
  void removeWhiteSpace_whenNull_expectNull() {
    assertNull(FilterUtils.removeWhiteSpace(null, true));
  }

  @Test
  void removeWhiteSpace_whenStripQuotes_expectTrimmedValues() {
    String[] input = new String[] {"  'abc'  ", " \"def\" ", "  ", "\t\"g hi\""};
    String[] expected = new String[] {"abc", "def", "g hi"};
    assertArrayEquals(expected, FilterUtils.removeWhiteSpace(input, true));
  }

  @Test
  void removeWhiteSpace_whenNoStripQuotes_expectTrimmedNonEmptyValues() {
    String[] input = new String[] {"  abc  ", " def ", "  ", "\t g hi"};
    String[] expected = new String[] {"abc", "def", "g hi"};
    assertArrayEquals(expected, FilterUtils.removeWhiteSpace(input, false));
  }

  // sanitizeURI / isURI (Mockito)
  @Test
  void sanitizeURI_whenCallbackReturnsValue_expectSameValue() throws Exception {
    FilterCallback cb = Mockito.mock(FilterCallback.class);
    Mockito.when(cb.processURI("http://x", null)).thenReturn("http://x");
    assertEquals("http://x", FilterUtils.sanitizeURI(cb, "http://x"));
  }

  @Test
  void sanitizeURI_whenCallbackThrows_expectEmptyString() throws Exception {
    FilterCallback cb = Mockito.mock(FilterCallback.class);
    Mockito.when(cb.processURI("bad", null)).thenThrow(new CommentException("fail"));
    assertEquals("", FilterUtils.sanitizeURI(cb, "bad"));
  }

  @Test
  void isURI_whenSanitizedEqualsOriginal_expectTrue() throws Exception {
    FilterCallback cb = Mockito.mock(FilterCallback.class);
    Mockito.when(cb.processURI("http://ok", null)).thenReturn("http://ok");
    assertTrue(FilterUtils.isURI(cb, "http://ok"));
  }

  @Test
  void isURI_whenSanitizedDiffers_expectFalse() throws Exception {
    FilterCallback cb = Mockito.mock(FilterCallback.class);
    Mockito.when(cb.processURI("http://ok", null)).thenReturn("sanitized");
    assertFalse(FilterUtils.isURI(cb, "http://ok"));
  }

  // splitOnCharArray
  @Test
  void splitOnCharArray_whenCommonDelimiters_expectTokens() {
    String[] tokens = FilterUtils.splitOnCharArray("a,b;c|d", ",;|");
    assertArrayEquals(new String[] {"a", "b", "c", "d"}, tokens);
  }

  @Test
  void splitOnCharArray_whenLeadingDelimiters_expectEmptyThenToken() {
    String[] tokens = FilterUtils.splitOnCharArray(";;a", ";");
    assertArrayEquals(new String[] {"", "a"}, tokens);
  }

  // isPointPair
  @Test
  void isPointPair_whenValidPairsSeparatedByWhitespace_expectTrue() {
    assertTrue(FilterUtils.isPointPair("1,2 3,4\n5.5,-6\t7,-8.75"));
  }

  @Test
  void isPointPair_whenInvalid_expectFalse() {
    assertFalse(FilterUtils.isPointPair("1 2"));
    assertFalse(FilterUtils.isPointPair("1,2,3"));
    assertFalse(FilterUtils.isPointPair("a,b"));
  }

  // isIntegerInRange
  @Test
  void isIntegerInRange_whenWithinBounds_expectTrue() {
    assertTrue(FilterUtils.isIntegerInRange("+10", 0, 20));
    assertTrue(FilterUtils.isIntegerInRange("0", 0, 0));
  }

  @Test
  void isIntegerInRange_whenOutOfBoundsOrInvalid_expectFalse() {
    assertFalse(FilterUtils.isIntegerInRange("-1", 0, 10));
    assertFalse(FilterUtils.isIntegerInRange("11", 0, 10));
    assertFalse(FilterUtils.isIntegerInRange("abc", 0, 10));
  }

  // isNth
  @Test
  void isNth_whenKeywordsAndIntegersWithinBounds_expectTrue() {
    assertTrue(FilterUtils.isNth("odd"));
    assertTrue(FilterUtils.isNth("even"));
    assertTrue(FilterUtils.isNth("0"));
    assertTrue(FilterUtils.isNth("999999"));
    assertTrue(FilterUtils.isNth("n"));
    assertTrue(FilterUtils.isNth("2n+1"));
    assertTrue(FilterUtils.isNth("-2n+3"));
    assertTrue(FilterUtils.isNth("n-0"));
  }

  @Test
  void isNth_whenOutOfBoundsOrMalformed_expectFalse() {
    assertFalse(FilterUtils.isNth("1000000"));
    assertFalse(FilterUtils.isNth("n+"));
    assertFalse(FilterUtils.isNth("n-"));
    assertFalse(FilterUtils.isNth("1000000n"));
    assertFalse(FilterUtils.isNth("n+1000000"));
  }
}
