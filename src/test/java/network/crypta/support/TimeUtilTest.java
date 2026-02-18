package network.crypta.support;

import java.time.Instant;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static java.util.Calendar.MILLISECOND;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test case for {@link TimeUtil} class.
 *
 * @author Alberto Bacchelli &lt;sback@freenetproject.org&gt;
 */
@SuppressWarnings("java:S100") // Allow descriptive test method names with underscores
class TimeUtilTest {

  // 1w+1d+1h+1m+1s+1ms
  private static final long ONE_FOR_TERM_LONG = 694861001;

  @BeforeEach
  void setUp() {
    Locale.setDefault(Locale.US);
  }

  /** Tests formatTime(long,int,boolean) method trying the biggest long value */
  @Test
  void testFormatTime_LongIntBoolean_MaxValue() {
    String expectedForMaxLongValue = "15250284452w3d7h12m55.807s";
    assertEquals(expectedForMaxLongValue, TimeUtil.formatTime(Long.MAX_VALUE, 6, true));
  }

  /** Tests formatTime(long,int,boolean) method trying the smallest long value */
  @Test
  void testFormatTime_LongIntBoolean_MinValue() {
    String expectedForMinLongValue = "-15250284452w3d7h12m55.808s";
    assertEquals(expectedForMinLongValue, TimeUtil.formatTime(Long.MIN_VALUE, 6, true));
  }

  /** Tests formatTime(long,int) method trying the biggest long value */
  @Test
  void testFormatTime_LongInt() {
    String expectedForMaxLongValue = "15250284452w3d7h12m55s";
    assertEquals(expectedForMaxLongValue, TimeUtil.formatTime(Long.MAX_VALUE, 6));
  }

  /** Tests formatTime(long) method trying the biggest long value */
  @Test
  void testFormatTime_Long() {
    // it uses two terms by default
    String expectedForMaxLongValue = "15250284452w3d";
    assertEquals(expectedForMaxLongValue, TimeUtil.formatTime(Long.MAX_VALUE));
  }

  /**
   * Tests formatTime(long) method using known values. They could be checked using Google Calculator
   * <a
   * href="http://www.google.com/intl/en/help/features.html#calculator">http://www.google.com/intl/en/help/features.html#calculator</a>
   */
  @Test
  void testFormatTime_KnownValues() {
    long methodLong;
    String[][] valAndExpected = {
      // one week
      {"604800000", "1w"},
      // one day
      {"86400000", "1d"},
      // one hour
      {"3600000", "1h"},
      // one minute
      {"60000", "1m"},
      // one second
      {"1000", "1s"}
    };
    for (String[] strings : valAndExpected) {
      methodLong = Long.parseLong(strings[0]);
      assertEquals(TimeUtil.formatTime(methodLong), strings[1]);
    }
  }

  /**
   * Tests formatTime(long,int) method using a long value that generate every possible term kind. It
   * tests if the maxTerms arguments works correctly
   */
  @Test
  void testFormatTime_LongIntBoolean_maxTerms() {
    String[] valAndExpected = {
      // 0 terms
      "",
      // 1 term
      "1w",
      // 2 terms
      "1w1d",
      // 3 terms
      "1w1d1h",
      // 4 terms
      "1w1d1h1m",
      // 5 terms
      "1w1d1h1m1s",
      // 6 terms
      "1w1d1h1m1.001s"
    };
    for (int i = 0; i < valAndExpected.length; i++)
      assertEquals(TimeUtil.formatTime(ONE_FOR_TERM_LONG, i, true), valAndExpected[i]);
  }

  /**
   * Tests formatTime(long,int) method using one millisecond time interval. It tests if the
   * withSecondFractions argument works correctly
   */
  @Test
  void testFormatTime_LongIntBoolean_milliseconds() {
    long methodValue = 1; // 1ms
    assertEquals("0s", TimeUtil.formatTime(methodValue, 6, false));
    assertEquals("0.001s", TimeUtil.formatTime(methodValue, 6, true));
  }

  /**
   * Tests formatTime(long,int) method using a long value that generate every possible term kind. It
   * tests if the maxTerms arguments works correctly
   */
  @Test
  void testFormatTime_LongIntBoolean_tooManyTerms() {
    assertThrows(IllegalArgumentException.class, () -> TimeUtil.formatTime(ONE_FOR_TERM_LONG, 7));
  }

  /** Tests {@link TimeUtil#setTimeToZero(Instant)} */
  @Test
  void testSetTimeToZero() {
    // Test whether zeroing doesn't happen when it needs not to.

    GregorianCalendar c = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    c.set(2015, Calendar.JANUARY, 1, 0, 0, 0);
    c.set(MILLISECOND, 0);

    Instant original = c.toInstant();
    Instant zeroed = TimeUtil.setTimeToZero(original);

    assertEquals(original, zeroed);
    // Test whether zeroing happens when it should.

    c.set(2014, Calendar.DECEMBER, 31, 23, 59, 59);
    c.set(MILLISECOND, 999);
    original = c.toInstant();

    c.set(2014, Calendar.DECEMBER, 31, 0, 0, 0);
    c.set(MILLISECOND, 0);
    Instant expected = c.toInstant();

    zeroed = TimeUtil.setTimeToZero(original);

    assertEquals(expected, zeroed);
  }

  @Test
  void testToMillis_oneForTermLong() {
    assertEquals(ONE_FOR_TERM_LONG, TimeUtil.toMillis("1w1d1h1m1.001s"));
  }

  @Test
  void testToMillis_maxLong() {
    assertEquals(Long.MAX_VALUE, TimeUtil.toMillis("15250284452w3d7h12m55.807s"));
  }

  @Test
  void testToMillis_minLong() {
    assertEquals(Long.MIN_VALUE, TimeUtil.toMillis("-15250284452w3d7h12m55.808s"));
  }

  @Test
  void testRoundTrip_formatThenParse_minLong() {
    String formatted = TimeUtil.formatTime(Long.MIN_VALUE, 6, true);
    assertEquals(Long.MIN_VALUE, TimeUtil.toMillis(formatted));
  }

  @Test
  void testToMillis_empty() {
    assertEquals(0, TimeUtil.toMillis(""));
    assertEquals(0, TimeUtil.toMillis("-"));
  }

  @Test
  void testToMillis_unknownFormat() {
    assertThrows(
        NumberFormatException.class, () -> TimeUtil.toMillis("15250284452w3q7h12m55.807s"));
  }

  @Test
  void testToMillis_fractionalMillis() {
    assertEquals(100, TimeUtil.toMillis("0.1s"));
    assertEquals(10, TimeUtil.toMillis("0.01s"));
    assertEquals(1, TimeUtil.toMillis("0.001s"));
    assertEquals(0, TimeUtil.toMillis("0.0001s"));
  }

  // Additional tests for uncovered branches and methods

  @Test
  void formatTime_whenZeroWithFractions_returnsEmptyString() {
    // Arrange
    long millis = 0L;
    // Act
    String formatted = TimeUtil.formatTime(millis, 6, true);
    // Assert
    assertEquals("", formatted);
  }

  @Test
  void formatTime_whenFractionsButInsufficientTerms_fallsBackToSeconds() {
    // Arrange
    long millis = 1500L; // 1.5s
    // Act
    String formatted = TimeUtil.formatTime(millis, 1, true);
    // Assert
    assertEquals("1s", formatted);
  }

  @Test
  void formatTime_whenNegativeIntervalWithFractions_formatsWithLeadingMinus() {
    // Arrange
    long negative = -ONE_FOR_TERM_LONG;
    // Act
    String formatted = TimeUtil.formatTime(negative, 6, true);
    // Assert
    assertEquals("-1w1d1h1m1.001s", formatted);
  }

  @Test
  void formatTime_whenNegativeSubSecondWithoutFractions_returnsZeroSeconds() {
    // Arrange
    long negativeMillis = -1L;
    // Act
    String formatted = TimeUtil.formatTime(negativeMillis, 6, false);
    // Assert
    // With no fractions and absolute value < 1000, implementation returns "0s".
    assertEquals("0s", formatted);
  }

  @Test
  void toMillis_whenFractionGreaterThanOne_returnsExpectedMillis() {
    // Arrange & Act & Assert
    assertEquals(1500L, TimeUtil.toMillis("1.5s"));
  }

  @Test
  void toMillis_whenNegativeFraction_returnsNegativeMillis() {
    // Arrange & Act & Assert
    assertEquals(-1L, TimeUtil.toMillis("-0.001s"));
  }

  @Test
  void makeHTTPDate_whenEpochZero_matchesRfc1123() {
    // Arrange
    long epoch = 0L;
    // Act
    String httpDate = TimeUtil.makeHTTPDate(epoch);
    // Assert
    assertEquals("Thu, 1 Jan 1970 00:00:00 GMT", httpDate);
  }

  @Test
  void makeHTTPDate_whenArbitraryInstant_formatsCorrectly() {
    // Arrange
    Instant instant = Instant.parse("2000-01-02T03:04:05Z");
    // Act
    String httpDate = TimeUtil.makeHTTPDate(instant.toEpochMilli());
    // Assert
    assertEquals("Sun, 2 Jan 2000 03:04:05 GMT", httpDate);
  }

  @Test
  void setTimeToZero_whenDefaultTzNotUtc_truncatesByUtcDay() {
    // Arrange
    TimeZone originalTz = TimeZone.getDefault();
    try {
      TimeZone.setDefault(TimeZone.getTimeZone("America/Los_Angeles"));
      GregorianCalendar c = new GregorianCalendar(TimeZone.getTimeZone("America/Los_Angeles"));
      c.set(2021, Calendar.JULY, 10, 8, 15, 30);
      c.set(MILLISECOND, 123);
      Instant original = c.toInstant();

      // Compute expected UTC midnight by flooring epoch millis to day length
      long expectedMs = (original.toEpochMilli() / 86_400_000L) * 86_400_000L;
      Instant expected = Instant.ofEpochMilli(expectedMs);

      // Act
      Instant zeroed = TimeUtil.setTimeToZero(original);

      // Assert
      assertEquals(expected, zeroed);
    } finally {
      TimeZone.setDefault(originalTz);
    }
  }
}
