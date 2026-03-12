package network.crypta.support;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Utilities for working with times and durations.
 *
 * <p>This class provides helpers to:
 *
 * <ul>
 *   <li>Format a duration in milliseconds into a compact string using units {@code w}, {@code d},
 *       {@code h}, {@code m}, and {@code s} (optionally with fractional seconds).
 *   <li>Parse a human-friendly interval string (e.g., {@code 2h30m15.250s}) into milliseconds with
 *       overflow saturation.
 *   <li>Create RFC&nbsp;1123 timestamps suitable for HTTP headers.
 *   <li>Truncate an {@link Instant} to the start of its UTC day.
 * </ul>
 *
 * <p>The class is stateless and thread-safe.
 */
public class TimeUtil {

  // Split the regex into smaller parts for readability and to keep individual pattern complexity
  // low (Sonar S5843).
  private static final String TIME_INTERVAL_PART_1 =
      "-?(?:(\\d+)w)?(?:(\\d+)d)?(?:(\\d+)h)?(?:(\\d+)m)?"; // weeks, days, hours, minutes
  private static final String TIME_INTERVAL_PART_2 =
      "(?:(\\d+)([.]\\d+)?s)?"; // seconds and optional fractional seconds
  private static final Pattern TIME_INTERVAL_PATTERN =
      Pattern.compile(TIME_INTERVAL_PART_1 + TIME_INTERVAL_PART_2);

  private TimeUtil() {}

  /**
   * Formats a duration into a compact {@code w/d/h/m/s} string.
   *
   * <p>The output contains up to {@code maxTerms} non-zero units, ordered from the largest to the
   * smallest: weeks ({@code w}), days ({@code d}), hours ({@code h}), minutes ({@code m}), and
   * seconds ({@code s}). When {@code withSecondFractions} is {@code true} and at least two term
   * slots remain, seconds are rendered with milliseconds as a fractional part to three decimal
   * places (e.g., {@code 1.234s}); otherwise seconds are truncated to whole seconds.
   *
   * <p>Negative durations are prefixed with {@code -}. The implementation preserves the full
   * magnitude for {@link Long#MIN_VALUE} by internally carrying an extra millisecond during the
   * conversion. When {@code withSecondFractions} is {@code false} and the absolute value is less
   * than one second, the method returns {@code "0s"} (no sign).
   *
   * @param timeInterval duration to format, in milliseconds
   * @param maxTerms maximum number of units to include; intended range is {@code 1..6}
   * @param withSecondFractions whether to include a fractional seconds component when possible
   * @return the formatted string, never {@code null}
   * @throws IllegalArgumentException if {@code maxTerms > 6}
   * @see #formatTime(long)
   * @see #formatTime(long, int)
   */
  public static String formatTime(long timeInterval, int maxTerms, boolean withSecondFractions) {
    if (maxTerms > 6) throw new IllegalArgumentException();

    StringBuilder sb = new StringBuilder(64);
    long remaining = timeInterval;
    int[] termCount = {0};

    boolean neg = remaining < 0;
    boolean extraOneMs = false;
    if (neg) {
      sb.append('-');
      // Preserve the full magnitude for Long.MIN_VALUE by tracking one extra millisecond
      // separately.
      // abs(Long.MIN_VALUE) overflows; use Long.MAX_VALUE and remember +1 ms to apply in seconds.
      if (remaining == Long.MIN_VALUE) {
        remaining = Long.MAX_VALUE;
        extraOneMs = true;
      } else {
        remaining = -remaining;
      }
    }

    // Collapse sub-second values to "0s" when fractions are not requested.
    if (!withSecondFractions && remaining < 1000) {
      return "0s";
    }

    // Weeks
    long weeks = DAYS.convert(remaining, MILLISECONDS) / 7;
    if (reachedMaxTermsAfterAppend(sb, weeks, 'w', maxTerms, termCount)) return sb.toString();
    remaining -= DAYS.toMillis(7 * weeks);

    // Days
    long days = DAYS.convert(remaining, MILLISECONDS);
    if (reachedMaxTermsAfterAppend(sb, days, 'd', maxTerms, termCount)) return sb.toString();
    remaining -= DAYS.toMillis(days);

    // Hours
    long hours = HOURS.convert(remaining, MILLISECONDS);
    if (reachedMaxTermsAfterAppend(sb, hours, 'h', maxTerms, termCount)) return sb.toString();
    remaining -= HOURS.toMillis(hours);

    // Minutes
    long minutes = MINUTES.convert(remaining, MILLISECONDS);
    if (reachedMaxTermsAfterAppend(sb, minutes, 'm', maxTerms, termCount)) return sb.toString();
    remaining -= MINUTES.toMillis(minutes);

    // Seconds (optionally with a fractional part)
    appendSeconds(sb, remaining, withSecondFractions, maxTerms, termCount, extraOneMs);

    return sb.toString();
  }

  // Returns true when the term limit has been met, so the caller stops emitting more units.
  private static boolean reachedMaxTermsAfterAppend(
      StringBuilder sb, long amount, char suffix, int maxTerms, int[] termCount) {
    if (amount > 0) {
      if (termCount[0] >= maxTerms) {
        return true; // Already at limit; signal to stop.
      }
      sb.append(amount).append(suffix);
      termCount[0]++;
    }
    return termCount[0] >= maxTerms;
  }

  // Appends seconds in either fractional (to three decimals) or whole-second form. Fractional
  // seconds are used only when at least two term slots remain, aligning with historical UI
  // expectations about detail level controlled by maxTerms.
  private static void appendSeconds(
      StringBuilder sb,
      long millis,
      boolean withSecondFractions,
      int maxTerms,
      int[] termCount,
      boolean extraOneMs) {
    if (termCount[0] >= maxTerms) return;
    if (withSecondFractions && ((maxTerms - termCount[0]) >= 2)) {
      if (millis > 0) {
        long adjusted = extraOneMs ? millis + 1 : millis;
        double fractionalSeconds = adjusted / 1000.0;
        sb.append(String.format(Locale.ROOT, "%.3f", fractionalSeconds)).append('s');
      }
    } else {
      long adjusted = extraOneMs ? millis + 1 : millis;
      long seconds = SECONDS.convert(adjusted, MILLISECONDS);
      if (seconds > 0) {
        sb.append(seconds).append('s');
      }
    }
  }

  /**
   * Formats a duration using two units without fractional seconds.
   *
   * <p>This is equivalent to calling {@link #formatTime(long, int, boolean)
   * formatTime(timeInterval, 2, false)}.
   *
   * @param timeInterval duration to format, in milliseconds
   * @return the formatted string
   */
  public static String formatTime(long timeInterval) {
    return formatTime(timeInterval, 2, false);
  }

  /**
   * Formats a duration using up to {@code maxTerms} units without fractional seconds.
   *
   * <p>This is equivalent to calling {@link #formatTime(long, int, boolean)
   * formatTime(timeInterval, maxTerms, false)}.
   *
   * @param timeInterval duration to format, in milliseconds
   * @param maxTerms maximum number of units to include; intended range is {@code 1..6}
   * @return the formatted string
   * @throws IllegalArgumentException if {@code maxTerms > 6}
   */
  public static String formatTime(long timeInterval, int maxTerms) {
    return formatTime(timeInterval, maxTerms, false);
  }

  /**
   * Parses a human-friendly interval string into milliseconds.
   *
   * <p>The input consists of an optional leading {@code -} followed by any combination of
   * unit-bearing fields in decreasing order: weeks ({@code w}), days ({@code d}), hours ({@code
   * h}), minutes ({@code m}), and seconds ({@code s}) with an optional fractional part (e.g.,
   * {@code 1.250s}). All fields are optional, but at least one must be present. Examples:
   *
   * <ul>
   *   <li>{@code 2h30m}
   *   <li>{@code 45s}
   *   <li>{@code 1.5s}
   *   <li>{@code -3m}
   *   <li>{@code 1w2d3h4m5.678s}
   * </ul>
   *
   * <p>Fractional seconds are converted to milliseconds with truncation (no rounding). On overflow,
   * the result saturates to {@link Long#MAX_VALUE} (for positive inputs) or {@link Long#MIN_VALUE}
   * (for negative inputs).
   *
   * @param timeInterval the interval string to parse; must match the grammar described above with
   *     no leading/trailing whitespace
   * @return the duration in milliseconds
   * @throws NumberFormatException if the string does not match the expected format
   */
  public static long toMillis(String timeInterval) {
    Matcher matcher = TIME_INTERVAL_PATTERN.matcher(timeInterval);
    if (!matcher.matches()) {
      throw new NumberFormatException("Unknown format: " + timeInterval);
    }

    String group;
    boolean negative = timeInterval.startsWith("-");

    // Use BigInteger to safely accumulate and saturate at bounds
    BigInteger total = BigInteger.ZERO;

    if ((group = matcher.group(1)) != null) { // weeks
      total = total.add(safeMul(group, 604_800_000L));
    }
    if ((group = matcher.group(2)) != null) { // days
      total = total.add(safeMul(group, 86_400_000L));
    }
    if ((group = matcher.group(3)) != null) { // hours
      total = total.add(safeMul(group, 3_600_000L));
    }
    if ((group = matcher.group(4)) != null) { // minutes
      total = total.add(safeMul(group, 60_000L));
    }
    if ((group = matcher.group(5)) != null) { // seconds
      total = total.add(safeMul(group, 1_000L));
    }
    if ((group = matcher.group(6)) != null) { // fractional seconds (e.g., ".250")
      long fracMillis = (long) (Double.parseDouble(group) * 1000);
      if (fracMillis != 0L) {
        total = total.add(BigInteger.valueOf(fracMillis));
      }
    }

    if (!negative) {
      BigInteger max = BigInteger.valueOf(Long.MAX_VALUE);
      if (total.compareTo(max) > 0) return Long.MAX_VALUE;
      return total.longValue();
    } else {
      // For negatives, allow magnitude up to (Long.MAX_VALUE + 1) and then saturate to MIN_VALUE
      BigInteger minMagnitude = BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE);
      if (total.compareTo(minMagnitude) > 0) return Long.MIN_VALUE;
      return -total.longValue();
    }
  }

  // Multiplies a decimal string by a constant using BigInteger to avoid overflow during
  // accumulation.
  private static BigInteger safeMul(String number, long factor) {
    BigInteger n = new BigInteger(number);
    return n.multiply(BigInteger.valueOf(factor));
  }

  /**
   * Formats an instant as an RFC&nbsp;1123 date string in UTC for HTTP headers.
   *
   * <p>The output matches {@link DateTimeFormatter#RFC_1123_DATE_TIME}, for example: {@code Wed, 21
   * Oct 2015 07:28:00 GMT}.
   *
   * @param time milliseconds since the Unix epoch (1970-01-01T00:00:00Z)
   * @return the RFC&nbsp;1123-formatted date string
   */
  public static String makeHTTPDate(long time) {
    return DateTimeFormatter.RFC_1123_DATE_TIME.format(
        Instant.ofEpochMilli(time).atOffset(ZoneOffset.UTC));
  }

  /**
   * Truncates a date to the start of its UTC day.
   *
   * <p>Returns a new {@link Instant} representing the same instant rounded down to {@code
   * 00:00:00.000} in UTC for that day.
   *
   * @param instant the input instant, not {@code null}
   * @return a new {@link Instant} aligned to the UTC day boundary
   * @throws NullPointerException if {@code instant} is {@code null}
   */
  public static Instant setTimeToZero(final Instant instant) {
    return instant.truncatedTo(ChronoUnit.DAYS);
  }
}
