package network.crypta.support;

/**
 * Utility for formatting byte counts into human‑readable strings using IEC (base‑1024) binary
 * prefixes.
 *
 * <p>The formatter produces a mantissa and a unit (e.g., {@code 1.25 KiB}, {@code 1023 B}). It is
 * locale‑independent: the decimal separator is always {@code '.'}, and unit labels are English
 * strings. Negative inputs are supported and yield a negative mantissa (e.g., {@code -1.5 KiB}).
 *
 * <p>Mantissas are trimmed rather than rounded to keep readability consistent:
 *
 * <ul>
 *   <li>For values with three digits before the decimal point, the decimal part is dropped (e.g.,
 *       {@code 100 KiB}).
 *   <li>Otherwise, the textual form is truncated to at most four characters, preserving useful
 *       precision (e.g., {@code 12.3 MiB}, {@code 1.25 GiB}).
 * </ul>
 *
 * <p>Thread safety: the class is stateless and all methods are {@code static}; it is safe to call
 * concurrently.
 *
 * <p>Complexity: all operations are constant time, aside from negligible string allocations.
 */
public class SizeUtil {
  // IEC unit suffixes in ascending order. The array is private by design; callers should use the
  // formatting methods rather than relying on unit constants directly.
  private static final String[] SUFFIXES =
      new String[] {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"};

  private SizeUtil() {}

  /**
   * Formats a byte count using IEC units with a regular breaking space between mantissa and unit.
   *
   * <p>Examples: {@code 1024 -> "1.0 KiB"}, {@code 100*1024 -> "100 KiB"}, {@code -1536 -> "-1.5
   * KiB"}.
   *
   * @param bytes the number of bytes; may be negative
   * @return a human‑readable string such as {@code "1.25 GiB"} or {@code "1023 B"}
   */
  public static String formatSize(long bytes) {
    return formatSize(bytes, false);
  }

  /**
   * Formats a byte count using IEC units with no separator between mantissa and unit.
   *
   * <p>Intended for compact displays or contexts where spaces are undesirable.
   *
   * @param bytes the number of bytes; may be negative
   * @return a string such as {@code "1.0KiB"} or {@code "1023B"}
   */
  public static String formatSizeWithoutSpace(long bytes) {
    String[] result = formatSizeParts(bytes);
    return result[0].concat(result[1]);
  }

  /**
   * Formats a byte count using IEC units with either a regular space or a non‑breaking space
   * (U+00A0) between mantissa and unit.
   *
   * @param bytes the number of bytes; may be negative
   * @param useNonBreakingSpace when {@code true}, inserts {@code '\u00A0'} instead of a regular
   *     space to prevent unwanted line breaks
   * @return a human‑readable string such as {@code "1.25 GiB"} or {@code "1.0\u00A0KiB"}
   */
  public static String formatSize(long bytes, boolean useNonBreakingSpace) {
    String[] result = formatSizeParts(bytes);
    return result[0].concat((useNonBreakingSpace ? "\u00a0" : " ")).concat(result[1]);
  }

  /**
   * Computes the formatted size as two parts: mantissa and unit.
   *
   * <p>The returned array has exactly two elements: index {@code 0} is the mantissa (possibly with
   * a leading {@code -}), and index {@code 1} is the unit string (one of {@code B}, {@code KiB},
   * {@code MiB}, {@code GiB}, {@code TiB}, {@code PiB}, {@code EiB}, {@code ZiB}, {@code YiB}). For
   * extremely large values beyond the available suffixes, the unit element is the empty string.
   *
   * <p>Notes:
   *
   * <ul>
   *   <li>The decimal separator in the mantissa is always {@code '.'} and is not locale‑aware.
   *   <li>The mantissa is trimmed (not rounded) to keep at most three significant digits; examples
   *       include {@code 1.25}, {@code 12.3}, and {@code 123}.
   *   <li>Given 64‑bit {@code long} inputs, practical units top out at {@code EiB}; labels for
   *       larger units are present for completeness.
   * </ul>
   *
   * @param bytes the number of bytes; may be negative
   * @return a two‑element array {@code [mantissa, unit]}
   */
  public static String[] formatSizeParts(long bytes) {
    long s = 1;
    int i = 0;
    boolean negative = bytes < 0;
    if (negative) {
      bytes *= -1;
    }

    // Increase the scale by powers of 1024 while the next unit would not overflow and would
    // still be less than or equal to the value to format. This chooses the largest unit that does
    // not exceed the magnitude of 'bytes'.
    while (i < SUFFIXES.length && s <= Long.MAX_VALUE / 1024 && s * 1024 <= bytes) {
      s *= 1024;
      i++;
    }

    // For byte values (no scaling), return an integral mantissa without a decimal part.
    if (s == 1) {
      return new String[] {(negative ? "-" : "") + bytes, SUFFIXES[0]};
    }

    double mantissa = (double) bytes / (double) s;
    String o = trimMantissa(String.valueOf(mantissa));
    if (negative) {
      o = "-" + o;
    }
    // Guard against out-of-range unit indices (e.g., inputs beyond the largest supported unit).
    if (i < SUFFIXES.length) {
      return new String[] {o, SUFFIXES[i]};
    } else {
      // If values exceed all suffixes or the mantissa becomes non-finite, return an empty unit.
      return new String[] {o, ""};
    }
  }

  /**
   * Trims the textual mantissa produced by {@link String#valueOf(double)} to keep output readable
   * and stable. Rules are chosen to yield at most three significant digits overall while avoiding
   * scientific notation for common ranges.
   */
  private static String trimMantissa(String s) {
    int dot = s.indexOf('.');
    if (dot == 3) {
      return s.substring(0, 3);
    }
    if (dot > -1 && s.indexOf('E') == -1 && s.length() > 4) {
      return s.substring(0, 4);
    }
    return s;
  }
}
