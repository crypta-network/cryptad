package network.crypta.config;

import java.util.Locale;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.Fields;
import network.crypta.support.TimeUtil;

/**
 * Config-local helpers for parsing and formatting dimension-aware integer values.
 *
 * <p>This helper keeps the configuration-specific parts of numeric parsing inside the config leaf
 * after {@link Fields} moved to {@code :foundation-support}. It handles only the behaviors that
 * still depend on configuration concepts such as {@link Dimension} and localized UI text from
 * {@link NodeL10n}. Generic size parsing, compact numeric formatting, and duration conversion are
 * still delegated to shared support utilities.
 *
 * <p>Typical callers are option types that need to accept user-facing values such as bandwidth
 * limits or durations while preserving the historical persistence format used by configuration
 * files. The class is intentionally package-private and stateless so that config parsing policy
 * stays explicit, easy to audit, and physically owned by {@code :foundation-config}.
 */
final class DimensionValueSupport {

  /** NodeL10n key for the localized "per second" suffix used by the first-time wizard. */
  private static final String BANDWIDTH_PER_SECOND_KEY =
      "FirstTimeWizardToadlet.bandwidthPerSecond";

  /** Not instantiable; this type exposes only stateless helper methods. */
  private DimensionValueSupport() {}

  /**
   * Removes an optional per-second qualifier from a bandwidth expression.
   *
   * <p>Examples of removed suffixes: {@code "/s"}, {@code "/sec"}, {@code "/second"}, {@code "ps"},
   * and the localized wizard suffix.
   *
   * @param value input limit expression.
   * @return {@code value} without the per-second suffix.
   */
  static String trimPerSecond(String value) {
    String trimmed = value.trim();
    if (trimmed.isEmpty()) {
      return "";
    }

    String lower = trimmed.toLowerCase(Locale.ROOT);
    for (String suffix :
        new String[] {
          "/s",
          "/sec",
          "/second",
          "ps",
          NodeL10n.getBase().getString(BANDWIDTH_PER_SECOND_KEY).toLowerCase(Locale.ROOT)
        }) {
      if (lower.endsWith(suffix)) {
        return trimmed.substring(0, trimmed.length() - suffix.length());
      }
    }
    return trimmed;
  }

  /**
   * Parses an integer according to a {@link Dimension}.
   *
   * @param value input string.
   * @param dimension interpretation of the value.
   * @return parsed integer.
   * @throws NumberFormatException if parsing fails.
   * @throws ArithmeticException if a duration does not fit in an {@code int}.
   */
  static int parseInt(String value, Dimension dimension) {
    return switch (dimension) {
      case NOT, SIZE -> Fields.parseInt(value);
      case DURATION -> parseDurationMillis(value);
    };
  }

  /**
   * Formats an integer according to a {@link Dimension}.
   *
   * @param value value to format.
   * @param dimension interpretation of the value.
   * @return formatted string.
   */
  static String intToString(int value, Dimension dimension) {
    return switch (dimension) {
      case NOT -> Fields.intToString(value, false);
      case SIZE -> Fields.intToString(value, true);
      case DURATION -> TimeUtil.formatTime(value, 6, false);
    };
  }

  /**
   * Parses a duration string and verifies that the millisecond result fits in a signed int.
   *
   * @param value duration expression accepted by {@link TimeUtil#toMillis(String)}.
   * @return parsed duration in milliseconds, narrowed to {@code int}.
   * @throws NumberFormatException if {@code value} is not a valid duration expression.
   * @throws ArithmeticException if the parsed millisecond count exceeds the {@code int} range.
   */
  private static int parseDurationMillis(String value) {
    long durationInMillis = TimeUtil.toMillis(value);
    if ((int) durationInMillis == durationInMillis) {
      return (int) durationInMillis;
    }
    throw new ArithmeticException("integer overflow");
  }
}
