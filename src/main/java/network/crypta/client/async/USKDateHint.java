package network.crypta.client.async;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.TemporalField;
import java.time.temporal.WeekFields;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableUSK;
import network.crypta.keys.USK;

/**
 * Builds and describes date-based edition "hints" for updatable SSK/USK keys.
 *
 * <p>This helper encapsulates the logic used by the client to derive readable, stable suffixes that
 * encode a point in time at different granularities (year, month, day, and a week representation).
 * These suffixes are embedded into document names and small hint payloads so that producers and
 * consumers can rendezvous on likely editions without scanning the entire namespace.
 *
 * <p>Instances are immutable and thread-safe. Each instance is bound to a UTC {@link
 * java.time.LocalDate} captured at construction. Typical usage is to obtain a hint anchored to
 * "today" in UTC via {@link #now()} and then render one or more representations via {@link
 * #get(Type)} or the compact wire format via {@link #getData(long)}. Consumers such as the USK
 * fetcher use these forms to schedule and interpret background requests.
 *
 * <ul>
 *   <li><strong>Responsibilities</strong>: provide date-derived suffixes and a minimal wire payload
 *       that carries a suggested edition and the most precise date form.
 *   <li><strong>Precision</strong>: {@link Type#DAY} is strictly more precise than other types;
 *       {@link Type#MONTH} and {@link Type#WEEK} are not strictly ordered, but both are more
 *       precise than {@link Type#YEAR}.
 *   <li><strong>Newline policy</strong>: the {@linkplain #getData(long) payload} uses LF-only
 *       ("\n") line endings, regardless of platform, because it is a cross-platform wire format.
 * </ul>
 */
public class USKDateHint {

  /**
   * Precision levels available when rendering a date.
   *
   * <p>The values express an ordering used by scheduling logic. See {@link
   * #alwaysMorePreciseThan(Type)} for details on how one value compares to another for precision.
   */
  public enum Type {
    /** Year-only precision, for example {@code 2023}. Lowest precision. */
    YEAR,
    /** Month precision using a zero-indexed month, for example {@code 2023-5} for June. */
    MONTH,
    /** Day precision, for example {@code 2023-5-1} for 2023-06-01. Highest non-week precision. */
    DAY,
    /** Week-based year and week of year, for example {@code 2023-WEEK-1}. */
    WEEK;

    /**
     * Report whether this precision is strictly more precise than another.
     *
     * <p>The ordering reflects scheduling semantics: {@link #DAY} is more precise than all other
     * types. {@link #MONTH} and {@link #WEEK} are each strictly more precise than {@link #YEAR} but
     * are not strictly ordered relative to one another because weeks and months cross boundaries
     * differently. {@link #YEAR} is never strictly more precise.
     *
     * @param type the other precision to compare against; may be {@code null}, which is treated as
     *     unspecified and therefore not strictly less precise than any value.
     * @return {@code true} if this value is strictly more precise than {@code type}; otherwise
     *     {@code false}.
     */
    public boolean alwaysMorePreciseThan(Type type) {
      if (this.equals(type)) return false;
      if (this.equals(DAY)) { // Day beats everything.
        return true;
      } else if (this.equals(
          MONTH)) { // Month and week don't beat each other as they sometimes overlap.
        return type.equals(YEAR);
      } else if (this.equals(WEEK)) {
        return type.equals(YEAR);
      } else { // YEAR: everything else is more precise
        return false;
      }
    }
  }

  private static final TemporalField WEEK_OF_YEAR = WeekFields.of(Locale.US).weekOfWeekBasedYear();
  private static final TemporalField WEEK_YEAR = WeekFields.of(Locale.US).weekBasedYear();

  private final LocalDate dateUtc;

  USKDateHint(LocalDate dateUtc) {
    this.dateUtc = dateUtc;
  }

  /**
   * Create a new hint instance anchored to the current date in UTC.
   *
   * <p>The resulting object is immutable. All derived strings are computed from the captured date
   * and do not change after creation.
   *
   * <pre>{@code
   * USKDateHint hint = USKDateHint.now();
   * String day = hint.get(USKDateHint.Type.DAY);
   * }</pre>
   *
   * @return a new {@code USKDateHint} bound to "today" in UTC.
   */
  public static USKDateHint now() {
    return new USKDateHint(LocalDate.now(ZoneOffset.UTC));
  }

  /**
   * Render the date using the requested precision.
   *
   * <p>For {@link Type#WEEK}, the result is the week-based year and week-of-year encoded as {@code
   * <year>-WEEK-<week>}, using US week fields (weeks start on Sunday). For the other values, the
   * format is {@code <year>[-<zeroIndexedMonth>[-<day>]]} where the month is zero-indexed to
   * preserve historical behavior. When {@code type} is {@code null}, the method behaves like
   * requesting the most precise non-week form and returns the day string.
   *
   * @param type desired precision; may be {@code null} to request the day form.
   * @return a non-empty string encoding the date at the requested precision; never {@code null}.
   */
  public String get(Type type) {
    if (type == Type.WEEK) {
      return dateUtc.get(WEEK_YEAR) + "-WEEK-" + dateUtc.get(WEEK_OF_YEAR);
    }

    StringBuilder sb = new StringBuilder();
    sb.append(dateUtc.getYear());
    if (type == Type.YEAR) {
      return sb.toString();
    }

    sb.append('-');
    sb.append(dateUtc.getMonthValue() - 1); // zero-indexed month
    if (type == Type.MONTH) {
      return sb.toString();
    }

    sb.append('-');
    sb.append(dateUtc.getDayOfMonth());
    return sb.toString();
  }

  /**
   * Build the compact wire-format payload for a hint insertion.
   *
   * <p>The payload consists of three LF-terminated lines using UTF-8 content: a literal {@code
   * HINT}, the decimal edition number, and the {@link #get(Type) day} representation of the date.
   * Newlines are always LF ("\n"), regardless of the host platform, so the payload is portable and
   * consistently parsed by all nodes.
   *
   * <pre>{@code
   * String data = USKDateHint.now().getData(12345);
   * // HINT\n12345\nYYYY-M-D\n
   * }</pre>
   *
   * @param edition the suggested absolute edition number to advertise; non-negative values are
   *     expected by consumers.
   * @return a three-line LF-terminated string suitable for insertion and remote parsing.
   */
  @SuppressWarnings("java:S3457")
  public String getData(long edition) {
    return "HINT\n%d\n%s\n".formatted(edition, get(Type.DAY));
  }

  /**
   * Compute insert-capable SSK URIs for each precision variant.
   *
   * <p>The returned array contains four entries in the {@link Type#values()} order (year, month,
   * day, week). Each URI refers to a document name suffixed with {@code -DATEHINT-<suffix>}, where
   * {@code <suffix>} is the string produced by {@link #get(Type)} for the corresponding precision.
   *
   * @param key the insertable USK used to derive per-precision SSK insert URIs; must not be {@code
   *     null}.
   * @return a new array of length four containing insert URIs in deterministic order.
   */
  public FreenetURI[] getInsertURIs(InsertableUSK key) {
    return Arrays.stream(Type.values())
        .map(type -> key.getInsertableSSK(getDocName(key, type)).getInsertURI())
        .toArray(FreenetURI[]::new);
  }

  /**
   * Compute request-capable SSK URIs for each precision variant.
   *
   * <p>The returned array contains four entries in the {@link Type#values()} order (year, month,
   * day, week). Each entry targets the corresponding document name suffixed with {@code
   * -DATEHINT-<suffix>}.
   *
   * @param key the USK used to derive per-precision SSK request URIs; must not be {@code null}.
   * @return a new array of length four containing request URIs in deterministic order.
   */
  public ClientSSK[] getRequestURIs(USK key) {
    return Arrays.stream(Type.values())
        .map(type -> key.getSSK(getDocName(key, type)))
        .toArray(ClientSSK[]::new);
  }

  /**
   * Compute request-capable SSK URIs for each precision variant keyed by {@link Type}.
   *
   * <p>The returned map preserves {@link Type#values()} order via {@link EnumMap} and provides a
   * direct association between precision levels and their corresponding request URIs.
   *
   * @param key the USK used to derive per-precision SSK request URIs; must not be {@code null}.
   * @return a map of precision types to request URIs, never {@code null}.
   */
  public Map<Type, ClientSSK> getRequestURIsByType(USK key) {
    EnumMap<Type, ClientSSK> result = new EnumMap<>(Type.class);
    for (Type type : Type.values()) {
      result.put(type, key.getSSK(getDocName(key, type)));
    }
    return result;
  }

  private String getDocName(USK key, Type type) {
    return "%s-DATEHINT-%s".formatted(key.siteName, get(type));
  }
}
