package network.crypta.support.http;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Parses HTTP date strings using the RFC 7231/RFC 1123 wire format.
 *
 * <p>The HTTP stack needs a single place that understands the canonical {@code GMT} timestamp
 * format used by response headers such as {@code Last-Modified} and {@code Expires}. This helper
 * keeps that parsing logic neutral so filters and HTTP compatibility facades can share the same
 * behavior without importing each other.
 *
 * <p>The implementation creates a new {@link SimpleDateFormat} for each invocation. That keeps the
 * API thread-safe without extra synchronization while preserving the exact legacy parsing pattern
 * and locale expectations.
 */
public final class HttpDateParser {

  private static final TimeZone UTC_TIME_ZONE = TimeZone.getTimeZone("UTC");

  private HttpDateParser() {}

  /**
   * Parses an RFC 7231/RFC 1123 HTTP date string in the {@code GMT} time zone.
   *
   * <p>Callers should use this for header values that must follow the standard HTTP wire format.
   * The parser is strict with respect to the expected layout and locale and therefore rejects
   * malformed or non-HTTP date strings instead of attempting heuristic recovery.
   *
   * @param httpDate Header value to parse, typically from an HTTP date-bearing field.
   * @return Parsed {@link Date} representing the supplied timestamp in UTC/GMT.
   * @throws ParseException if the input does not match the expected HTTP date format.
   */
  public static Date parseHTTPDate(String httpDate) throws ParseException {
    SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
    sdf.setTimeZone(UTC_TIME_ZONE);
    return sdf.parse(httpDate);
  }
}
