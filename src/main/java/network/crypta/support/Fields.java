package network.crypta.support;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Comparator;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.StringTokenizer;
import network.crypta.config.Dimension;
import network.crypta.l10n.NodeL10n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility methods for parsing and formatting primitive values and arrays.
 *
 * <p>Fields centralizes frequently used helpers for:
 *
 * <ul>
 *   <li>Parsing booleans from common textual representations.
 *   <li>Parsing and formatting numbers and size-like quantities (SI/IEC suffixes).
 *   <li>Converting between byte arrays and primitive types.
 *   <li>Comparing byte arrays and primitive values with well-defined semantics.
 *   <li>Parsing and formatting date/time strings used by the node.
 * </ul>
 *
 * <p>Unless otherwise noted, methods do not accept {@code null} parameters and throw standard
 * exceptions if input is malformed. All operations are thread-safe and have no global side effects
 * beyond logging.
 *
 * @author oskar
 */
public abstract class Fields {
  private static final Logger LOG = LoggerFactory.getLogger(Fields.class);

  private Fields() {}

  // Common boolean string literals used across methods
  private static final String TRUE_LITERAL = "true";
  private static final String FALSE_LITERAL = "false";
  private static final String YES_LITERAL = "yes";
  private static final String NO_LITERAL = "no";

  /**
   * Digit table for nibble-to-hex conversion used by {@link #numberList(long[])}. Only indices
   * {@code 0..15} are read.
   */
  private static final char[] digits = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
  };

  private static final long[] MULTIPLES = {
    1000,
    1L << 10,
    1000 * 1000,
    1L << 20,
    1000L * 1000L * 1000L,
    1L << 30,
    1000L * 1000L * 1000L * 1000L,
    1L << 40,
    1000L * 1000L * 1000L * 1000L * 1000,
    1L << 50,
    1000L * 1000L * 1000L * 1000L * 1000L * 1000L,
    1L << 60
  };
  private static final String[] MULTIPLES_2 = {
    "k", "K", "m", "M", "g", "G", "t", "T", "p", "P", "e", "E"
  };

  private static final DateTimeFormatter SEC_TO_DATE_TIME_FORMATTER =
      DateTimeFormatter.ofPattern("yyyyMMdd-HH:mm:ss").withZone(ZoneOffset.UTC);

  // IEC size suffix helpers are implemented without a regex to avoid ReDoS risks.

  /**
   * Parses a hexadecimal string into a {@code long} using two's-complement semantics.
   *
   * <p>Unlike {@link Long#parseLong(String, int)}, this method does not interpret a leading minus
   * sign; instead it treats the sequence of hex digits as a two's-complement representation. This
   * allows round-tripping values produced by {@link Long#toHexString(long)}.
   *
   * @param hex lower- or upper-case hex digits, up to 16 characters.
   * @return the parsed {@code long} value.
   * @throws NumberFormatException if length &gt; 16 or a non-hex character is present.
   */
  public static long hexToLong(String hex) throws NumberFormatException {
    int len = hex.length();
    if (len > 16) {
      throw new NumberFormatException();
    }

    long l = 0;
    for (int i = 0; i < len; i++) {
      l <<= 4;
      int c = Character.digit(hex.charAt(i), 16);
      if (c < 0) {
        throw new NumberFormatException();
      }
      l |= c;
    }
    return l;
  }

  /**
   * Parses a hexadecimal string into an {@code int} using two's-complement semantics.
   *
   * <p>See {@link #hexToLong(String)} for a detailed rationale; the behavior is analogous but with
   * an {@code int} result.
   *
   * @param hex lower- or upper-case hex digits, up to 16 characters.
   * @return the parsed {@code int} value.
   * @throws NumberFormatException if length &gt; 16 or a non-hex character is present.
   */
  public static int hexToInt(String hex) throws NumberFormatException {
    int len = hex.length();
    if (len > 16) {
      throw new NumberFormatException();
    }

    int l = 0;
    for (int i = 0; i < len; i++) {
      l <<= 4;
      int c = Character.digit(hex.charAt(i), 16);
      if (c < 0) {
        throw new NumberFormatException();
      }
      l |= c;
    }
    return l;
  }

  /**
   * Parses a boolean from a string, returning a fallback when the value is unclear.
   *
   * <p>If {@code def} is {@code true}, only a case-insensitive {@code "false"} disables it. If
   * {@code def} is {@code false}, only {@code "true"} enables it. Any other input yields the
   * default.
   *
   * @param s source string; may be {@code null}.
   * @param def default value used when the string does not explicitly specify the opposite.
   * @return parsed value or {@code def} when uncertain.
   */
  /* woo, rocket science! (this is purely abstraction people) */
  public static boolean stringToBool(String s, boolean def) {
    if (s == null) {
      return def;
    }
    return (def ? !s.equalsIgnoreCase(FALSE_LITERAL) : s.equalsIgnoreCase(TRUE_LITERAL));
  }

  /**
   * Parses a boolean from a string and fails fast on unknown values.
   *
   * <p>Accepts case-insensitive {@code "true"}/{@code "yes"} and {@code "false"}/{@code "no"}.
   *
   * @param s source string; must not be {@code null}.
   * @return the parsed boolean.
   * @throws NumberFormatException if {@code s} is {@code null} or not one of the accepted tokens.
   */
  public static boolean stringToBool(String s) throws NumberFormatException {
    if (s == null) {
      throw new NumberFormatException("Null");
    }
    if (s.equalsIgnoreCase(FALSE_LITERAL) || s.equalsIgnoreCase(NO_LITERAL)) {
      return false;
    }
    if (s.equalsIgnoreCase(TRUE_LITERAL) || s.equalsIgnoreCase(YES_LITERAL)) {
      return true;
    }
    throw new NumberFormatException("Invalid boolean: " + s);
  }

  /**
   * Converts a boolean to the lowercase tokens {@code "true"} or {@code "false"}.
   *
   * @param b input value.
   * @return {@code "true"} when {@code b} is {@code true}; otherwise {@code "false"}.
   */
  public static String boolToString(boolean b) {
    return b ? TRUE_LITERAL : FALSE_LITERAL;
  }

  /**
   * Splits a comma-separated list into trimmed elements.
   *
   * @param ls input string; may be {@code null}.
   * @return a new array of trimmed tokens, or an empty array when {@code ls} is {@code null}.
   */
  public static String[] commaList(String ls) {
    if (ls == null) {
      return new String[0];
    }
    StringTokenizer st = new StringTokenizer(ls, ",");
    String[] r = new String[st.countTokens()];
    for (int i = 0; i < r.length; i++) {
      r[i] = st.nextToken().trim();
    }
    return r;
  }

  /**
   * Joins strings with a comma delimiter.
   *
   * @param ls elements to join; never {@code null}.
   * @return a comma-separated string, or an empty string when {@code ls} is empty.
   */
  public static String commaList(String[] ls) {
    return textList(ls, ',');
  }

  /**
   * Joins strings with an arbitrary single-character delimiter.
   *
   * @param ls elements to join; never {@code null}.
   * @param ch delimiter to insert between elements.
   * @return joined text, or an empty string when {@code ls} is empty.
   */
  public static String textList(String[] ls, char ch) {
    if (ls.length == 0) {
      return "";
    }
    StringBuilder sb = new StringBuilder();
    for (String s : ls) {
      sb.append(s);
      sb.append(ch);
    }
    // assert(sb.length() > 0); -- always true as ls.length != 0
    // remove last ch
    sb.deleteCharAt(sb.length() - 1);
    return sb.toString();
  }

  /**
   * Parses a comma-separated list of hexadecimal numbers into a {@code long[]}.
   *
   * @param ls input list using {@code ,} as separator; tokens are hex without {@code 0x}.
   * @return array of values in the order encountered.
   * @throws NumberFormatException if any token is not valid hex.
   */
  public static long[] numberList(String ls) throws NumberFormatException {
    StringTokenizer st = new StringTokenizer(ls, ",");
    long[] r = new long[st.countTokens()];
    for (int i = 0; i < r.length; i++) {
      r[i] = hexToLong(st.nextToken());
    }
    return r;
  }

  /**
   * Formats a {@code long[]} as a comma-separated sequence of lowercase hex numbers.
   *
   * @param ls source values.
   * @return comma-separated hex representation; empty when {@code ls} is empty.
   */
  public static String numberList(long[] ls) {
    if (ls.length == 0) {
      return "";
    }
    char[] numberBuf = new char[64];
    StringBuilder listBuf = new StringBuilder(ls.length * 18);
    for (long l : ls) {
      // Convert the number into a string in a fixed size buffer.
      int charPos = 64;
      do {
        numberBuf[--charPos] = digits[(int) (l & 0x0F)];
        l >>>= 4;
      } while (l != 0);

      listBuf.append(numberBuf, charPos, (64 - charPos));
      listBuf.append(',');
    }
    // assert(listBuf.length() > 0); -- always true as ls.length != 0
    // remove last comma
    listBuf.deleteCharAt(listBuf.length() - 1);
    return listBuf.toString();
  }

  /**
   * Parses a timestamp string into milliseconds since the epoch.
   *
   * <p>Supported forms:
   *
   * <ul>
   *   <li>{@code YYYYMMDD-HH:MM:SS} (24-hour clock) or {@code YYYYMMDD} (midnight assumed).
   *   <li>Relative deltas: {@code [+|-]<n><unit>} where unit is one of {@code y|year}, {@code
   *       month|mo}, {@code week|w}, {@code day|d}, {@code hour|h}, {@code minute|min}, {@code
   *       second|s|sec}. When the unit is omitted, days are assumed. The system default {@link
   *       TimeZone} applies.
   * </ul>
   *
   * @param date absolute or relative expression.
   * @return epoch milliseconds.
   * @throws NumberFormatException if the format is invalid or fields are out of range.
   */
  public static long dateTime(String date) throws NumberFormatException {
    if (date.isEmpty()) {
      throw new NumberFormatException("Date time empty");
    }
    if (date.charAt(0) == '-' || date.charAt(0) == '+') {
      // Preserve original semantics including fallback behavior when no unit is provided.
      return parseRelativeDateTimeWithOriginalFallback(date);
    }
    return parseAbsoluteDateTime(date);
  }

  private static long parseRelativeDateTimeWithOriginalFallback(String date) {
    StringBuilder sb = new StringBuilder(10);
    for (int x = 1; x < date.length(); x++) {
      char c = date.charAt(x);
      if (Character.isDigit(c)) {
        sb.append(c);
      } else {
        break;
      }
    }
    int num = Integer.parseInt(sb.toString());
    int chop = 1 + sb.length();
    int amount = (date.charAt(0) == '+') ? num : -num;
    GregorianCalendar gc = new GregorianCalendar();
    if (date.length() == chop) {
      // Preserve historical behavior: default to days when the unit is omitted.
      gc.add(Calendar.DAY_OF_YEAR, amount);
    } else {
      String deltaTypeString = date.substring(chop).toLowerCase();
      addDelta(gc, deltaTypeString, amount);
    }
    return gc.getTime().getTime();
  }

  private static void addDelta(GregorianCalendar gc, String deltaTypeString, int amount) {
    switch (deltaTypeString) {
      case "y", "year" -> gc.add(Calendar.YEAR, amount);
      case "month", "mo" -> gc.add(Calendar.MONTH, amount);
      case "week", "w" -> gc.add(Calendar.WEEK_OF_YEAR, amount);
      case "day", "d" -> gc.add(Calendar.DAY_OF_YEAR, amount);
      case "hour", "h" -> gc.add(Calendar.HOUR, amount);
      case "minute", "min" -> gc.add(Calendar.MINUTE, amount);
      case "second", "s", "sec" -> gc.add(Calendar.SECOND, amount);
      default ->
          throw new NumberFormatException("unknown time/date delta type: " + deltaTypeString);
    }
  }

  private static long parseAbsoluteDateTime(String date) {
    int dash = date.indexOf('-');
    if (!((dash == -1) && (date.length() == 8)) && !((dash == 8) && (date.length() == 17))) {
      throw new NumberFormatException("Date time: " + date + " not correct.");
    }
    int year = Integer.parseInt(date.substring(0, 4));
    int month = Integer.parseInt(date.substring(4, 6));
    int day = Integer.parseInt(date.substring(6, 8));
    int hour = (dash == -1) ? 0 : Integer.parseInt(date.substring(9, 11));
    int minute = (dash == -1) ? 0 : Integer.parseInt(date.substring(12, 14));
    int second = (dash == -1) ? 0 : Integer.parseInt(date.substring(15, 17));
    try {
      return buildCalendarMillis(year, month, day, hour, minute, second);
    } catch (Exception e) {
      LOG.debug("Invalid date {}", date, e);
      NumberFormatException nfe = new NumberFormatException("Invalid date '" + date + "'");
      nfe.initCause(e);
      throw nfe;
    }
  }

  private static long buildCalendarMillis(
      int year, int month, int day, int hour, int minute, int second) {
    return switch (month) {
      case 1 ->
          new GregorianCalendar(year, Calendar.JANUARY, day, hour, minute, second)
              .getTime()
              .getTime();
      case 2 ->
          new GregorianCalendar(year, Calendar.FEBRUARY, day, hour, minute, second)
              .getTime()
              .getTime();
      case 3 ->
          new GregorianCalendar(year, Calendar.MARCH, day, hour, minute, second)
              .getTime()
              .getTime();
      case 4 ->
          new GregorianCalendar(year, Calendar.APRIL, day, hour, minute, second)
              .getTime()
              .getTime();
      case 5 ->
          new GregorianCalendar(year, Calendar.MAY, day, hour, minute, second).getTime().getTime();
      case 6 ->
          new GregorianCalendar(year, Calendar.JUNE, day, hour, minute, second).getTime().getTime();
      case 7 ->
          new GregorianCalendar(year, Calendar.JULY, day, hour, minute, second).getTime().getTime();
      case 8 ->
          new GregorianCalendar(year, Calendar.AUGUST, day, hour, minute, second)
              .getTime()
              .getTime();
      case 9 ->
          new GregorianCalendar(year, Calendar.SEPTEMBER, day, hour, minute, second)
              .getTime()
              .getTime();
      case 10 ->
          new GregorianCalendar(year, Calendar.OCTOBER, day, hour, minute, second)
              .getTime()
              .getTime();
      case 11 ->
          new GregorianCalendar(year, Calendar.NOVEMBER, day, hour, minute, second)
              .getTime()
              .getTime();
      case 12 ->
          new GregorianCalendar(year, Calendar.DECEMBER, day, hour, minute, second)
              .getTime()
              .getTime();
      default -> throw new NumberFormatException("Invalid month: " + month);
    };
  }

  /**
   * Formats seconds since the epoch as {@code yyyyMMdd[-HH:mm:ss]} in GMT.
   *
   * <p>If the time portion is zero, the {@code -HH:mm:ss} suffix is omitted.
   *
   * @param time seconds since 1970-01-01T00:00:00Z.
   * @return formatted timestamp in GMT.
   */
  public static String secToDateTime(long time) {
    String dateString = SEC_TO_DATE_TIME_FORMATTER.format(Instant.ofEpochSecond(time));

    if (dateString.endsWith("-00:00:00")) {
      dateString = dateString.substring(0, 8);
    }

    return dateString;
  }

  /**
   * Compares two byte arrays lexicographically using unsigned byte values.
   *
   * @param b1 first array.
   * @param b2 second array.
   * @return {@code -1}, {@code 0}, or {@code 1} if {@code b1} is less than, equal to, or greater
   *     than {@code b2}.
   */
  public static int compareBytes(byte[] b1, byte[] b2) {
    int len = Math.max(b1.length, b2.length);
    for (int i = 0; i < len; ++i) {
      if (i == b1.length) {
        return -1;
      } else if (i == b2.length) {
        return 1;
      } else if ((0xff & b1[i]) > (0xff & b2[i])) {
        return 1;
      } else if ((0xff & b1[i]) < (0xff & b2[i])) {
        return -1;
      }
    }
    return 0;
  }

  public static int compareBytes(byte[] a, byte[] b, int aoff, int boff, int len) {
    for (int i = 0; i < len; ++i) {
      if (i + aoff == a.length) {
        return i + boff == b.length ? 0 : -1;
      } else if (i + boff == b.length) {
        return 1;
      } else if ((0xff & a[i + aoff]) > (0xff & b[i + boff])) {
        return 1;
      } else if ((0xff & a[i + aoff]) < (0xff & b[i + boff])) {
        return -1;
      }
    }
    return 0;
  }

  /**
   * Tests arrays for byte-wise equality.
   *
   * @param a first array.
   * @param b second array.
   * @return {@code true} when equal length and all bytes match.
   */
  public static boolean byteArrayEqual(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    for (int i = 0; i < a.length; ++i) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * Tests ranges of arrays for byte-wise equality.
   *
   * @param a first array.
   * @param b second array.
   * @param aoff offset into {@code a}.
   * @param boff offset into {@code b}.
   * @param len number of bytes to compare.
   * @return {@code true} when both ranges exist and are equal.
   */
  public static boolean byteArrayEqual(byte[] a, byte[] b, int aoff, int boff, int len) {
    if ((a.length < aoff + len) || (b.length < boff + len)) {
      return false;
    }
    for (int i = 0; i < len; ++i) {
      if (a[i + aoff] != b[i + boff]) {
        return false;
      }
    }
    return true;
  }

  /** Comparator that delegates to {@link Fields#compareBytes(byte[], byte[])}. */
  public static final class ByteArrayComparator implements Comparator<byte[]> {

    @Override
    public int compare(byte[] o1, byte[] o2) {
      return compareBytes(o1, o2);
    }
  }

  // Future: If needed, add IntegerComparator/LongComparator.

  /**
   * Computes a simple XOR-shift-based hash for a byte array.
   *
   * @param b source array.
   * @return hash code suitable for evenly distributed random-like input.
   */
  public static int hashCode(byte[] b) {
    return hashCode(b, 0, b.length);
  }

  /**
   * Computes a simple XOR-shift-based hash for a byte range.
   *
   * @param b source array.
   * @param ptr start offset.
   * @param length number of bytes.
   * @return hash code.
   */
  public static int hashCode(byte[] b, int ptr, int length) {
    int h = 0;
    for (int i = length - 1; i >= 0; --i) {
      int x = b[ptr + i] & 0xff;
      h ^= x << ((i & 3) << 3);
    }
    return h;
  }

  /**
   * 64-bit variant of {@link #hashCode(byte[], int, int)}.
   *
   * <p>Not suitable for cryptographic purposes.
   */
  public static long longHashCode(byte[] b) {
    return longHashCode(b, 0, b.length);
  }

  /**
   * 64-bit variant of {@link #hashCode(byte[], int, int)} over a byte range.
   *
   * <p>Not suitable for cryptographic purposes.
   */
  public static long longHashCode(byte[] b, int offset, int length) {
    long h = 0;
    for (int i = length - 1; i >= 0; --i) {
      int x = b[i + offset] & 0xff;
      h ^= ((long) x) << ((i & 7) << 3);
    }
    return h;
  }

  /**
   * Joins objects with commas using {@link Object#toString()}.
   *
   * @param addr elements to join.
   * @return comma-separated string, or empty if {@code addr} is empty.
   */
  public static String commaList(Object[] addr) {
    return commaList(addr, ',');
  }

  /**
   * Joins objects with a custom delimiter using {@link Object#toString()}.
   *
   * @param addr elements to join.
   * @param comma delimiter to insert between elements.
   * @return joined string, or empty if {@code addr} is empty.
   */
  public static String commaList(Object[] addr, char comma) {
    if (addr.length == 0) {
      return "";
    }
    StringBuilder sb = new StringBuilder();
    for (Object a : addr) {
      sb.append(a);
      sb.append(comma);
    }
    // assert(sb.length() > 0); -- always true as addr.length != 0
    // remove last comma
    sb.deleteCharAt(sb.length() - 1);
    return sb.toString();
  }

  /**
   * Converts a {@code long[]} to a byte array in little-endian order (the least significant byte
   * first).
   *
   * @param longs source longs.
   * @return a new byte array of size {@code longs.length * 8}.
   */
  public static byte[] longsToBytes(long[] longs) {
    byte[] buf = new byte[longs.length * 8];
    for (int i = 0; i < longs.length; i++) {
      long x = longs[i];
      for (int j = 0; j < 8; j++) {
        buf[i * 8 + j] = (byte) x;
        x >>>= 8;
      }
    }
    return buf;
  }

  /**
   * Converts a byte array to a {@code long[]} in big-endian order.
   *
   * @param buf source bytes.
   * @return a new long array whose length is {@code buf.length / 8}.
   * @throws IllegalArgumentException if {@code buf.length} is not a multiple of 8.
   */
  public static long[] bytesToLongs(byte[] buf) {
    return bytesToLongs(buf, 0, buf.length);
  }

  /**
   * Converts a byte range to a {@code long[]} in big-endian order.
   *
   * @param buf source bytes.
   * @param offset start offset in {@code buf}.
   * @param length number of bytes to read; must be a multiple of 8.
   * @return a new long array of size {@code length / 8}.
   * @throws IllegalArgumentException if {@code length} is not a multiple of 8.
   */
  public static long[] bytesToLongs(byte[] buf, int offset, int length) {
    if (length % 8 != 0) {
      throw new IllegalArgumentException();
    }
    long[] longs = new long[length / 8];
    for (int i = 0; i < longs.length; i++) {
      long x = 0;
      for (int j = 7; j >= 0; j--) {
        long y = (buf[offset + i * 8 + j] & 0xff);
        x = (x << 8) | y;
      }
      longs[i] = x;
    }
    return longs;
  }

  /**
   * Converts 8 bytes starting at offset 0 to a {@code long} in big-endian order.
   *
   * @param buf source bytes; length must be at least 8.
   * @return the decoded {@code long}.
   * @throws IllegalArgumentException if fewer than 8 bytes are available.
   */
  public static long bytesToLong(byte[] buf) {
    return bytesToLong(buf, 0);
  }

  /**
   * Converts 8 bytes starting at {@code offset} to a {@code long} in big-endian order.
   *
   * @param buf source bytes.
   * @param offset starting index; must allow 8 readable bytes.
   * @return the decoded {@code long}.
   * @throws IllegalArgumentException if fewer than 8 bytes are available from {@code offset}.
   */
  public static long bytesToLong(byte[] buf, int offset) {
    if (buf.length < 8 + offset) {
      throw new IllegalArgumentException();
    }
    long x = 0;
    for (int j = 7; j >= 0; j--) {
      long y = (buf[j + offset] & 0xff);
      x = (x << 8) | y;
    }
    return x;
  }

  public static int bytesToInt(byte[] buf) {
    return bytesToInt(buf, 0);
  }

  /**
   * Converts 4 bytes starting at {@code offset} to an {@code int} in big-endian order.
   *
   * @param buf source bytes; length must be at least 4.
   * @param offset starting index.
   * @return the decoded {@code int}.
   * @throws IllegalArgumentException if fewer than 4 bytes are available.
   */
  public static int bytesToInt(byte[] buf, int offset) {
    if (buf.length < 4) {
      throw new IllegalArgumentException();
    }
    int x = 0;
    for (int j = 3; j >= 0; j--) {
      int y = (buf[j + offset] & 0xff);
      x = (x << 8) | y;
    }
    return x;
  }

  /**
   * Converts 2 bytes starting at {@code offset} to a {@code short} in big-endian order.
   *
   * @param buf source bytes; length must be at least 2.
   * @param offset starting index.
   * @return the decoded {@code short}.
   * @throws IllegalArgumentException if fewer than 2 bytes are available.
   */
  public static short bytesToShort(byte[] buf, int offset) {
    if (buf.length < 2) {
      throw new IllegalArgumentException();
    }
    short x = 0;
    for (int j = 1; j >= 0; j--) {
      short y = (short) (buf[j + offset] & 0xff);
      x = (short) ((x << 8) | y);
    }
    return x;
  }

  /**
   * Converts a byte range to an {@code int[]} in big-endian order.
   *
   * @param buf source bytes.
   * @param offset start offset.
   * @param length number of bytes; must be a multiple of 4.
   * @return a new int array of size {@code length / 4}.
   * @throws IllegalArgumentException if {@code length} is not a multiple of 4.
   */
  public static int[] bytesToInts(byte[] buf, int offset, int length) {
    if (length % 4 != 0) {
      throw new IllegalArgumentException();
    }
    int[] ints = new int[length / 4];
    for (int i = 0; i < ints.length; i++) {
      int x = 0;
      for (int j = 3; j >= 0; j--) {
        int y = (buf[j + offset + i * 4] & 0xff);
        x = (x << 8) | y;
      }
      ints[i] = x;
    }
    return ints;
  }

  /**
   * Converts a whole byte array to an {@code int[]} in big-endian order.
   *
   * @param buf source bytes.
   * @return a new int array of size {@code buf.length / 4}.
   * @throws IllegalArgumentException if {@code buf.length} is not a multiple of 4.
   */
  public static int[] bytesToInts(byte[] buf) {
    return bytesToInts(buf, 0, buf.length);
  }

  /**
   * Encodes a {@code long} to 8 bytes in little-endian order (the least significant byte first).
   *
   * @param x value to encode.
   * @return new byte[8].
   */
  public static byte[] longToBytes(long x) {
    byte[] buf = new byte[8];
    for (int j = 0; j < 8; j++) {
      buf[j] = (byte) x;
      x >>>= 8;
    }
    return buf;
  }

  /**
   * Encodes an {@code int[]} to bytes in little-endian order.
   *
   * @param ints source values.
   * @return new byte array of size {@code ints.length * 4}.
   */
  public static byte[] intsToBytes(int[] ints) {
    return intsToBytes(ints, 0, ints.length);
  }

  /**
   * Encodes a subrange of an {@code int[]} to bytes in little-endian order.
   *
   * @param ints source values.
   * @param offset start index in {@code ints}.
   * @param length number of {@code int}s to encode.
   * @return new byte array of size {@code length * 4}.
   */
  public static byte[] intsToBytes(int[] ints, int offset, int length) {
    byte[] buf = new byte[length * 4];
    for (int i = 0; i < length; i++) {
      long x = ints[i + offset];
      for (int j = 0; j < 4; j++) {
        buf[i * 4 + j] = (byte) x;
        x >>>= 8;
      }
    }
    return buf;
  }

  /**
   * Encodes an {@code int} to 4 bytes in little-endian order.
   *
   * @param x value to encode.
   * @return new byte[4].
   */
  public static byte[] intToBytes(int x) {
    byte[] buf = new byte[4];
    for (int j = 0; j < 4; j++) {
      buf[j] = (byte) x;
      x >>>= 8;
    }
    return buf;
  }

  /**
   * Encodes a {@code short} to 2 bytes in little-endian order.
   *
   * @param x value to encode.
   * @return new byte[2].
   */
  public static byte[] shortToBytes(short x) {
    byte[] buf = new byte[2];
    for (int j = 0; j < 2; j++) {
      buf[j] = (byte) x;
      x = (short) (x >>> 8);
    }
    return buf;
  }

  /**
   * Parses a {@code long} or returns a default value on failure.
   *
   * @param s input string.
   * @param defaultValue value to return when parsing fails.
   * @return parsed value or {@code defaultValue}.
   */
  public static long parseLong(String s, long defaultValue) {
    try {
      return Long.parseLong(s);
    } catch (NumberFormatException e) {
      LOG.error("Failed to parse value as long: {} : {}", s, e, e);
      return defaultValue;
    }
  }

  /**
   * Parses an {@code int} or returns a default value on failure.
   *
   * @param s input string.
   * @param defaultValue value to return when parsing fails.
   * @return parsed value or {@code defaultValue}.
   */
  public static int parseInt(String s, int defaultValue) {
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException e) {
      LOG.error("Failed to parse value as int: {} : {}", s, e, e);
      return defaultValue;
    }
  }

  /**
   * Parses a {@code short} or returns a default value on failure.
   *
   * <p>Note: The return type is {@code long} for historical reasons.
   *
   * @param s input string.
   * @param defaultValue value to return when parsing fails.
   * @return parsed value or {@code defaultValue}.
   */
  public static long parseShort(String s, short defaultValue) {
    try {
      return Short.parseShort(s);
    } catch (NumberFormatException e) {
      LOG.error("Failed to parse value as short: {} : {}", s, e, e);
      return defaultValue;
    }
  }

  /**
   * Parses a human-readable quantity into a {@code short} with optional IEC suffix.
   *
   * <p>Recognizes trailing {@code iB} and one or more {@code i} characters, and the unit prefixes
   * {@code k}/{@code K}. The intermediate math uses {@code double} and may overflow the {@code
   * short} range.
   *
   * @param s input string.
   * @return parsed value.
   * @throws NumberFormatException if the string is not parseable.
   */
  public static short parseShort(String s) throws NumberFormatException {
    s = stripIecSuffix(s, 'B');
    short res = 1;
    int x = s.length() - 1;
    int idx;
    try {
      while ((x >= 0) && ((idx = "kK".indexOf(s.charAt(x))) != -1)) {
        x--;
        res = (short) (res * MULTIPLES[idx]);
      }
      res = (short) (res * Double.parseDouble(s.substring(0, x + 1)));
    } catch (ArithmeticException e) {
      throw new NumberFormatException(e.getMessage());
    }
    return res;
  }

  /**
   * Removes an optional {@code per-second} qualifier from a bandwidth expression.
   *
   * <p>Examples of removed suffixes: {@code "/s"}, {@code "/sec"}, {@code "/second"}, {@code "ps"},
   * and the localized variant used in the wizard. The input case is preserved.
   *
   * @param limit input limit expression.
   * @return {@code limit} without the per-second suffix.
   */
  public static String trimPerSecond(String limit) {
    limit = limit.trim();
    if (limit.isEmpty()) {
      return "";
    }
    /*
     * IEC endings are case-sensitive, so the input string's case should not be modified. However, the
     * qualifiers should not be case-sensitive.
     */
    final String lower = limit.toLowerCase(Locale.ROOT);
    for (String ending :
        new String[] {
          "/s",
          "/sec",
          "/second",
          "ps",
          NodeL10n.getBase()
              .getString("FirstTimeWizardToadlet.bandwidthPerSecond")
              .toLowerCase(Locale.ROOT)
        }) {
      if (lower.endsWith(ending)) {
        return limit.substring(0, limit.length() - ending.length());
      }
    }
    return limit;
  }

  /**
   * Parses an integer according to a {@link Dimension}.
   *
   * <ul>
   *   <li>{@code NOT}/{@code SIZE}: delegates to {@link #parseInt(String)}.
   *   <li>{@code DURATION}: parses a duration via {@link TimeUtil#toMillis(String)} and returns
   *       milliseconds as an {@code int} when the value fits.
   * </ul>
   *
   * @param s input string.
   * @param dimension interpretation of the value.
   * @return parsed integer.
   * @throws NumberFormatException if parsing fails.
   * @throws ArithmeticException if the duration does not fit in an {@code int}.
   */
  public static int parseInt(String s, Dimension dimension) throws NumberFormatException {
    return switch (dimension) {
      case NOT, SIZE -> parseInt(s);
      case DURATION -> {
        long durationInMillis = TimeUtil.toMillis(s);
        if ((int) durationInMillis == durationInMillis) {
          yield (int) durationInMillis;
        }
        throw new ArithmeticException("integer overflow");
      }
    };
  }

  /**
   * Parses a human-readable quantity into an {@code int} with optional SI/IEC suffixes.
   *
   * <p>If a trailing {@code b} or {@code B} is present, the result is interpreted as bits or bytes
   * respectively (bits are converted to bytes: {@code 8b == 1}).
   *
   * @param s input string.
   * @return parsed bytes as an {@code int}.
   * @throws NumberFormatException if the string is not parseable.
   */
  public static int parseInt(String s) throws NumberFormatException {
    boolean isSizeInBits = s.endsWith("b");
    // strip bit/byte suffix without a regex to avoid backtracking
    s = isSizeInBits ? stripIecSuffix(s, 'b') : stripIecSuffix(s, 'B');
    int res = 1;
    int x = s.length() - 1;
    int idx;
    try {
      while ((x >= 0) && ((idx = "kKmMgG".indexOf(s.charAt(x))) != -1)) {
        x--;
        res = (int) (res * MULTIPLES[idx]);
      }
      res = (int) (res * Double.parseDouble(s.substring(0, x + 1)));
    } catch (ArithmeticException e) {
      throw new NumberFormatException(e.getMessage());
    }
    return isSizeInBits ? res / 8 : res;
  }

  /**
   * Parses a human-readable quantity into a {@code long} with optional SI/IEC suffixes.
   *
   * @param s input string.
   * @return parsed value.
   * @throws NumberFormatException if the string is not parseable or overflows {@code long} during
   *     scaling.
   */
  public static long parseLong(String s) throws NumberFormatException {
    s = stripIecSuffix(s, 'B');
    long res = 1;
    int x = s.length() - 1;
    int idx;
    try {
      while ((x >= 0) && ((idx = "kKmMgGtTpPeE".indexOf(s.charAt(x))) != -1)) {
        x--;
        res *= MULTIPLES[idx];
      }
      String multiplier = s.substring(0, x + 1).trim();
      if (multiplier.indexOf('.') > -1 || multiplier.indexOf('E') > -1) {
        double m = Double.parseDouble(multiplier);
        checkLongOverflowWhenMultiply(res, m);
        res = (long) (res * m);
        if (LOG.isDebugEnabled()) {
          LOG.debug("Parsed {} of {} as double: {}", multiplier, s, res);
        }
      } else {
        long m = Long.parseLong(multiplier);
        checkLongOverflowWhenMultiply(res, m);
        res *= m;
        if (LOG.isDebugEnabled()) {
          LOG.debug("Parsed {} of {} as long: {}", multiplier, s, res);
        }
      }
    } catch (ArithmeticException e) {
      throw new NumberFormatException(e.getMessage());
    }
    return res;
  }

  private static String stripIecSuffix(String s, char unit) {
    if (s.isEmpty()) return s;
    if (s.charAt(s.length() - 1) != unit) return s;
    int k = s.length() - 2;
    while (k >= 0 && s.charAt(k) == 'i') {
      k--;
    }
    return s.substring(0, k + 1);
  }

  private static void checkLongOverflowWhenMultiply(long a, Number b) {
    if (a != 0 && Math.abs(b.longValue()) > Long.MAX_VALUE / a) {
      throw new NumberFormatException("Long overflow");
    }
  }

  /**
   * Formats a positive {@code long} using a compact unit suffix when evenly divisible.
   *
   * <p>Uses {@code k/m/g/t/p/e} (and uppercase counterparts for IEC), appending {@code iB} for IEC
   * units when {@code isSize} is {@code true}. Falls back to {@link Long#toString(long)} for
   * non-positive values or when no clean unit boundary exists.
   *
   * @param val value to format.
   * @param isSize when {@code true}, allows IEC units; otherwise only SI multiples of 1000.
   * @return formatted string.
   */
  public static String longToString(long val, boolean isSize) {
    String ret = Long.toString(val);

    if (val <= 0) {
      return ret;
    }

    for (int i = MULTIPLES.length - 1; i >= 0; i--) {
      if (val > MULTIPLES[i] && val % MULTIPLES[i] == 0 && (isSize || MULTIPLES[i] % 1000 == 0)) {
        StringBuilder tmp = new StringBuilder();
        tmp.append(val / MULTIPLES[i]).append(MULTIPLES_2[i]);
        if (!MULTIPLES_2[i].toLowerCase(Locale.ROOT).equals(MULTIPLES_2[i])) {
          tmp.append("iB");
        }
        ret = tmp.toString();
        break;
      }
    }
    return ret;
  }

  /**
   * Formats an integer according to a {@link Dimension}.
   *
   * @param val value to format.
   * @param dimension interpretation (plain number, size, or duration).
   * @return formatted string.
   */
  public static String intToString(int val, Dimension dimension) {
    return switch (dimension) {
      case NOT -> intToString(val, false);
      case SIZE -> intToString(val, true);
      case DURATION -> TimeUtil.formatTime(val, 6, false);
    };
  }

  /**
   * Formats a positive {@code int} using a compact unit suffix when evenly divisible. See {@link
   * #longToString(long, boolean)} for details.
   *
   * @param val value to format.
   * @param isSize when {@code true}, allows IEC units; otherwise only SI multiples of 1000.
   * @return formatted string.
   */
  public static String intToString(int val, boolean isSize) {
    String ret = Integer.toString(val);

    if (val <= 0) {
      return ret;
    }

    for (int i = MULTIPLES.length - 1; i >= 0; i--) {
      if (val > MULTIPLES[i] && val % MULTIPLES[i] == 0 && (isSize || MULTIPLES[i] % 1000 == 0)) {
        StringBuilder tmp = new StringBuilder();
        tmp.append(val / MULTIPLES[i]).append(MULTIPLES_2[i]);
        if (!MULTIPLES_2[i].toLowerCase(Locale.ROOT).equals(MULTIPLES_2[i])) {
          tmp.append("iB");
        }
        ret = tmp.toString();
        break;
      }
    }
    return ret;
  }

  /**
   * Formats a positive {@code short} using a compact unit suffix when evenly divisible. See {@link
   * #longToString(long, boolean)} for details.
   *
   * @param val value to format.
   * @param isSize when {@code true}, allows IEC units; otherwise only SI multiples of 1000.
   * @return formatted string.
   */
  public static String shortToString(short val, boolean isSize) {
    String ret = Short.toString(val);

    if (val <= 0) {
      return ret;
    }

    for (int i = MULTIPLES.length - 1; i >= 0; i--) {
      if (val > MULTIPLES[i] && val % MULTIPLES[i] == 0 && (isSize || MULTIPLES[i] % 1000 == 0)) {
        StringBuilder tmp = new StringBuilder();
        tmp.append(val / MULTIPLES[i]).append(MULTIPLES_2[i]);
        if (!MULTIPLES_2[i].toLowerCase(Locale.ROOT).equals(MULTIPLES_2[i])) {
          tmp.append("iB");
        }
        ret = tmp.toString();
        break;
      }
    }
    return ret;
  }

  /**
   * Decodes IEEE-754 {@code double} values from a byte range.
   *
   * @param data source bytes.
   * @param offset start offset.
   * @param length number of bytes; must be a multiple of 8.
   * @return new array of doubles.
   * @throws IllegalArgumentException if {@code length} is not a multiple of 8.
   */
  public static double[] bytesToDoubles(byte[] data, int offset, int length) {
    long[] longs = bytesToLongs(data, offset, length);
    double[] doubles = new double[longs.length];
    for (int i = 0; i < longs.length; i++) {
      doubles[i] = Double.longBitsToDouble(longs[i]);
    }
    return doubles;
  }

  /**
   * Encodes {@code doubles} values as bytes using {@link Double#doubleToLongBits(double)}.
   *
   * @param doubles source values.
   * @return byte array containing all encodings.
   */
  public static byte[] doublesToBytes(double[] doubles) {
    long[] longs = new long[doubles.length];
    for (int i = 0; i < longs.length; i++) {
      longs[i] = Double.doubleToLongBits(doubles[i]);
    }
    return longsToBytes(longs);
  }

  /**
   * Decodes {@code double} values from an entire byte array. See {@link #bytesToDoubles(byte[],
   * int, int)}.
   *
   * @param data source bytes.
   * @return decoded doubles.
   */
  public static double[] bytesToDoubles(byte[] data) {
    return bytesToDoubles(data, 0, data.length);
  }

  /**
   * Removes empty lines and trims leading/trailing spaces from each remaining line.
   *
   * @param str input text.
   * @return cleaned text, always ending with a newline when at least one non-empty line remains.
   */
  public static String trimLines(String str) {
    StringBuilder r = new StringBuilder(str.length());
    int start = 0;
    int length = str.length();
    while (start <= length) {
      int end = str.indexOf('\n', start);
      if (end == -1) {
        end = length;
      }
      String line = str.substring(start, end).trim();
      if (!line.isEmpty()) {
        r.append(line);
        r.append('\n');
      }
      if (end == length) {
        break;
      }
      start = end + 1;
    }
    return r.toString();
  }

  /**
   * Compares version-like strings by alternating non-digit and digit runs.
   *
   * <p>Digit runs compare numerically; leading zeroes make a run smaller when numeric values are
   * equal. Non-digit runs compare lexicographically. A number token is considered greater than a
   * non-number token.
   *
   * @param x left-hand version.
   * @param y right-hand version.
   * @return negative, zero, or positive, according to the comparison.
   */
  public static int compareVersion(String x, String y) {
    int i = 0;
    int j = 0;
    boolean wantDigits = false;
    while (true) {
      int xCount = getDigits(x, i, wantDigits);
      String xTok = xCount > 0 ? x.substring(i, i + xCount) : null;
      i += xCount;

      int yCount = getDigits(y, j, wantDigits);
      String yTok = yCount > 0 ? y.substring(j, j + yCount) : null;
      j += yCount;

      int cmp = compareTokens(xTok, yTok, wantDigits);
      if (cmp != 0) return cmp;

      if (bothConsumed(i, x, j, y)) return 0;
      wantDigits = !wantDigits;
    }
  }

  private static boolean bothConsumed(int i, String x, int j, String y) {
    return i >= x.length() && j >= y.length();
  }

  private static int compareTokens(String xTok, String yTok, boolean wantDigits) {
    int presenceCmp = compareTokenPresence(xTok, yTok);
    if (presenceCmp != 0) return presenceCmp;
    if (xTok == null) return 0; // both nulls
    return wantDigits ? compareDigitTokens(xTok, yTok) : compareNonDigitTokens(xTok, yTok);
  }

  private static int compareTokenPresence(String xTok, String yTok) {
    if (xTok != null && yTok == null) return 1; // numbers > not numbers.
    if (yTok != null && xTok == null) return -1;
    return 0;
  }

  private static int compareNonDigitTokens(String xTok, String yTok) {
    if (xTok.equals(yTok)) return 0;
    return xTok.compareTo(yTok);
  }

  private static int compareDigitTokens(String xDigits, String yDigits) {
    if (xDigits.equals(yDigits)) return 0;
    try {
      long a = Integer.parseInt(xDigits);
      long b = Integer.parseInt(yDigits);
      if (a > b) return 1;
      if (a < b) return -1;
      return Integer.compare(yDigits.length(), xDigits.length()); // Extra 0's at the beginning.
      // Extra 0's at the beginning.
    } catch (NumberFormatException _) {
      // Too many digits!
      return xDigits.compareTo(yDigits);
    }
  }

  static int getDigits(String s, int i, boolean wantDigits) {
    int origI = i;
    for (; i < s.length(); i++) {
      if (Character.isDigit(s.charAt(i)) != wantDigits) {
        break;
      }
    }
    return i - origI;
  }

  /**
   * Compares two objects by their identity hash codes.
   *
   * @param o1 first object.
   * @param o2 second object.
   * @return {@code Integer.compare(System.identityHashCode(o1), System.identityHashCode(o2))}.
   */
  public static int compareObjectID(Object o1, Object o2) {
    int id1 = System.identityHashCode(o1);
    int id2 = System.identityHashCode(o2);
    return Integer.compare(id1, id2);
  }

  /**
   * Compares two {@code int} values avoiding overflow pitfalls.
   *
   * <p>Equivalent to {@link Integer#compare(int, int)}.
   */
  public static int compare(int x, int y) {
    return Integer.compare(x, y);
  }

  /**
   * Compares two {@code long} values avoiding overflow pitfalls.
   *
   * <p>Equivalent to {@link Long#compare(long, long)}.
   */
  public static int compare(long x, long y) {
    return Long.compare(x, y);
  }

  /** Compares two {@code double} values, ordering {@code NaN} after any numeric value. */
  public static int compare(double x, double y) {
    if (Double.isNaN(x)) {
      if (Double.isNaN(y)) {
        return 0; // kind of!
      } else {
        return -1; // the second is better
      }
    } else if (Double.isNaN(y)) {
      return 1; // first is better
    } else {
      if (x > y) {
        return 1;
      } else if (x < y) {
        return -1;
      }
    }
    return 0;
  }

  /** Compares two {@code float} values, ordering {@code NaN} after any numeric value. */
  public static int compare(float x, float y) {
    if (Float.isNaN(x)) {
      if (Float.isNaN(y)) {
        return 0; // kind of!
      } else {
        return -1; // the second is better
      }
    } else if (Float.isNaN(y)) {
      return 1; // first is better
    } else {
      if (x > y) {
        return 1;
      } else if (x < y) {
        return -1;
      }
    }
    return 0;
  }

  /**
   * Compares two dates, treating {@code null} as the epoch.
   *
   * @param a first date or {@code null}.
   * @param b second date or {@code null}.
   * @return the result of {@link Instant#compareTo(Instant)} on normalized values.
   */
  public static int compare(Instant a, Instant b) {
    // Normalize nulls to epoch so Instant#compareTo can be used safely.
    a = (a != null ? a : Instant.EPOCH);
    b = (b != null ? b : Instant.EPOCH);
    return a.compareTo(b);
  }

  /**
   * Copies all remaining bytes from a {@link ByteBuffer} into a new array.
   *
   * @param buf source buffer; its position advances to the limit.
   * @return a new byte array containing the remaining bytes.
   */
  public static byte[] copyToArray(ByteBuffer buf) {
    byte[] ret = new byte[buf.remaining()];
    buf.get(ret);
    return ret;
  }
}
