package network.crypta.node.simulator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import network.crypta.support.Fields;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for long-term simulator tests that persist status in a CSV file.
 *
 * <p>This type centralizes small, stable utilities that multiple simulator tests rely on: a
 * fixed-format UTC date formatter, a snapshot of the current instant for reproducible "today"
 * handling, and common exit codes for well-known failure modes. Subclasses typically construct a
 * single test run, then append status lines to a CSV log as progress or failure outcomes occur. The
 * intent is to keep the CSV output consistent across runs and keep date handling locale-safe and
 * time-zone independent.
 *
 * <p>The class is state-light and is designed to be used concurrently by different test threads, as
 * long as callers treat the provided helpers as immutable. The {@code Today} snapshot is taken once
 * at class load time and does not advance; this favors reproducibility over real-time accuracy. The
 * write helper appends to a file and terminates the JVM on I/O failure to avoid producing partial
 * or misleading output.
 *
 * <ul>
 *   <li>Provides a shared UTC date format and parsing helper.
 *   <li>Exposes a stable "today" snapshot for deterministic reporting.
 *   <li>Defines exit codes for common failure conditions in simulator runs.
 * </ul>
 */
public class LongTermTest {

  private static final Logger LOG = LoggerFactory.getLogger(LongTermTest.class);

  private static final DateTimeFormatter DATE_FORMATTER =
      DateTimeFormatter.ofPattern("yyyy.MM.dd", Locale.US).withZone(ZoneOffset.UTC);

  /**
   * Shared UTC date formatter wrapper for CSV status fields.
   *
   * <p>The formatter is immutable and thread-safe, and it uses the {@code yyyy.MM.dd} pattern in
   * the US locale with a fixed UTC zone. The value is read-only and intended to be reused for both
   * formatting and parsing in simulator code without per-call allocation.
   */
  protected static final UtcDateFormat dateFormat = new UtcDateFormat(DATE_FORMATTER);

  /**
   * Snapshot of the current instant captured at class initialization.
   *
   * <p>This value is intentionally stable for the lifetime of the JVM, so repeated calls yield
   * consistent "today" semantics within a run. The snapshot is immutable and safe for concurrent
   * access by multiple simulator tasks.
   */
  protected static final Today today = new Today(Instant.now());

  /**
   * Exit status used when a test cannot proceed because no seed nodes are available.
   *
   * <p>This is a stable, non-zero code intended for automation and scripts that classify failures
   * without parsing log output. It should remain constant to preserve compatibility with existing
   * tooling.
   */
  protected static final int EXIT_NO_SEEDNODES = 257;

  /**
   * Exit status used when a test fails to reach its target condition or threshold.
   *
   * <p>The code signals a completed run with an unmet goal, rather than an unexpected crash. Keep
   * this value stable so that callers can distinguish it from other failure modes.
   */
  protected static final int EXIT_FAILED_TARGET = 258;

  /**
   * Exit status used when the run terminates due to an unhandled exception or I/O failure.
   *
   * <p>The code is reserved for unexpected termination paths, including fatal logging and explicit
   * {@code System.exit} calls when writing status output fails.
   */
  protected static final int EXIT_THREW_SOMETHING = 261;

  /**
   * Character encoding used for CSV status log output.
   *
   * <p>The encoding is fixed to UTF-8 to avoid platform-dependent defaults and to keep output
   * stable across environments. It is immutable and safe to reuse for all log writes.
   */
  protected static final Charset ENCODING = StandardCharsets.UTF_8;

  /**
   * Creates a new long-term test helper instance.
   *
   * <p>This constructor is protected because the class is intended to be extended by simulator
   * tests, not instantiated directly by external callers. The base type itself is stateless; all
   * shared utilities are static and thread-safe.
   */
  protected LongTermTest() {}

  /**
   * Appends a single CSV line to the given status log file.
   *
   * <p>The method converts the provided fields to a comma-separated line, appends a newline, and
   * writes using UTF-8. It opens the file in append mode for each call, making it safe for
   * occasional writes without keeping a stream open. On any {@link IOException}, it logs the
   * failure and terminates the JVM using {@link #EXIT_THREW_SOMETHING} to avoid silent corruption
   * or partial output.
   *
   * @param file the log file to append to, created if it does not already exist
   * @param csvLine ordered field values that make up a single CSV record
   */
  protected static void writeToStatusLog(File file, List<String> csvLine) {
    try (FileOutputStream fos = new FileOutputStream(file, true);
        OutputStreamWriter writer = new OutputStreamWriter(fos, ENCODING)) {
      writer.write(Fields.commaList(csvLine.toArray(), '!'));
      writer.write('\n');
    } catch (IOException e) {
      LOG.error("Exiting due to IOException writing status file {}", file, e);
      System.exit(EXIT_THREW_SOMETHING);
    }
  }

  /**
   * UTC-only formatter and parser for the simulator's CSV date fields.
   *
   * <p>This wrapper normalizes both parsing and formatting to a single, fixed pattern and zone. It
   * is deliberately minimal: formatting converts {@link Date} to a UTC {@link LocalDate}, while
   * parsing converts a date-only string to a midnight UTC {@link Date}. Instances are immutable and
   * thread-safe.
   */
  protected static final class UtcDateFormat {
    private final DateTimeFormatter formatter;

    /**
     * Creates a wrapper around the provided formatter.
     *
     * <p>The formatter must already be configured for UTC and the expected pattern. Callers should
     * prefer the shared {@link #dateFormat} instance rather than constructing new ones.
     *
     * @param formatter formatter preconfigured for the simulator's date pattern and UTC zone
     */
    private UtcDateFormat(DateTimeFormatter formatter) {
      this.formatter = formatter;
    }

    /**
     * Formats a {@link Date} into a UTC date string suitable for CSV output.
     *
     * <p>The result uses the fixed {@code yyyy.MM.dd} pattern. The time portion of the provided
     * {@link Date} is ignored after conversion to an instant and then to a {@link LocalDate} in
     * UTC. This method is deterministic and allocation-light beyond the resulting string.
     *
     * @param date point-in-time value to format; must be non-null and represent a valid instant
     * @return a UTC date string formatted for the simulator's CSV files
     */
    public String format(Date date) {
      return formatter.format(date.toInstant());
    }

    /**
     * Parses a UTC date string from the simulator's CSV files.
     *
     * <p>The input must use the {@code yyyy.MM.dd} pattern in UTC. The resulting {@link Date}
     * represents the start of that day in UTC (midnight). If parsing fails, the underlying {@link
     * DateTimeParseException} is wrapped in a {@link ParseException} with the original error index
     * preserved.
     *
     * @param text date text in {@code yyyy.MM.dd} form, interpreted as UTC midnight
     * @return a {@link Date} representing the parsed day at UTC midnight
     * @throws ParseException if the text is malformed or does not match the expected pattern
     */
    public Date parse(String text) throws ParseException {
      try {
        LocalDate date = LocalDate.parse(text, formatter);
        return Date.from(date.atStartOfDay(ZoneOffset.UTC).toInstant());
      } catch (DateTimeParseException e) {
        ParseException parseException = new ParseException(e.getMessage(), e.getErrorIndex());
        parseException.initCause(e);
        throw parseException;
      }
    }
  }

  /**
   * Snapshot of a specific instant, exposed via {@link Date} and calendar helpers.
   *
   * <p>This class is intentionally immutable and thread-safe. It captures an {@link Instant} once
   * and provides UTC-based views of that instant as {@link Date} and {@link GregorianCalendar}
   * instances. It is used to provide a consistent "today" reference for simulator tests that need
   * deterministic output across a run.
   */
  protected static final class Today {
    private final Instant instant;
    private static final TimeZone TIME_ZONE_GMT = TimeZone.getTimeZone("GMT");

    /**
     * Creates a snapshot wrapper for the provided instant.
     *
     * <p>Callers should pass a non-null instant that represents the desired "today" reference.
     * Prefer the shared {@link #today} instance rather than constructing new snapshots.
     *
     * @param instant immutable point-in-time value to expose through helper methods
     */
    private Today(Instant instant) {
      this.instant = instant;
    }

    /**
     * Returns the captured instant as a {@link Date}.
     *
     * <p>The returned {@link Date} is a new instance each call and can be mutated by the caller
     * without affecting this snapshot. The value is always based on the original instant, not the
     * current time.
     *
     * @return a new {@link Date} representing the snapshot instant
     */
    public Date getTime() {
      return Date.from(instant);
    }

    /**
     * Returns the fixed GMT time zone used by the simulator snapshot.
     *
     * <p>The returned time zone is a shared, immutable instance and should be treated as read-only.
     * It is used to keep calendar calculations deterministic and independent of host settings.
     *
     * @return the GMT {@link TimeZone} used for calendar calculations
     */
    public TimeZone getTimeZone() {
      return TIME_ZONE_GMT;
    }

    /**
     * Returns a calendar initialized to the snapshot instant in GMT.
     *
     * <p>The calendar is a new instance each call and may be modified by the caller without
     * affecting this snapshot. The time zone is explicitly set to GMT to avoid host-dependent
     * defaults and to keep date math stable.
     *
     * @return a new {@link GregorianCalendar} set to the snapshot instant in GMT
     */
    public GregorianCalendar copyCalendar() {
      GregorianCalendar calendar = new GregorianCalendar(TIME_ZONE_GMT);
      calendar.setTime(Date.from(instant));
      return calendar;
    }
  }
}
