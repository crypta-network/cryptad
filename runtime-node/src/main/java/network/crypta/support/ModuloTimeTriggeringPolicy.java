package network.crypta.support;

import ch.qos.logback.core.rolling.DefaultTimeBasedFileNamingAndTriggeringPolicy;

/**
 * Triggering policy that rotates only on wall-clock-aligned multiples of a time unit.
 *
 * <p>This augments Logback's default time-based triggering policy by requiring two conditions for
 * rollover:
 *
 * <ol>
 *   <li>The underlying policy detects a new period boundary.
 *   <li>The current local time (in the JVM's {@link java.time.ZoneId#systemDefault() default time
 *       zone}) is aligned to the configured {@link Unit} and {@code multiple}.
 * </ol>
 *
 * This prevents schedule drift across process restarts for multi-unit rotations (for example, every
 * 5 minutes or every 3 hours).
 *
 * <p>Supported units: {@link Unit#MINUTE}, {@link Unit#HOUR}, {@link Unit#DAY}, {@link Unit#WEEK},
 * {@link Unit#MONTH}, {@link Unit#YEAR}. A {@code multiple} less than 1 is clamped to 1.
 *
 * <p>Time semantics:
 *
 * <ul>
 *   <li>MINUTE — any minute where {@code minute % multiple == 0}.
 *   <li>HOUR — top of the hour where {@code hour % multiple == 0} (minute must be 0).
 *   <li>DAY — local midnight on days where {@code epochDay % multiple == 0}.
 *   <li>WEEK — ISO weeks, aligned to Monday 00:00; rollover when the computed week index modulo
 *       {@code multiple} is 0 (see inline notes).
 *   <li>MONTH — first day of month 00:00 where {@code (year*12 + monthIndex) % multiple == 0}.
 *   <li>YEAR — January 1st 00:00 where {@code year % multiple == 0}.
 * </ul>
 *
 * <p>Implementation notes:
 *
 * <ul>
 *   <li>Computation uses {@link java.time} and the system default time zone.
 *   <li>DST transitions may make local midnight ambiguous or skipped; observed instants follow the
 *       Java time-zone rules for the host.
 * </ul>
 *
 * @param <E> event type produced by the attached appender
 */
public class ModuloTimeTriggeringPolicy<E>
    extends DefaultTimeBasedFileNamingAndTriggeringPolicy<E> {

  /** Units used to evaluate wall-clock alignment for modulo checks. */
  public enum Unit {
    MINUTE,
    HOUR,
    DAY,
    WEEK,
    MONTH,
    YEAR
  }

  private Unit unit = Unit.HOUR;
  private int multiple = 1;
  // Tracks last observed minute index (epoch minutes) to detect period changes independently
  // of the parent policy. This guards against false negatives when tests inject times via
  // setCurrentTime()/setDateInCurrentPeriod() and the parent policy does not detect a boundary.
  private long lastMinuteIndex = Long.MIN_VALUE;

  // Diagnostic counter retained for compatibility; not used in decision-making since the
  // wall-clock alignment change. Incremented when a period boundary is observed.
  @SuppressWarnings("unused")
  private long boundaryCount;

  /** Creates a policy with defaults of {@link Unit#HOUR} and {@code multiple == 1}. */
  public ModuloTimeTriggeringPolicy() {}

  /**
   * Creates a policy with an explicit unit and multiple.
   *
   * @param unit the base wall-clock unit to align to; must not be {@code null}
   * @param multiple the required multiple for {@code unit}; values &lt; 1 are treated as 1
   */
  @SuppressWarnings("unused")
  public ModuloTimeTriggeringPolicy(Unit unit, int multiple) {
    this.unit = unit;
    this.multiple = Math.max(1, multiple);
  }

  /**
   * Sets the wall-clock unit used for modulo alignment.
   *
   * @param unit the unit to apply; must not be {@code null}
   */
  public void setUnit(Unit unit) {
    this.unit = unit;
  }

  /**
   * Sets the required multiple for the selected unit.
   *
   * <p>Values less than 1 are treated as 1, which effectively disables the modulo constraint and
   * defers to the underlying time-based boundary detection.
   *
   * @param multiple the multiple to enforce; non-positive values are clamped to 1
   */
  public void setMultiple(int multiple) {
    this.multiple = Math.max(1, multiple);
  }

  /**
   * Indicates whether a rollover should occur for the given event.
   *
   * <p>First delegates to the default time-based policy; if a period boundary is detected, it then
   * requires the local wall clock to satisfy the configured modulo predicate (see class
   * documentation). If {@code multiple <= 1}, the modulo predicate is ignored and any boundary
   * triggers rollover.
   *
   * <p>Thread-safety: typically invoked by an appender thread without external synchronization.
   *
   * @param activeFile the current active log file (may be {@code null})
   * @param event the current event (type depends on the appender)
   * @return {@code true} if a rollover should occur; otherwise {@code false}
   */
  @Override
  public boolean isTriggeringEvent(java.io.File activeFile, E event) {
    // Use the policy's notion of current time so tests can control it via setCurrentTime().
    long now = getCurrentTime();
    java.time.ZoneId zone = java.time.ZoneId.systemDefault();
    java.time.ZonedDateTime zdt =
        java.time.ZonedDateTime.ofInstant(java.time.Instant.ofEpochMilli(now), zone);

    boolean aligned;
    switch (unit) {
      case MINUTE:
        aligned = (zdt.getMinute() % multiple) == 0;
        break;
      case HOUR:
        aligned = (zdt.getHour() % multiple) == 0 && zdt.getMinute() == 0;
        break;
      case DAY:
        {
          long epochDay = zdt.toLocalDate().toEpochDay();
          aligned = (epochDay % multiple) == 0 && zdt.getHour() == 0 && zdt.getMinute() == 0;
          break;
        }
      case WEEK:
        {
          long epochDay = zdt.toLocalDate().toEpochDay();
          long isoWeekIndex = Math.floorDiv(epochDay + 3, 7); // 1970-01-01 was a Thursday
          aligned =
              (isoWeekIndex % multiple) == 0
                  && zdt.getDayOfWeek() == java.time.DayOfWeek.MONDAY
                  && zdt.getHour() == 0
                  && zdt.getMinute() == 0;
          break;
        }
      case MONTH:
        {
          int monthIndex = zdt.getYear() * 12 + (zdt.getMonthValue() - 1);
          aligned =
              (monthIndex % multiple) == 0
                  && zdt.getDayOfMonth() == 1
                  && zdt.getHour() == 0
                  && zdt.getMinute() == 0;
          break;
        }
      case YEAR:
      default:
        aligned =
            (zdt.getYear() % multiple) == 0
                && zdt.getDayOfYear() == 1
                && zdt.getHour() == 0
                && zdt.getMinute() == 0;
        break;
    }

    // Detect minute boundary transitions independently as a fallback for cases where the underlying
    // policy does not report a boundary (e.g., when times are injected in tests).
    long minuteIndex = java.lang.Math.floorDiv(now, 60_000L);
    boolean minuteChanged = minuteIndex != lastMinuteIndex;
    boolean observedPreviousMinute = lastMinuteIndex != Long.MIN_VALUE;
    lastMinuteIndex = minuteIndex;

    if (!aligned) {
      // If not aligned, never rotate.
      // Still call parent to keep its internal state in sync.
      super.isTriggeringEvent(activeFile, event);
      return false;
    }

    // Prefer the parent policy's boundary detection, but allow a fallback when a minute boundary
    // has
    // occurred while aligned, to avoid false negatives under controlled test clocks.
    boolean parentBoundary = super.isTriggeringEvent(activeFile, event);
    if (parentBoundary) {
      boundaryCount++; // retained for diagnostics; not used for decision
      return true;
    }
    return observedPreviousMinute && minuteChanged;
  }

  // Intentionally no override for time source; we rely on getCurrentTime() inherited from
  // TimeBasedFileNamingAndTriggeringPolicyBase so unit tests can adjust the perceived time via
  // setCurrentTime(long).
}
