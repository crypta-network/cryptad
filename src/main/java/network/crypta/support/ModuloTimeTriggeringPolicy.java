package network.crypta.support;

import ch.qos.logback.core.rolling.DefaultTimeBasedFileNamingAndTriggeringPolicy;
import ch.qos.logback.core.rolling.TimeBasedRollingPolicy;

/**
 * A Logback TimeBased triggering policy that only triggers at multiples of a base time unit.
 *
 * <p>Supported units: MINUTE, HOUR, DAY, WEEK, MONTH, YEAR. Multipliers &gt;= 1 are honored.
 */
public class ModuloTimeTriggeringPolicy<E>
    extends DefaultTimeBasedFileNamingAndTriggeringPolicy<E> {

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

  // Kept for backwards compatibility, not used after wall-clock alignment change
  @SuppressWarnings("unused")
  private long boundaryCount;

  public ModuloTimeTriggeringPolicy() {}

  public ModuloTimeTriggeringPolicy(Unit unit, int multiple) {
    this.unit = unit;
    this.multiple = Math.max(1, multiple);
  }

  public void setUnit(Unit unit) {
    this.unit = unit;
  }

  public void setMultiple(int multiple) {
    this.multiple = Math.max(1, multiple);
  }

  @Override
  public boolean isTriggeringEvent(java.io.File activeFile, E event) {
    // Let default policy detect period boundaries, then allow only aligned multiples.
    if (!super.isTriggeringEvent(activeFile, event)) return false;
    boundaryCount++; // no longer used for decision, retained for diagnostics if needed
    if (multiple <= 1) return true;

    // Align to wall-clock boundaries rather than JVM-relative counts so restarts
    // do not drift multi-unit rotations (e.g., 5-minute, 3-hour, etc.).
    long now = System.currentTimeMillis();
    java.time.ZoneId zone = java.time.ZoneId.systemDefault();
    java.time.ZonedDateTime zdt =
        java.time.ZonedDateTime.ofInstant(java.time.Instant.ofEpochMilli(now), zone);

    switch (unit) {
      case MINUTE:
        return (zdt.getMinute() % multiple) == 0;
      case HOUR:
        return (zdt.getHour() % multiple) == 0 && zdt.getMinute() == 0;
      case DAY:
        {
          long epochDay = zdt.toLocalDate().toEpochDay();
          // Rotate at local midnight on days where epochDay is a multiple of N
          return (epochDay % multiple) == 0 && zdt.getHour() == 0 && zdt.getMinute() == 0;
        }
      case WEEK:
        {
          // ISO week starts Monday. Compute week index since epoch anchored to ISO Monday.
          long epochDay = zdt.toLocalDate().toEpochDay();
          long isoWeekIndex = Math.floorDiv(epochDay + 3, 7); // 1970-01-01 was a Thursday
          return (isoWeekIndex % multiple) == 0
              && zdt.getDayOfWeek() == java.time.DayOfWeek.MONDAY
              && zdt.getHour() == 0
              && zdt.getMinute() == 0;
        }
      case MONTH:
        {
          int monthIndex = zdt.getYear() * 12 + (zdt.getMonthValue() - 1);
          return (monthIndex % multiple) == 0
              && zdt.getDayOfMonth() == 1
              && zdt.getHour() == 0
              && zdt.getMinute() == 0;
        }
      case YEAR:
      default:
        return (zdt.getYear() % multiple) == 0
            && zdt.getDayOfYear() == 1
            && zdt.getHour() == 0
            && zdt.getMinute() == 0;
    }
  }

  @Override
  public void setTimeBasedRollingPolicy(TimeBasedRollingPolicy<E> tbrp) {
    super.setTimeBasedRollingPolicy(tbrp);
  }
}
