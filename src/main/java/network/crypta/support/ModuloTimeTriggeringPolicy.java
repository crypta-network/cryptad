package network.crypta.support;

import ch.qos.logback.core.rolling.DefaultTimeBasedFileNamingAndTriggeringPolicy;
import ch.qos.logback.core.rolling.TimeBasedRollingPolicy;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;

/**
 * A Logback TimeBased triggering policy that only triggers at multiples of a base time unit.
 *
 * <p>Supported units: MINUTE, HOUR, DAY. Multipliers &gt;= 1 are honored.
 */
public class ModuloTimeTriggeringPolicy<E>
    extends DefaultTimeBasedFileNamingAndTriggeringPolicy<E> {

  public enum Unit {
    MINUTE,
    HOUR,
    DAY
  }

  private Unit unit = Unit.HOUR;
  private int multiple = 1;

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
    if (multiple <= 1) return true;

    long nowMillis = getCurrentTime();
    ZonedDateTime now =
        ZonedDateTime.ofInstant(Instant.ofEpochMilli(nowMillis), ZoneId.systemDefault());
    switch (unit) {
      case MINUTE:
        long minutes = ChronoUnit.MINUTES.between(Instant.EPOCH, now.toInstant());
        return minutes % multiple == 0;
      case HOUR:
        long hours = ChronoUnit.HOURS.between(Instant.EPOCH, now.toInstant());
        return hours % multiple == 0;
      case DAY:
      default:
        long days = ChronoUnit.DAYS.between(Instant.EPOCH, now.toInstant());
        return days % multiple == 0;
    }
  }

  @Override
  public void setTimeBasedRollingPolicy(TimeBasedRollingPolicy<E> tbrp) {
    super.setTimeBasedRollingPolicy(tbrp);
  }
}
