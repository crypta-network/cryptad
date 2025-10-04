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
    boundaryCount++;
    if (multiple <= 1) return true;

    switch (unit) {
      case MINUTE:
      case HOUR:
      case DAY:
      case WEEK:
      case MONTH:
      case YEAR:
      default:
        // Super already aligned us to the correct period boundary for the configured pattern;
        // we only allow every Nth boundary to honor the multiplier across all units.
        return (boundaryCount % multiple) == 0;
    }
  }

  @Override
  public void setTimeBasedRollingPolicy(TimeBasedRollingPolicy<E> tbrp) {
    super.setTimeBasedRollingPolicy(tbrp);
  }
}
