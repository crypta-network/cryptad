package network.crypta.support;

import java.io.Serial;
import java.io.Serializable;

/**
 * Holds cumulative bandwidth totals and a creation timestamp.
 *
 * <p>This is a simple, mutable value object used to aggregate bandwidth figures over time. The
 * totals are expressed in bytes, and {@code creationTime} stores the millisecond time since the
 * Unix epoch when the values were last updated or created.
 *
 * <p>Thread-safety: This class is not thread-safe. If an instance is shared across threads, callers
 * must provide external synchronization.
 *
 * <p>Overflow: All counters are {@code long}. Arithmetic follows two's-complement semantics and may
 * wrap on overflow; no saturation or checks are performed.
 *
 * <p>Equality: {@link #equals(Object)} compares the three fields and requires the argument to be of
 * the exact same runtime class (no {@code instanceof} check). As a result, equality can be
 * asymmetric with subclasses.
 */
public class BandwidthStatsContainer implements Serializable {
  @Serial private static final long serialVersionUID = 1L;

  private long creationTime = 0L;
  private long totalBytesOut = 0L;
  private long totalBytesIn = 0L;

  /**
   * Indicates whether some other object is equal to this one.
   *
   * <p>Two containers are equal when and only when the other object is a {@code
   * BandwidthStatsContainer} (exact runtime class match) and their {@code creationTime}, {@code
   * totalBytesIn}, and {@code totalBytesOut} fields are all equal.
   *
   * <p>Note: The strict class check ({@code o.getClass() == BandwidthStatsContainer.class}) means a
   * subclass instance is not considered equal to a base instance, even if all field values match.
   * Consequently, equality may be asymmetric with respect to subclasses.
   *
   * @param o object to compare against; may be {@code null}
   * @return {@code true} if {@code o} is an equal {@code BandwidthStatsContainer}; {@code false}
   *     otherwise
   */
  @Override
  @SuppressWarnings("EqualsGetClass")
  public boolean equals(Object o) {
    if (o == null) return false;
    if (o.getClass() == BandwidthStatsContainer.class) {
      BandwidthStatsContainer oB = (BandwidthStatsContainer) o;
      return (oB.creationTime == this.creationTime)
          && (oB.totalBytesIn == this.totalBytesIn)
          && (oB.totalBytesOut == this.totalBytesOut);
    } else return false;
  }

  /**
   * Returns a hash code value for the object consistent with {@link #equals(Object)}.
   *
   * <p>The hash is derived from the three fields using simple mixing and a multiplier.
   *
   * @return a hash code consistent with the equality definition
   */
  @Override
  public int hashCode() {
    int hash = 3;
    hash = 41 * hash + Long.hashCode(this.creationTime);
    hash = 41 * hash + Long.hashCode(this.totalBytesOut);
    hash = 41 * hash + Long.hashCode(this.totalBytesIn);
    return hash;
  }

  /**
   * Adds the byte totals from another instance into this instance.
   *
   * <p>Only {@code totalBytesIn} and {@code totalBytesOut} are added; {@code creationTime} of this
   * instance remains unchanged. Arithmetic uses Java {@code long} addition and can wrap on
   * overflow.
   *
   * <p>Side effects: Mutates this instance. No synchronization is performed.
   *
   * @param latestBW the source of additional byte totals; must not be {@code null}
   * @throws NullPointerException if {@code latestBW} is {@code null}
   */
  public void addFrom(BandwidthStatsContainer latestBW) {
    this.totalBytesIn += latestBW.totalBytesIn;
    this.totalBytesOut += latestBW.totalBytesOut;
  }

  /**
   * Returns the creation timestamp.
   *
   * @return milliseconds since the Unix epoch representing when this container was created or last
   *     updated by the caller
   */
  public long getCreationTime() {
    return creationTime;
  }

  /**
   * Sets the creation timestamp.
   *
   * <p>No validation is performed.
   *
   * @param creationTime milliseconds since the Unix epoch
   */
  public void setCreationTime(long creationTime) {
    this.creationTime = creationTime;
  }

  /**
   * Returns the cumulative total of bytes sent.
   *
   * @return total bytes transmitted (may be negative if overflow occurred)
   */
  public long getTotalBytesOut() {
    return totalBytesOut;
  }

  /**
   * Sets the cumulative total of bytes sent.
   *
   * <p>No validation or saturation is performed. The value may be any {@code long}.
   *
   * @param totalBytesOut total bytes transmitted
   */
  public void setTotalBytesOut(long totalBytesOut) {
    this.totalBytesOut = totalBytesOut;
  }

  /**
   * Returns the cumulative total of bytes received.
   *
   * @return total bytes received (may be negative if overflow occurred)
   */
  public long getTotalBytesIn() {
    return totalBytesIn;
  }

  /**
   * Sets the cumulative total of bytes received.
   *
   * <p>No validation or saturation is performed. The value may be any {@code long}.
   *
   * @param totalBytesIn total bytes received
   */
  public void setTotalBytesIn(long totalBytesIn) {
    this.totalBytesIn = totalBytesIn;
  }
}
