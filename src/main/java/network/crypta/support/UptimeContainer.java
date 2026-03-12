package network.crypta.support;

import java.io.Serial;
import java.io.Serializable;

/**
 * Container for basic uptime statistics.
 *
 * <p>This mutable value object carries two pieces of information, both expressed in milliseconds:
 *
 * <ul>
 *   <li><b>Capture time</b> ({@link #getCreationTime()}): the wall-clock time, in milliseconds
 *       since the Unix epoch (UTC), when the latest uptime sample was observed.
 *   <li><b>Total uptime</b> ({@link #getTotalUptime()}): an accumulated uptime value intended to
 *       represent the sum of per-interval uptimes.
 * </ul>
 *
 * <p>Instances are not thread-safe. If multiple threads access the same instance, callers must
 * provide external synchronization.
 *
 * <p>Equality and hash code are defined in terms of both fields.
 *
 * @author Artefact2
 */
public class UptimeContainer implements Serializable {
  @Serial private static final long serialVersionUID = 1L;
  // Milliseconds since Unix epoch (UTC) of the most recent captured sample.
  private long creationTime = 0;
  // Accumulated uptime in milliseconds; expected non-negative (not enforced by this class).
  private long totalUptime = 0;

  /**
   * Compares this container to the specified object for equality.
   *
   * <p>Two containers are equal when both their capture time and accumulated uptime are identical.
   *
   * @param o the object to compare against
   * @return {@code true} if {@code o} is an {@code UptimeContainer} with the same values; otherwise
   *     {@code false}
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof UptimeContainer oB)) return false;
    return (oB.creationTime == this.creationTime) && (oB.totalUptime == this.totalUptime);
  }

  /**
   * Returns a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash is derived from both the capture time and the accumulated uptime.
   *
   * @return a hash code value for this container
   */
  @Override
  public int hashCode() {
    int hash = 7;
    hash = 29 * hash + Long.hashCode(this.creationTime);
    hash = 29 * hash + Long.hashCode(this.totalUptime);
    return hash;
  }

  /**
   * Aggregates values from the provided container into this instance.
   *
   * <p>This method replaces this instance's capture time with the source container's capture time
   * and adds the source's accumulated uptime to this instance's accumulated uptime. It mutates this
   * instance and does not modify the argument.
   *
   * <p>Expected usage is to merge a later sample into an ongoing total; no ordering checks are
   * performed.
   *
   * <p>Thread-safety: this method is not synchronized.
   *
   * @param latestUptime the source container to merge from; expected to represent a later sample
   * @throws NullPointerException if {@code latestUptime} is {@code null}
   */
  public void addFrom(UptimeContainer latestUptime) {
    this.creationTime = latestUptime.creationTime;
    this.totalUptime += latestUptime.totalUptime;
  }

  /**
   * Returns the capture time of the latest sample.
   *
   * @return milliseconds since the Unix epoch (UTC)
   */
  public long getCreationTime() {
    return creationTime;
  }

  /**
   * Sets the capture time of the latest sample.
   *
   * <p>No validation is performed.
   *
   * @param creationTime milliseconds since the Unix epoch (UTC)
   */
  public void setCreationTime(long creationTime) {
    this.creationTime = creationTime;
  }

  /**
   * Returns the accumulated uptime.
   *
   * @return accumulated uptime in milliseconds
   */
  public long getTotalUptime() {
    return totalUptime;
  }

  /**
   * Sets the accumulated uptime.
   *
   * <p>No validation is performed; callers may enforce non-negativity as needed.
   *
   * @param totalUptime accumulated uptime in milliseconds
   */
  public void setTotalUptime(long totalUptime) {
    this.totalUptime = totalUptime;
  }
}
