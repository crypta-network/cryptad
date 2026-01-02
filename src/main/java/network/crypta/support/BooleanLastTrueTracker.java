package network.crypta.support;

/**
 * Tracks when a boolean condition was last {@code true}.
 *
 * <p>This utility records the instant at which the tracked condition transitions from {@code false}
 * to {@code true}. While the condition remains {@code true}, callers can query using the current
 * time to obtain a view that the last-true moment is effectively "now". Once the condition becomes
 * {@code false} again, the stored timestamp reflects the most recent {@code false -> true}
 * transition.
 *
 * <p>Thread-safety: All public methods are synchronized on {@code this}, so instances are safe for
 * concurrent use by multiple threads without external locking.
 *
 * <p>Time base: The class does not mandate a specific time unit or epoch for the {@code long}
 * timestamps (typically milliseconds since the epoch from {@link System#currentTimeMillis()} or a
 * monotonic source). Callers must use a consistent time base for all interactions with a given
 * instance.
 *
 * <p>Sentinel: If the condition has never been {@code true}, {@link #getTimeLastTrue(long)} returns
 * {@code -1} (when the no-arg constructor is used).
 */
public class BooleanLastTrueTracker {
  // Guarded by 'this'. Holds the current state of the tracked condition.
  private boolean isTrue;
  // Guarded by 'this'. Timestamp of the most recent false->true transition; -1 if never true.
  private long timeLastTrue;

  public BooleanLastTrueTracker() {
    isTrue = false;
    timeLastTrue = -1;
  }

  /**
   * Creates a tracker with a predefined "last true" timestamp while starting in the {@code false}
   * state.
   *
   * <p>This is useful when the last-true moment is known from persisted state, and callers want to
   * continue tracking from that point.
   *
   * @param lastTrue the timestamp to report as the most recent {@code false -> true} transition
   *     until the state next becomes {@code true}. The unit/epoch is defined by the caller but must
   *     be consistent with subsequent {@code now} values supplied to this instance.
   */
  public BooleanLastTrueTracker(long lastTrue) {
    isTrue = false;
    timeLastTrue = lastTrue;
  }

  /**
   * Returns the current value of the tracked condition.
   *
   * <p>Thread-safe: synchronized on {@code this}.
   *
   * @return {@code true} if the condition is currently true; otherwise {@code false}.
   */
  public synchronized boolean isTrue() {
    return isTrue;
  }

  /**
   * Updates the tracked condition and optionally records a new "last true" timestamp.
   *
   * <p>When transitioning from {@code false} to {@code true}, this method stores {@code now} as the
   * time the condition last became true. For all other cases (no change, or {@code true -> false})
   * the stored timestamp is left unchanged.
   *
   * <p>Return value: This method returns the previous state (i.e., the value of {@link #isTrue()}
   * before applying the update). This is intentionally useful to detect whether a transition
   * occurred without an extra read.
   *
   * <p>Thread-safe: synchronized on {@code this}.
   *
   * @param value the new state to set.
   * @param now the caller-supplied current time, used only when transitioning {@code false ->
   *     true}. The unit/epoch is not enforced by this class; callers must supply values consistent
   *     with those used elsewhere for the same instance (for example, wall-clock or monotonic
   *     time).
   * @return the previous state of the condition.
   */
  public synchronized boolean set(boolean value, long now) {
    if (value == isTrue) return value;
    if (!isTrue) timeLastTrue = now;
    isTrue = value;
    return !value;
  }

  /**
   * Returns when the condition was last {@code true} according to the provided time base.
   *
   * <p>If the condition is currently {@code true}, the method returns the supplied {@code now}
   * value. If it is currently {@code false}, it returns the timestamp recorded the last time the
   * condition became {@code true}. If the condition has never been {@code true}, it returns {@code
   * -1} (when this instance was created via the no-arg constructor).
   *
   * <p>Thread-safe: synchronized on {@code this}.
   *
   * @param now the caller-supplied current time; only used to echo back when the condition is
   *     currently {@code true}. The unit/epoch must match the one used with {@link #set(boolean,
   *     long)} for meaningful comparisons.
   * @return {@code now} if currently true; otherwise the timestamp of the most recent {@code false
   *     -> true} transition, or {@code -1} if never true.
   */
  public synchronized long getTimeLastTrue(long now) {
    if (isTrue) return now;
    else return timeLastTrue;
  }
}
