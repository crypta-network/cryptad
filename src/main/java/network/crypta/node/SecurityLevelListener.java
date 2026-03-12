package network.crypta.node;

/**
 * Listener for security level changes.
 *
 * <p>Implementations receive a callback whenever a security level value transitions from a previous
 * value to a new value. The generic type {@code T} represents the domain used to express the level
 * (for example, an enum).
 *
 * <p>Threading: no specific caller thread is guaranteed. Callers may invoke listeners from any
 * thread. Implementations should return quickly and avoid long-running or blocking work on the
 * calling thread.
 *
 * @param <T> the type that represents a security level value
 */
public interface SecurityLevelListener<T> {

  /**
   * Notifies that the security level changes.
   *
   * <p>The callback provides both the previous value and the new value so implementations can
   * compare or compute deltas as needed. Nullability, if any, is determined by the caller.
   *
   * @param oldLevel the previous security level value
   * @param newLevel the new security level value
   */
  void onChange(T oldLevel, T newLevel);
}
