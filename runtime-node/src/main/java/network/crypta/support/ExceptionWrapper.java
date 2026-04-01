package network.crypta.support;

/**
 * Thread-safe container that holds a single {@link Exception} reference.
 *
 * <p>This minimal utility is useful when an API cannot throw checked exceptions or when a worker
 * thread needs to communicate a failure back to a caller. The container stores at most one value;
 * each call to {@link #set(Exception)} overwrites any previously stored exception.
 *
 * <p>Concurrency: Both {@link #get()} and {@link #set(Exception)} are {@code synchronized} on this
 * instance, providing mutual exclusion and establishing a happens-before relationship from a
 * successful {@code set(...)} to a subsequent {@code get()}. This class does not implement waiting
 * or notification primitives; if signaling is needed, coordinate externally (e.g., with latches or
 * condition variables).
 *
 * <p>Nullability: The stored value may be {@code null} (before any assignment or when cleared via
 * {@code set(null)}).
 *
 * <p>Performance: All operations are O(1) and allocate no additional objects beyond the stored
 * reference.
 */
public class ExceptionWrapper {

  // Captured exception reference; may be null when unset or explicitly cleared.
  private Exception e;

  /**
   * Returns the currently stored exception.
   *
   * <p>Threading: This method is synchronized and may briefly block while another thread is
   * executing {@link #set(Exception)}.
   *
   * @return the stored exception, or {@code null} if none has been set, or it has been cleared
   */
  public synchronized Exception get() {
    return e;
  }

  /**
   * Stores the given exception reference.
   *
   * <p>Semantics: Overwrites any previously stored value. Passing {@code null} clears the
   * container.
   *
   * <p>Threading: This method is synchronized and may briefly block while another thread is
   * executing {@link #get()} or another invocation of this method.
   *
   * @param e the exception to store; may be {@code null} to clear the current value
   */
  public synchronized void set(Exception e) {
    this.e = e;
  }
}
