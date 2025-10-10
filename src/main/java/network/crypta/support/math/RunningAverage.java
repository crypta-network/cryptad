package network.crypta.support.math;

import java.io.Serializable;

/**
 * Abstraction for a running average.
 *
 * <p>A {@code RunningAverage} accepts individual numeric observations ("reports") and exposes a
 * point-in-time estimate via {@link #currentValue()}. Different implementations provide different
 * averaging strategies (e.g. simple windowed mean, time-decaying mean, bootstrapped decaying mean).
 *
 * <p>Thread-safety: Implementations are expected to be thread-safe. Public methods that read or
 * mutate state should synchronize appropriately so callers may safely invoke them from multiple
 * threads.
 *
 * <p>Semantics common to all implementations:
 *
 * <ul>
 *   <li>{@link #report(double)} attempts to incorporate a single observation. Implementations may
 *       validate inputs (e.g. range checks) and either ignore or reject invalid values; consult the
 *       implementation Javadoc for details.
 *   <li>{@link #currentValue()} is side‑effect free and returns the estimate at the time of the
 *       call.
 *   <li>{@link #valueIfReported(double)} must not mutate state; it returns what {@link
 *       #currentValue()} would be if the supplied value were reported next. Implementations may
 *       return the unchanged value or throw {@link IllegalArgumentException} for invalid inputs;
 *       see the concrete type for specifics.
 *   <li>{@link #countReports()} returns the number of accepted (valid) observations so far. This
 *       count is monotonically increasing and does not include ignored/invalid reports.
 * </ul>
 *
 * <p>Copying: Prefer copy constructors on concrete implementations, or use {@link #copyOf
 * (RunningAverage)} when you only have the interface.
 *
 * <p>Serialization: Implementations are {@link java.io.Serializable}, but the serialized form is
 * implementation‑defined and subject to change between versions.
 */
public interface RunningAverage extends Serializable {

  /**
   * Returns the current estimate of the average.
   *
   * <p>For implementations with an initial default, this value may be that default until the first
   * valid report is accepted.
   */
  double currentValue();

  /**
   * Reports a single observation as a {@code double}.
   *
   * <p>Implementations define what constitutes a valid input and whether invalid values are ignored
   * or rejected with an exception.
   *
   * @param d observation to incorporate
   * @throws IllegalArgumentException if the value is invalid and the implementation chooses to
   *     signal it
   */
  void report(double d);

  /**
   * Reports a single observation as a {@code long} (convenience overload).
   *
   * <p>Default semantics match {@link #report(double)} for the same numeric value.
   *
   * @param d observation to incorporate
   * @throws IllegalArgumentException if the value is invalid and the implementation chooses to
   *     signal it
   */
  void report(long d);

  /**
   * Returns the value that {@link #currentValue()} would produce if {@code r} were reported next,
   * without mutating internal state.
   *
   * <p>Typical implementations compute this in O(1). Invalid inputs may either yield the unchanged
   * current value or cause an {@link IllegalArgumentException}; see the concrete type for details.
   *
   * @param r hypothetical observation to evaluate
   * @return the predicted value of {@link #currentValue()} if {@code r} were reported next
   * @throws IllegalArgumentException if the value is invalid and the implementation chooses to
   *     signal it
   */
  double valueIfReported(double r);

  /**
   * Returns the total number of accepted reports so far.
   *
   * <p>This is the number of valid observations that have affected the average; it is monotonically
   * increasing and never includes ignored/invalid inputs.
   */
  long countReports();

  /**
   * Creates a deep copy (snapshot) of the given instance.
   *
   * <p>The returned object will not reflect future changes to {@code original}. When the concrete
   * type is known, prefer invoking its copy constructor directly.
   *
   * @param original the instance to copy
   * @return an independent snapshot of {@code original}
   * @throws UnsupportedOperationException if the implementation type is unknown to this utility
   * @throws NullPointerException if {@code original} is {@code null}
   */
  static RunningAverage copyOf(RunningAverage original) {
    return switch (original) {
      case null -> throw new NullPointerException("original");
      case SimpleRunningAverage sra -> new SimpleRunningAverage(sra);
      case TrivialRunningAverage tra -> new TrivialRunningAverage(tra);
      case TimeDecayingRunningAverage tdra -> new TimeDecayingRunningAverage(tdra);
      case BootstrappingDecayingRunningAverage bdra ->
          new BootstrappingDecayingRunningAverage(bdra);
      case DecayingKeyspaceAverage dka -> new DecayingKeyspaceAverage(dka);
      default ->
          throw new UnsupportedOperationException(
              "Unsupported RunningAverage implementation: " + original.getClass().getName());
    };
  }
}
