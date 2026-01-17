package network.crypta.support.math;

/**
 * Immutable container for default values and input bounds in running averages.
 *
 * <p>This record groups the three values that bound a running average: the default value returned
 * before any valid reports, and the inclusive minimum and maximum accepted observations. Using a
 * dedicated carrier reduces parameter proliferation in constructors and promotes consistent bounds
 * reuse across different running-average implementations. It is intended for call sites that build
 * averages repeatedly with the same bounds and for configuration layers that want to pass a single
 * object through APIs without losing clarity about units and ranges.
 *
 * <p>Instances are immutable and thread-safe. The record does not enforce validation on its own; it
 * simply stores the values. Implementations such as {@code TimeDecayingRunningAverage} and {@code
 * BootstrappingDecayingRunningAverage} interpret {@code min} and {@code max} as inclusive bounds
 * and treat values outside the range or non-finite inputs as invalid reports. Use a shared instance
 * when the same bounds apply to multiple averages or when constructing averages on demand.
 *
 * <ul>
 *   <li>Encapsulates default value plus inclusive bounds in a single reusable object.
 *   <li>Supports constructor reuse and consistent configuration propagation.
 *   <li>Does not perform validation; validation is owned by the consuming average implementation.
 * </ul>
 *
 * @param defaultValue initial value returned before the first valid report is accepted
 * @param min inclusive lower bound for accepted observations, expressed in the caller's units
 * @param max inclusive upper bound for accepted observations, expressed in the caller's units
 */
public record RunningAverageBounds(double defaultValue, double min, double max) {

  /**
   * Creates a bounds record with the supplied default value and inclusive range.
   *
   * <p>This factory is a convenience for callers that want a readable named constructor and a clear
   * call site. It does not validate the bounds; callers should ensure {@code min} and {@code max}
   * follow the expectations of the target running average implementation. Typical usage is to pass
   * the returned instance into a running-average constructor along with half-life or other decay
   * settings, keeping bounds bundled as a single argument.
   *
   * @param defaultValue initial value returned before the average accepts any valid report
   * @param min inclusive lower bound for accepted observations in the caller's units
   * @param max inclusive upper bound for accepted observations in the caller's units
   * @return an immutable bounds record capturing the provided default value and range
   */
  public static RunningAverageBounds of(double defaultValue, double min, double max) {
    return new RunningAverageBounds(defaultValue, min, max);
  }
}
