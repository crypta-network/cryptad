package network.crypta.config;

/**
 * Identifies a string-valued option that exposes a finite set of selectable values.
 *
 * <p>Implementations typically also implement {@code StringCallback} (or another {@link
 * ConfigCallback}) to perform validation and persistence. The values returned by {@link
 * #getPossibleValues()} should be acceptable inputs for the corresponding setter, and are used by
 * UIs to render a dropdown or similar control. Ordering may be used for presentation; any
 * case-sensitivity or alias handling is defined by the implementation.
 */
public interface EnumerableOptionCallback {

  /**
   * Returns the list of values that the option can accept.
   *
   * <p>The returned array must not be {@code null} and should not contain {@code null} elements.
   * Implementations may return a new array on each call; callers must not modify the returned array
   * if it is shared. The set should be stable for the lifetime of the option instance unless
   * explicitly documented otherwise by the implementation.
   *
   * @return an array of acceptable values, in display order.
   */
  String[] getPossibleValues();

  /**
   * Returns the current effective value of the option.
   *
   * <p>Implementations are expected to return a value that appears in {@link #getPossibleValues()}
   * (subject to any normalization rules they define). The value reflects the currently applied
   * configuration and may come from defaults, persisted state, or runtime changes, depending on the
   * owning option.
   *
   * @return the current value; never {@code null} unless explicitly documented by the
   *     implementation.
   */
  String get();
}
