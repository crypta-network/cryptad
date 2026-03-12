package org.spaceroots.mantissa.utilities;

/**
 * Adapts a single {@code double} value to the {@link ArraySliceMappable} interface.
 *
 * <p>This class is a lightweight bridge for APIs that operate on state vectors represented as
 * contiguous slices of primitive arrays. It stores one scalar value and exposes it as a
 * one-dimensional state: {@link #getStateDimension()} always returns {@code 1}, and the mapping
 * methods read from and write to {@code array[start]} without copying or additional allocation.
 *
 * <p>The instance is intentionally mutable: callers may update the value via {@link
 * #setValue(double)} or by calling {@link #mapStateFromArray(int, double[])}. This makes it
 * convenient as a reusable container in iterative algorithms, but it also means the class is not
 * thread-safe; external synchronization is required if the same instance is shared across threads.
 *
 * <ul>
 *   <li>Represents a scalar as a one-element array slice for mapping APIs.
 *   <li>Provides simple getters and setters for direct scalar access.
 *   <li>Performs no bounds checking beyond what the JVM enforces.
 * </ul>
 *
 * @see ArraySliceMappable
 * @see #mapStateFromArray(int, double[])
 * @see #mapStateToArray(int, double[])
 * @version $Id: MappableScalar.java 1346 2002-09-05 19:03:58Z luc $
 * @author L. Maisonobe
 */
@SuppressWarnings("unused")
public class MappableScalar implements ArraySliceMappable {

  /**
   * Creates a new instance with an initial value of {@code 0.0}.
   *
   * <p>This constructor is useful when the initial value is not known yet and will be provided
   * later, either through {@link #setValue(double)} or through {@link #mapStateFromArray(int,
   * double[])}. The created instance always reports a state dimension of {@code 1}.
   *
   * <p>No external resources are acquired, and construction is constant-time. The instance starts
   * in a valid state immediately after construction and can be reused across multiple mapping
   * operations by updating its value between calls.
   */
  public MappableScalar() {
    value = 0;
  }

  /**
   * Creates a new instance initialized to the provided scalar value.
   *
   * <p>The provided value is stored as-is, without validation or normalization. In particular,
   * {@code NaN} and infinite values are permitted and will be preserved when mapping to and from
   * arrays. The created instance always reports a state dimension of {@code 1}.
   *
   * <p>Construction performs a single field assignment and does not allocate additional objects.
   *
   * @param value initial scalar value to store; any {@code double} is accepted
   */
  public MappableScalar(double value) {
    this.value = value;
  }

  /**
   * Returns the current scalar value stored in this instance.
   *
   * <p>The returned value reflects the most recent call to {@link #setValue(double)} or {@link
   * #mapStateFromArray(int, double[])}. No defensive copying is required since the value is a
   * primitive {@code double}. This method does not perform synchronization; if another thread
   * mutates the instance concurrently, the returned value is simply whichever value is observed at
   * the time of the read.
   *
   * @return the current scalar value stored in this mutable container
   */
  public double getValue() {
    return value;
  }

  /**
   * Updates the scalar value stored in this instance.
   *
   * <p>This is a simple mutator with no side effects beyond updating the stored value. The value is
   * stored as provided, including {@code NaN} and infinities. Subsequent calls to {@link
   * #mapStateToArray(int, double[])} will write this value into the target array. This method does
   * not perform synchronization; if the instance is shared across threads, callers must provide
   * external synchronization to define update ordering.
   *
   * @param value new scalar value to store; any {@code double} is accepted
   */
  public void setValue(double value) {
    this.value = value;
  }

  /**
   * Returns the dimension of the mapped state vector.
   *
   * <p>This implementation always returns {@code 1} because a {@code MappableScalar} represents a
   * single scalar value when adapted to array-slice based APIs. Callers can use this constant
   * dimension to size arrays or validate that a mapping target is compatible.
   *
   * @return {@code 1}, indicating a one-element state representation
   */
  @Override
  public int getStateDimension() {
    return 1;
  }

  /**
   * Reinitialize internal state from the specified array slice data.
   *
   * <p>This method reads exactly one element from {@code array} and stores it as the current value.
   * The read location is {@code array[start]}. No explicit bounds checks are performed; if {@code
   * array} is {@code null} or {@code start} is out of range, the JVM will throw the corresponding
   * runtime exception.
   *
   * @param start index of the scalar within {@code array}; must be in range
   * @param array array holding state values; must be non-null and long enough
   * @throws NullPointerException if {@code array} is {@code null}
   * @throws ArrayIndexOutOfBoundsException if {@code start} is outside array bounds
   */
  @Override
  public void mapStateFromArray(int start, double[] array) {
    value = array[start];
  }

  /**
   * Store internal state data into the specified array slice.
   *
   * <p>This method writes exactly one element to {@code array}. The write location is {@code
   * array[start]}, and the stored value is the current scalar as returned by {@link #getValue()}.
   * No explicit bounds checks are performed; if {@code array} is {@code null} or {@code start} is
   * out of range, the JVM will throw the corresponding runtime exception.
   *
   * @param start index of the scalar within {@code array}; must be in range
   * @param array array where the scalar should be stored; must be non-null and writable
   * @throws NullPointerException if {@code array} is {@code null}
   * @throws ArrayIndexOutOfBoundsException if {@code start} is outside array bounds
   */
  @Override
  public void mapStateToArray(int start, double[] array) {
    array[start] = value;
  }

  /** Current scalar value, mutated by setters and mapping operations. */
  double value;
}
