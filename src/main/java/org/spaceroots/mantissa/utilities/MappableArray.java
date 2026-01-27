package org.spaceroots.mantissa.utilities;

/**
 * Wraps a {@code double[]} and exposes it through the {@link ArraySliceMappable} contract.
 *
 * <p>This type is a small adapter used when an algorithm expects an {@link ArraySliceMappable}
 * instance but the state is naturally represented as a plain Java array. The instance owns an
 * internal array and provides copy-based accessors to read from or write to slices of a larger
 * workspace array. This makes it convenient to pack multiple states into a single buffer (for
 * example, in integrators or optimizers) while still manipulating each state as a dedicated object.
 *
 * <p>The internal array is mutable through {@link #mapStateFromArray(int, double[])}, but callers
 * never receive a direct reference to it: both the array constructor and {@link #getArray()}
 * perform defensive copies. Instances are not thread-safe; if the same instance is accessed from
 * multiple threads, external synchronization is required.
 *
 * <ul>
 *   <li><strong>Responsibility:</strong> bridge between array slices and an owned state array
 *   <li><strong>Invariant:</strong> the state dimension equals the internal array length
 *   <li><strong>Copying:</strong> mapping operations use {@link System#arraycopy(Object, int,
 *       Object, int, int)}
 * </ul>
 *
 * @version $Id: MappableArray.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class MappableArray implements ArraySliceMappable {

  /**
   * Creates a new instance with the specified state dimension.
   *
   * <p>This constructor allocates an internal {@code double[]} of length {@code dimension} and
   * initializes all entries to {@code 0.0}. The resulting instance can then be used with mapping
   * methods to copy values from a larger workspace array into the internal state, or to export the
   * internal state back into a workspace array.
   *
   * <p>The internal array is owned by this instance and is never exposed directly. The dimension is
   * fixed for the lifetime of the instance.
   *
   * @param dimension number of state elements to allocate; must be non-negative
   * @throws NegativeArraySizeException if {@code dimension} is negative
   */
  public MappableArray(int dimension) {
    internalArray = new double[dimension];
    for (int i = 0; i < dimension; ++i) {
      internalArray[i] = 0;
    }
  }

  /**
   * Creates a new instance by copying values from an existing array.
   *
   * <p>The provided {@code array} defines both the initial contents and the fixed state dimension.
   * This constructor performs a defensive copy; subsequent changes to the caller's array do not
   * affect this instance, and later updates to this instance do not mutate the caller's array.
   *
   * <p>Use {@link #getArray()} to retrieve a snapshot of the current state, or use the mapping
   * methods to read from and write to slices of external workspace arrays.
   *
   * @param array source values to copy; must be non-null and fully initialized
   * @throws NullPointerException if {@code array} is {@code null}
   */
  public MappableArray(double[] array) {
    internalArray = array.clone();
  }

  /**
   * Returns a snapshot of the current internal state.
   *
   * <p>This method returns a defensive copy of the internal array so callers cannot mutate the
   * instance state by accident. The returned array is owned by the caller and can be modified
   * freely. For bulk copying into an existing workspace buffer, prefer {@link #mapStateToArray(int,
   * double[])} to avoid allocating a new array.
   *
   * @return a newly allocated array containing the current state values
   */
  public double[] getArray() {
    return internalArray.clone();
  }

  /**
   * Returns the dimension of the state represented by this instance.
   *
   * <p>The dimension is defined as the length of the internal array and is fixed at construction
   * time. Mapping operations copy exactly this many elements between this instance and a backing
   * workspace array. This value can be used to size workspace arrays and to validate offsets before
   * invoking {@link #mapStateFromArray(int, double[])} or {@link #mapStateToArray(int, double[])}.
   *
   * @return the number of {@code double} values in the state vector
   */
  @Override
  public int getStateDimension() {
    return internalArray.length;
  }

  /**
   * Updates the internal state by copying a slice from the provided array.
   *
   * <p>This method copies {@link #getStateDimension()} consecutive elements starting at {@code
   * start} from {@code array} into this instance's internal array. It does not retain a reference
   * to the provided array and performs the copy using {@link System#arraycopy(Object, int, Object,
   * int, int)}.
   *
   * <p>The copy is not bounds-checked beyond what {@code arraycopy} performs; invalid indices
   * result in runtime exceptions.
   *
   * @param start start index in {@code array} where the state slice begins
   * @param array source array holding at least {@code start + getStateDimension()} elements
   * @throws NullPointerException if {@code array} is {@code null}
   * @throws ArrayIndexOutOfBoundsException if the requested slice is outside {@code array}
   */
  @Override
  public void mapStateFromArray(int start, double[] array) {
    System.arraycopy(array, start, internalArray, 0, internalArray.length);
  }

  /**
   * Stores the current internal state into a slice of the provided array.
   *
   * <p>This method copies {@link #getStateDimension()} consecutive elements from this instance's
   * internal array into {@code array}, starting at index {@code start}. It is useful for packing
   * the state into a shared workspace buffer without allocating new arrays.
   *
   * <p>The copy is performed using {@link System#arraycopy(Object, int, Object, int, int)} and will
   * fail fast with runtime exceptions if {@code array} is {@code null} or too small for the
   * requested slice.
   *
   * @param start start index in {@code array} where the state slice is stored
   * @param array destination array large enough to receive {@code getStateDimension()} values
   * @throws NullPointerException if {@code array} is {@code null}
   * @throws ArrayIndexOutOfBoundsException if the requested slice is outside {@code array}
   */
  @Override
  public void mapStateToArray(int start, double[] array) {
    System.arraycopy(internalArray, 0, array, start, internalArray.length);
  }

  /**
   * Internal array holding the current state values.
   *
   * <p>This field is intentionally package-private for use within the Mantissa utilities package.
   * External callers should treat the state as encapsulated and use {@link #getArray()} or the
   * mapping methods to access it via defensive copies.
   */
  double[] internalArray;
}
