package org.spaceroots.mantissa.utilities;

import java.util.ArrayList;
import java.util.List;

/**
 * Dispatches state data between a flat {@code double[]} and multiple domain objects.
 *
 * <p>An {@code ArrayMapper} maintains an ordered list of {@link ArraySliceMappable} instances. Each
 * managed object owns a contiguous slice of a single logical state vector. The mapper remembers the
 * slice offset for each object and can copy data in either direction:
 *
 * <ul>
 *   <li>{@link #updateObjects(double[])} reads from a flat array and pushes each slice into its
 *       object via {@link ArraySliceMappable#mapStateFromArray(int, double[])}.
 *   <li>{@link #updateArray(double[])} pulls each object's state via {@link
 *       ArraySliceMappable#mapStateToArray(int, double[])} and writes into a flat array.
 * </ul>
 *
 * <p>The total dimension of the logical state vector is the sum of the dimensions reported by all
 * managed objects at the time they are added. Offsets are fixed once an object is managed; the
 * mapper does not re-query dimensions or recompute offsets later.
 *
 * <p>The internal backing array is created lazily. If you never call {@link #getDataArray()},
 * {@link #updateArray()}, or {@link #updateObjects()}, the mapper holds no array storage. Adding a
 * new object after the internal array has been initialized resets that array to a new zero-filled
 * instance sized for the enlarged state vector. Callers that need to preserve state across such a
 * change should store it externally and reapply it after adding objects.
 *
 * <p>This class is mutable and not thread-safe. Typical usage is to build a mapper once during
 * model setup, add all objects, then repeatedly synchronize between objects and arrays within a
 * single-threaded numerical algorithm loop.
 *
 * @see ArraySliceMappable
 * @version $Id: ArrayMapper.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class ArrayMapper {

  /**
   * Builds an empty mapper with no managed objects.
   *
   * <p>The logical state dimension is initially zero. The internal data array is not allocated
   * until required by {@link #getDataArray()}, {@link #updateArray()}, or {@link #updateObjects()}.
   *
   * <p>Objects may be added later using {@link #manageMappable(ArraySliceMappable)}.
   */
  public ArrayMapper() {
    domainObjects = new ArrayList<>();
    size = 0;
    internalData = null;
  }

  /**
   * Builds a mapper that initially manages a single object.
   *
   * <p>The provided object is assigned offset {@code 0} and contributes its full dimension to the
   * logical state vector. An internal data array of the corresponding size is allocated
   * immediately. Additional objects may be added later using {@link
   * #manageMappable(ArraySliceMappable)}; if that happens, the internal data array is reset to a
   * new zero-filled array sized for the enlarged vector.
   *
   * <p>This constructor is equivalent to using {@link #ArrayMapper()} and then calling {@link
   * #manageMappable(ArraySliceMappable)} once with the same object.
   *
   * @param object domain object to handle, owning the first slice; must not be {@code null}
   * @throws NullPointerException if {@code object} is {@code null}
   */
  public ArrayMapper(ArraySliceMappable object) {

    domainObjects = new ArrayList<>();
    domainObjects.add(new ArrayMapperEntry(object, 0));

    size = object.getStateDimension();

    internalData = new double[size];
  }

  /**
   * Adds a new domain object to the mapper.
   *
   * <p>The object is appended to the current management order. Its slice starts at the current end
   * of the logical state vector, and its dimension is added to the total size. Offsets of
   * previously managed objects are unchanged.
   *
   * <p>If the internal data array has already been allocated (because of a prior call to {@link
   * #getDataArray()}, {@link #updateArray()}, or {@link #updateObjects()}), this method replaces
   * that array with a new zero-filled array of the new total size. No attempt is made to preserve
   * any previous internal data.
   *
   * @param object domain object to handle, providing its dimension and slice mappings; must not be
   *     {@code null}
   * @throws NullPointerException if {@code object} is {@code null}
   */
  @SuppressWarnings("unused")
  public void manageMappable(ArraySliceMappable object) {

    domainObjects.add(new ArrayMapperEntry(object, size));

    size += object.getStateDimension();

    if (internalData != null) {
      internalData = new double[size];
    }
  }

  /**
   * Returns a copy of the internal flat data array.
   *
   * <p>If the internal array has not been created yet, it is allocated with the current total size
   * and filled with zeros. The returned array is a defensive copy; modifying it does not affect the
   * mapper. To push data into objects, use {@link #updateObjects(double[])} with the caller-owned
   * array. To pull object state into a caller-owned array, use {@link #updateArray(double[])}.
   *
   * @return a newly allocated array containing the mapper's current internal data, never {@code
   *     null}
   */
  @SuppressWarnings("unused")
  public double[] getDataArray() {
    if (internalData == null) {
      internalData = new double[size];
    }
    return internalData.clone();
  }

  /**
   * Maps data from the internal array to all managed objects.
   *
   * <p>If the internal array is not yet allocated, it is created and filled with zeros before
   * dispatch. Each managed object receives a view of its slice through a call to {@link
   * ArraySliceMappable#mapStateFromArray(int, double[])} using its fixed offset.
   *
   * <p>This method is convenient when the internal array is used as the authoritative state and the
   * caller wants to refresh object views of that state.
   */
  @SuppressWarnings("unused")
  public void updateObjects() {
    if (internalData == null) {
      internalData = new double[size];
    }
    updateObjects(internalData);
  }

  /**
   * Map data from the specified array to the domain objects.
   *
   * <p>The array is treated as a concatenation of all slices in management order. Each object is
   * asked to reinitialize itself by reading its slice starting at its fixed offset.
   *
   * <p>The mapper does not validate array bounds or nullability beyond passing the array to managed
   * objects. If {@code data} is shorter than the total size, an {@link
   * ArrayIndexOutOfBoundsException} may be thrown by slice copies. If {@code data} is longer,
   * excess elements are ignored.
   *
   * @param data flat array holding the data to dispatch; must be at least as long as the total
   *     mapped size
   * @throws NullPointerException if {@code data} is {@code null}
   */
  public void updateObjects(double[] data) {
    for (ArrayMapperEntry entry : domainObjects) {
      entry.object.mapStateFromArray(entry.offset, data);
    }
  }

  /**
   * Maps data from all managed objects to the internal array.
   *
   * <p>If the internal array is not yet allocated, it is created with the current total size and
   * filled with zeros before being populated. Each object writes its slice into the internal array
   * via {@link ArraySliceMappable#mapStateToArray(int, double[])} using its fixed offset.
   *
   * <p>This method is convenient when objects are mutated by client code and the caller wants to
   * rebuild a consistent flat state vector.
   */
  @SuppressWarnings("unused")
  public void updateArray() {
    if (internalData == null) {
      internalData = new double[size];
    }
    updateArray(internalData);
  }

  /**
   * Map data from the domain objects to the specified array.
   *
   * <p>The array is treated as a concatenation of all slices in management order. Each managed
   * object is asked to store its current state into its slice starting at its fixed offset.
   *
   * <p>The mapper does not validate array bounds. If {@code data} is too short, an {@link
   * ArrayIndexOutOfBoundsException} may be thrown by slice copies. If {@code data} is longer, only
   * the first {@code size} elements are written.
   *
   * @param data flat array where to put the data; must be at least as long as the total mapped size
   * @throws NullPointerException if {@code data} is {@code null}
   */
  public void updateArray(double[] data) {
    for (ArrayMapperEntry entry : domainObjects) {
      entry.object.mapStateToArray(entry.offset, data);
    }
  }

  /** Container for all handled objects. */
  private final List<ArrayMapperEntry> domainObjects;

  /** Total number of scalar elements handled. (size of the array) */
  private int size;

  /** Flat array holding all data. This is null as long as nobody uses it (lazy creation) */
  private double[] internalData;
}
