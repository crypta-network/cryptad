package org.spaceroots.mantissa.functions.vectorial;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Iterator over a sampled function that exposes one vector point at a time.
 *
 * <p>This iterator wraps a {@link SampledFunction} instance and provides a sequential, forward-only
 * traversal over its ordered samples. It delegates all data access to the wrapped function while
 * maintaining a simple cursor that starts at the first element and advances by one with each
 * successful call to {@link #nextSamplePoint()}. The iterator does not perform any interpolation or
 * transformation; it simply surfaces the stored sample pairs as-is, preserving their original
 * abscissa ordering and dimensionality.
 *
 * <p>Use this class when client code needs to consume samples incrementally without pulling the
 * entire dataset into memory or when coordinating sampling with external control flow such as
 * streaming or batch processing. The iterator is mutable and not thread-safe; callers should create
 * separate instances per consumer thread or guard access externally. The underlying sampled
 * function is assumed to remain stable for the lifetime of the iterator; modifying the source while
 * iterating may lead to inconsistent results.
 *
 * <ul>
 *   <li>Stateful cursor advances strictly forward; random access is not supported.
 *   <li>Dimension queries are delegated directly to the sampled function.
 *   <li>Exhaustion is signaled via {@link ExhaustedSampleException} rather than returning null.
 * </ul>
 *
 * @see SampledFunction
 * @see SampledFunctionIterator
 * @version $Id: BasicSampledFunctionIterator.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 */
public class BasicSampledFunctionIterator implements SampledFunctionIterator, Serializable {

  /**
   * Create an iterator bound to a sampled function.
   *
   * <p>The iterator keeps only a reference to the supplied function and initializes its internal
   * cursor to the first sample. The function must define a stable ordering and size for all
   * samples, as the iterator relies on these properties to detect exhaustion and to compute the
   * next element index. The caller is responsible for ensuring the argument is non-null and remains
   * valid for the duration of iteration.
   *
   * @param function sampled function providing ordered vector-valued samples; must not be null
   */
  public BasicSampledFunctionIterator(SampledFunction function) {
    this.function = function;
    next = 0;
  }

  /**
   * Get the dimension of the vector values produced by this iterator.
   *
   * <p>The dimension is obtained directly from the underlying sampled function and therefore
   * reflects the shape of every returned {@link VectorialValuedPair}. The value is constant for the
   * lifetime of the iterator and independent of the current cursor position. Clients may call this
   * method repeatedly without side effects when sizing arrays or validating input/output buffers
   * prior to pulling samples.
   *
   * @return number of components in each vector sample; always non-negative
   */
  public int getDimension() {
    return function.getDimension();
  }

  /**
   * Test whether another sample is available.
   *
   * <p>This check compares the current cursor position with the size of the underlying sampled
   * function. It performs no lookahead beyond this numeric comparison and does not modify iterator
   * state. Callers should use this method to guard calls to {@link #nextSamplePoint()} in order to
   * avoid {@link ExhaustedSampleException}. The result remains valid only until the next mutation
   * of the iterator or the underlying sampled function.
   *
   * @return {@code true} when at least one more sample can be returned; otherwise {@code false}
   */
  public boolean hasNext() {
    return next < function.size();
  }

  /**
   * Return the next sampled point from the underlying function.
   *
   * <p>The method retrieves the sample at the current cursor position, advances the cursor by one,
   * and returns the retrieved {@link VectorialValuedPair}. If the iterator is already exhausted, an
   * {@link ExhaustedSampleException} is thrown. Any problem encountered while accessing or
   * computing the sample is reported via {@link FunctionException}. The returned pair reflects the
   * exact state of the sampled function at the time of invocation; subsequent modifications to the
   * source data are not reflected retroactively.
   *
   * @return vector-valued sample at the current cursor position before it is advanced
   * @throws ExhaustedSampleException if the cursor has reached or exceeded the available sample
   *     count
   * @throws FunctionException if the sampled function cannot compute or deliver the requested point
   */
  public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {

    if (next >= function.size()) {
      throw new ExhaustedSampleException(function.size());
    }

    int current = next++;
    return function.samplePointAt(current);
  }

  /** Underlying sampled function. */
  private final SampledFunction function;

  /** Next sample element. */
  private int next;

  @Serial private static final long serialVersionUID = -4386278658288500627L;
}
