package org.spaceroots.mantissa.functions.scalar;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Iterator over a scalar {@link SampledFunction}.
 *
 * <p>This iterator provides a minimal, allocation-free way to traverse the discrete samples
 * produced by a {@link SampledFunction}. It keeps only the next index internally and delegates
 * every lookup to the underlying function, so consumers always observe the same values they would
 * obtain when calling {@link SampledFunction#samplePointAt(int)} directly. Use this class when you
 * need a sequential view of samples without copying them into a collection, or when you want a
 * lightweight cursor that can be passed between components while preserving the function as the
 * single source of truth.
 *
 * <p>Instances are mutable with respect to their internal cursor but thread-unsafe; a single
 * instance must not be shared across threads without external synchronization. The iterator does
 * not skip or filter values, and it stops exactly after {@link SampledFunction#size()} elements.
 * Calls to {@link #nextSamplePoint()} advance the cursor, while {@link #hasNext()} leaves it
 * unchanged, making the class suitable for simple while-loop traversal patterns.
 *
 * <ul>
 *   <li>Responsibilities: maintain iteration state and delegate sampling.
 *   <li>Notable behavior: throws {@link ExhaustedSampleException} once all samples are consumed.
 *   <li>Performance: O(1) state, no buffering; each access is a single underlying lookup.
 * </ul>
 *
 * @see SampledFunction
 * @version $Id: BasicSampledFunctionIterator.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 */
public class BasicSampledFunctionIterator implements SampledFunctionIterator, Serializable {

  /** Underlying sampled function. */
  private final SampledFunction function;

  /** Next sample element. */
  private int next;

  /**
   * Creates an iterator bound to the provided sampled function.
   *
   * <p>The iterator starts at the first sample (index {@code 0}) and progresses sequentially with
   * each call to {@link #nextSamplePoint()}. The supplied function is retained by reference; its
   * size and values are queried on demand, so later modifications of the function's backing data
   * are visible through the iterator.
   *
   * @param function sampled function providing indexed scalar values; must be non-null
   */
  public BasicSampledFunctionIterator(SampledFunction function) {
    this.function = function;
    next = 0;
  }

  /**
   * Indicates whether another sample is available without advancing the cursor.
   *
   * <p>The check compares the current cursor position against {@link SampledFunction#size()} and
   * therefore reflects any changes in the function's length between calls. It does not guard
   * against concurrent modifications; callers should ensure consistent access if the underlying
   * function can change in other threads.
   *
   * @return {@code true} when at least one sample remains to be returned
   */
  @Override
  public boolean hasNext() {
    return next < function.size();
  }

  /**
   * Returns the next sample point from the underlying function.
   *
   * <p>The method advances the internal cursor and requests the corresponding value from {@link
   * SampledFunction#samplePointAt(int)}. If the iterator is already exhausted, it throws an {@link
   * ExhaustedSampleException}. This method performs no caching; each call may re-evaluate the
   * sample if the function computes values lazily.
   *
   * @return immutable pair containing the abscissa and sampled scalar value
   * @throws ExhaustedSampleException if iteration is already exhausted when requesting another
   *     sample
   * @throws FunctionException if underlying sampled function fails to compute the sample value
   */
  @Override
  public ScalarValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {
    if (next >= function.size()) {
      throw new ExhaustedSampleException(function.size());
    }

    int current = next++;
    return function.samplePointAt(current);
  }

  @Serial private static final long serialVersionUID = -9106690005598356403L;
}
