package org.spaceroots.mantissa.functions.vectorial;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Iterator over vector-valued function samples produced by {@link SampledFunction}.
 *
 * <p>Implementations walk through a sequence of sampled points, typically generated from a
 * discretized or lazily evaluated vector function. The iterator exposes only read methods and
 * advances in a single forward direction; callers are expected to loop with {@link #hasNext()} and
 * {@link #nextSamplePoint()} until exhaustion. The dimensionality of each vector remains stable for
 * the life of the iterator, enabling callers to allocate result buffers up front. Instances are
 * stateful and generally not thread-safe; share them across threads only when external
 * synchronization preserves iteration order.
 *
 * <ul>
 *   <li>Expose the fixed dimension of every returned vector value.
 *   <li>Report exhaustion without altering the underlying sample source.
 *   <li>Propagate function evaluation failures via {@link FunctionException}.
 * </ul>
 *
 * <pre>{@code
 * SampledFunctionIterator it = sampledFunction.iterator();
 * while (it.hasNext()) {
 *   VectorialValuedPair pair = it.nextSamplePoint();
 *   // consume pair.getX() and pair.getVector()
 * }
 * }</pre>
 *
 * @see SampledFunction
 * @see VectorialValuedPair
 * @version $Id: SampledFunctionIterator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public interface SampledFunctionIterator {

  /**
   * Return the dimensionality of vectors yielded by this iterator.
   *
   * <p>The dimension is constant for all samples exposed by a given iterator instance and normally
   * matches the output dimension of the originating {@link SampledFunction}. Callers often retrieve
   * it once before iteration to allocate reusable arrays or matrices sized for each sample vector.
   * Implementations should not perform expensive computations when answering this query; the value
   * ought to be available without advancing the iteration cursor.
   *
   * @return number of components in each sample vector produced by this iterator
   */
  int getDimension();

  /**
   * Determine whether another sample point is available.
   *
   * <p>This predicate must not advance the iterator or trigger underlying function evaluation. A
   * {@code true} value indicates that a subsequent call to {@link #nextSamplePoint()} is expected
   * to succeed without throwing {@link ExhaustedSampleException}. Once it returns {@code false},
   * the iterator is considered exhausted and further calls to this method should continue to return
   * {@code false} consistently.
   *
   * @return {@code true} when at least one additional sample point can be retrieved safely
   */
  boolean hasNext();

  /**
   * Retrieve the next sampled point produced by the iterator.
   *
   * <p>The call advances the internal cursor and returns a {@link VectorialValuedPair} containing
   * the sample abscissa alongside the vector-valued function output. Clients should typically guard
   * calls with {@link #hasNext()} to avoid exhaustion errors. The returned pair is expected to be
   * either a new immutable instance or an object whose contents will not be mutated by subsequent
   * iterator operations, allowing immediate consumption by the caller. Repeated invocations
   * progress strictly forward; no rewinding or look-ahead is implied.
   *
   * @return next available sample point with its abscissa and vector value components
   * @throws ExhaustedSampleException if no further sample points remain for this iterator instance
   * @throws FunctionException if evaluating the underlying function fails for the requested sample
   */
  VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException;
}
