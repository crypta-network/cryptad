package network.crypta.support;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Random;

/**
 * Iterator over an array that can yield elements in randomized order.
 *
 * <p>This reusable, read-only iterator traverses the backing array and returns each element exactly
 * once per run. When a {@link Random} is supplied (either at construction time or via {@link
 * #reset(Random)}), the iteration order for the next run is a fresh random permutation generated
 * incrementally using a Fisher–Yates shuffle step at each {@link #next()} call. When no random
 * source is provided, the iterator yields elements in the array's natural (index) order.
 *
 * <p>Behavioral notes:
 *
 * <ul>
 *   <li>Read-only: {@link #remove()} is unsupported and throws {@link
 *       UnsupportedOperationException}.
 *   <li>Reusable: calling {@link #reset(Random)} restarts iteration from the beginning and, when a
 *       non-{@code null} {@link Random} is given, selects a new random order for the next run.
 *   <li>Non-thread-safe: instances are not safe for concurrent use without external
 *       synchronization.
 *   <li>Side effects: the underlying array reference is never modified; an internal index array is
 *       shuffled.
 * </ul>
 *
 * <p>Complexity: memory usage is {@code O(n)} for the internal index permutation where {@code n} is
 * the array length; {@link #hasNext()} and {@link #next()} run in {@code O(1)} expected time.
 *
 * @param <E> element type stored in the array
 * @author bertm
 */
public class RandomArrayIterator<E> implements Iterator<E> {
  /** The underlying array. */
  private final E[] array;

  /** Permutation state. This array contains a permutation of indices into {@link #array}. */
  private final int[] indices;

  /** Random source for the current run; {@code null} means deterministic index order. */
  private Random random;

  /** Current position in the permutation ({@link #indices}). */
  private int i;

  /**
   * Constructs an iterator over the given array with an optional random iteration order.
   *
   * <p>If {@code random} is non-{@code null}, this iterator's first run (until exhaustion or a
   * subsequent {@link #reset(Random) reset}) yields a random permutation. If {@code random} is
   * {@code null}, it yields elements in increasing index order.
   *
   * @param array backing array to iterate; must not be {@code null}
   * @param random random source for the first run, or {@code null} for natural order
   */
  public RandomArrayIterator(E[] array, Random random) {
    this.array = array;
    this.indices = sequence(array.length);
    reset(random);
  }

  /**
   * Constructs an iterator that initially yields elements in natural (index) order.
   *
   * <p>Call {@link #reset(Random)} with a non-{@code null} {@link Random} to obtain a fresh random
   * order for a subsequent run.
   *
   * @param array backing array to iterate; must not be {@code null}
   */
  public RandomArrayIterator(E[] array) {
    this(array, null);
  }

  /**
   * Resets iteration to the start and optionally selects a new random order.
   *
   * <p>After calling this method, the next call to {@link #next()} returns the first element of a
   * new run. If {@code random} is non-{@code null}, the order for the upcoming run is a fresh
   * random permutation; otherwise the iterator repeats the previous run's order, which for a newly
   * constructed iterator is the array's natural order.
   *
   * @param random random source for the next run, or {@code null} to repeat the last order
   */
  public void reset(Random random) {
    this.random = random;
    i = 0;
  }

  /**
   * Returns whether at least one more element is available in the current run.
   *
   * @return {@code true} if another element can be returned by {@link #next()}, otherwise {@code
   *     false}
   */
  @Override
  public boolean hasNext() {
    return i < indices.length;
  }

  /**
   * Returns the next element in the current run.
   *
   * <p>When a random source is active for this run, this method performs one incremental
   * Fisher–Yates shuffle step to ensure a uniform permutation over the remaining positions.
   *
   * @return the next array element according to the current order
   * @throws NoSuchElementException if no elements remain
   */
  @Override
  public E next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    if (random != null) {
      shuffleStep();
    }
    return array[indices[i++]];
  }

  /**
   * Unsupported operation; this iterator is read-only.
   *
   * @throws UnsupportedOperationException always thrown
   */
  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }

  /**
   * Creates an integer sequence array.
   *
   * @param length The length of the resulting array.
   * @return an array holding values [0, 1, ..., length - 1]
   */
  private int[] sequence(int length) {
    final int[] ret = new int[length];
    for (int k = 0; k < length; k++) {
      ret[k] = k;
    }
    return ret;
  }

  // Performs one in-place Fisher–Yates step at position {@code i}, swapping with a uniformly
  // chosen index in the range [i, indices.length).
  private void shuffleStep() {
    // Swap the index at position i with a random subsequent index.
    final int j = random.nextInt(indices.length - i) + i;
    final int tmp = indices[j];
    indices[j] = indices[i];
    indices[i] = tmp;
  }
}
