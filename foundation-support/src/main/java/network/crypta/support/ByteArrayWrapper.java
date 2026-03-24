package network.crypta.support;

import java.util.Arrays;
import java.util.Comparator;
import org.jetbrains.annotations.NotNull;

/**
 * Immutable wrapper for a {@code byte[]} that defines value semantics.
 *
 * <p>This class enables using raw byte sequences as keys in hash-based and sorted collections (for
 * example, {@link java.util.HashMap}, {@link java.util.HashSet}, or {@link java.util.TreeSet}) by
 * providing content-based {@link #equals(Object)}, cached {@link #hashCode()}, and a total,
 * lexicographic {@link #compareTo(ByteArrayWrapper)} ordering. The wrapped array is defensively
 * copied on construction and on {@link #get()} to maintain immutability.
 *
 * <p>Ordering is lexicographic on unsigned byte values (0–255) using {@link
 * Fields#compareBytes(byte[], byte[])}, and is consistent with equality. A shorter array is
 * considered smaller when it is a prefix of a longer array.
 *
 * <p>Thread-safety: instances are immutable and therefore thread-safe. Copies returned by {@link
 * #get()} are independent of the internal state.
 *
 * <p>Complexity: {@link #equals(Object)} and {@link #compareTo(ByteArrayWrapper)} are {@code O(n)}
 * in the length of the arrays; {@link #hashCode()} is {@code O(1)} after construction because the
 * hash is cached.
 *
 * @author toad
 */
public class ByteArrayWrapper implements Comparable<ByteArrayWrapper> {

  private final byte[] data;
  private final int hashCode;

  /**
   * Comparator that first compares cached hash codes and then falls back to natural order.
   *
   * <p>This comparator may be faster for mostly distinct values because it compares {@link
   * #hashCode()} first (an {@code int} comparison) and only performs a full lexicographic
   * comparison when hash codes collide. The resulting order is total and consistent with {@link
   * #equals(Object)} because ties on the hash are broken by {@link #compareTo(ByteArrayWrapper)}.
   */
  public static final Comparator<ByteArrayWrapper> FAST_COMPARATOR =
      Comparator.comparingInt(ByteArrayWrapper::hashCode).thenComparing(Comparator.naturalOrder());

  /**
   * Creates a new wrapper around a defensive copy of the provided array.
   *
   * @param data the byte sequence to wrap; the constructor copies its contents
   * @throws NullPointerException if {@code data} is {@code null}
   */
  public ByteArrayWrapper(byte[] data) {
    this.data = Arrays.copyOf(data, data.length);
    this.hashCode = Arrays.hashCode(this.data);
  }

  /**
   * Compares this instance to another object for equality by content.
   *
   * <p>Two wrappers are equal if and only if their underlying byte arrays have the same length and
   * identical byte values at every position. The comparison is by value, not by reference.
   *
   * @param other the object to compare with
   * @return {@code true} if the contents are equal; {@code false} otherwise
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (other instanceof ByteArrayWrapper b) {
      return this.hashCode == b.hashCode && Arrays.equals(this.data, b.data);
    }
    return false;
  }

  /**
   * Returns a cached, content-based hash code.
   *
   * <p>The hash is computed once from the wrapped array and stored, making later calls constant
   * time. The hash code is consistent with {@link #equals(Object)}.
   *
   * @return the cached hash code based on the array contents
   */
  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Returns a defensive copy of the wrapped array.
   *
   * <p>Modifying the returned array does not affect this wrapper. This method never returns a
   * reference to the internal array to preserve immutability.
   *
   * @return a new array containing the same bytes
   */
  public byte[] get() {
    return Arrays.copyOf(data, data.length);
  }

  /**
   * Compares this instance with another for lexicographic order on unsigned bytes.
   *
   * <p>The comparison uses {@link Fields#compareBytes(byte[], byte[])} and is consistent with
   * {@link #equals(Object)}. When two arrays share a common prefix, the shorter array is ordered
   * before the longer array.
   *
   * @param other the non-{@code null} value to compare against
   * @return a negative integer, zero, or a positive integer as this value is less than, equal to,
   *     or greater than {@code other}
   * @throws NullPointerException if {@code other} is {@code null}
   */
  @Override
  public int compareTo(@NotNull ByteArrayWrapper other) {
    if (this == other) {
      return 0;
    }
    return Fields.compareBytes(this.data, other.data);
  }
}
