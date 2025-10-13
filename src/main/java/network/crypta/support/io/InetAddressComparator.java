package network.crypta.support.io;

import java.net.InetAddress;
import java.util.Comparator;
import network.crypta.support.Fields;

/**
 * Comparator for {@link InetAddress} optimized for speed and hash-flood resilience.
 *
 * <p>Purpose: provide a fast, non-lexical ordering suitable for structures like {@code TreeMap}
 * when adversarial inputs may otherwise degrade hash-based collections. The ordering is not numeric
 * (CIDR or natural) and must not be used when proximity of similar IPs matters.
 *
 * <p>Algorithm overview:
 *
 * <ul>
 *   <li>Primary key: {@link InetAddress#hashCode()} to disperse addresses quickly.
 *   <li>Tie-break 1: prefer IPv6 over IPv4 when hashes are equal (16-byte vs 4-byte address
 *       length).
 *   <li>Tie-break 2: lexicographic comparison of the raw address bytes via {@link
 *       Fields#compareBytes(byte[], byte[])}.
 * </ul>
 *
 * <p>Nullability and exceptions: passing exactly one {@code null} reference throws a {@link
 * NullPointerException}. Passing two {@code null} references returns 0 (identity equality check).
 *
 * <p>Threading and side effects: the comparator is stateless, has no side effects, and is thread
 * safe. Complexity is O(1) with at most 16 byte comparisons in the worst tie-breaking path.
 *
 * <p>This comparator is deliberately stateless. A single shared instance ({@link #COMPARATOR}) is
 * exposed to avoid per-call allocations and enable reuse across the codebase.
 *
 * @author toad
 */
@SuppressWarnings("java:S6548") // Shared, stateless comparator instance is intentional.
public class InetAddressComparator implements Comparator<InetAddress> {

  /**
   * Shared, reusable instance of this comparator.
   *
   * <p>Preferred over creating new instances because the comparator is stateless and thread-safe.
   * Use with APIs that accept a {@link Comparator} for {@link InetAddress}, e.g., {@code
   * Collections.sort} or {@code Arrays.sort}.
   */
  public static final InetAddressComparator COMPARATOR = new InetAddressComparator();

  /**
   * Compares two IP addresses using a fast, dispersion-friendly order.
   *
   * <p>Order is by {@link InetAddress#hashCode()} first; on equal hashes, IPv6 addresses sort
   * before IPv4; on equal lengths, raw address bytes are compared lexicographically.
   *
   * @param arg0 the first address; may be {@code null} only if {@code arg1} is also {@code null}
   * @param arg1 the second address; may be {@code null} only if {@code arg0} is also {@code null}
   * @return a negative integer, zero, or a positive integer as the first argument is less than,
   *     equal to, or greater than the second
   * @throws NullPointerException if exactly one argument is {@code null}
   */
  @Override
  public int compare(InetAddress arg0, InetAddress arg1) {
    // Fast path: identical references (including the case where both are null).
    if (arg0 == arg1) return 0;

    int a = arg0.hashCode();
    int b = arg1.hashCode();
    // Primary key: hash code. This provides quick dispersion, especially for IPv4.
    if (a > b) return 1;
    else if (b > a) return -1;

    // Note: InetAddress equality is based on the address bytes; cached hostnames are irrelevant.
    byte[] bytes0 = arg0.getAddress();
    byte[] bytes1 = arg1.getAddress();

    // Tie-break 1: prefer IPv6 over IPv4 on equal hashes (length 16 vs 4).
    // compareBytes is length-agnostic, so check length explicitly first.
    if (bytes0.length > bytes1.length) return -1; // IPv6 sorts before IPv4 on hash ties.
    if (bytes1.length > bytes0.length) return 1; // IPv4 sorts after IPv6 on hash ties.

    // Final tie-break: lexicographic comparison of the raw address bytes.
    return Fields.compareBytes(bytes0, bytes1);
  }
}
