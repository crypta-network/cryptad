package network.crypta.clients.http.geoip;

/**
 * In-memory GeoIP lookup table backing {@link IPConverter}.
 *
 * <p>This class is a lightweight container for two parallel primitive arrays used during IPv4
 * lookups: an {@code int[]} of table entries (often interpreted as unsigned 32-bit values) and a
 * {@code short[]} of country identifiers stored as encoded two-character codes. The data is
 * typically produced by parsing a downloaded database file once and then re-used for many lookups
 * without allocating per-query objects.
 *
 * <p>The constructor stores references to the provided arrays directly, and the getters return the
 * same live backing arrays. This avoids copies, but it also means callers must maintain the
 * expected invariants themselves: index alignment between arrays, any required sort order, and
 * treating the arrays as effectively immutable once shared across threads. This class performs no
 * validation and does not provide any synchronization.
 *
 * <ul>
 *   <li>Responsibility: hold decoded range table data in memory.
 *   <li>Behavior: expose the backing arrays without defensive copies.
 *   <li>Threading: safe for concurrent reads if arrays are not mutated.
 * </ul>
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * Cache table = new Cache(codes, ips);
 * short[] countryCodes = table.getCodes();
 * int[] ipTable = table.getIps();
 * }</pre>
 *
 * @see IPConverter
 */
public class Cache {
  short[] codes;
  int[] ips;

  /**
   * Creates a new cache backed by the provided arrays.
   *
   * <p>This constructor does not copy or validate its inputs. The {@code codes} and {@code ips}
   * references are stored as-is and will be returned verbatim by {@link #getCodes()} and {@link
   * #getIps()}. Mutating either array after construction will therefore be observed through this
   * instance, which is convenient for tests but usually undesirable in production usage.
   *
   * @param codes array of encoded country codes aligned by index with {@code ips}; may be {@code
   *     null} to represent an intentionally absent table.
   * @param ips array of IPv4 table entries aligned by index with {@code codes}; may be {@code null}
   *     to represent an intentionally absent table.
   */
  public Cache(short[] codes, int[] ips) {
    this.codes = codes;
    this.ips = ips;
  }

  /**
   * Returns the country code table associated with this cache.
   *
   * <p>The returned array is the live backing {@code short[]} provided to the constructor; it is
   * not a defensive copy. Each element is typically an encoded two-character country code, with
   * negative values sometimes used by callers to indicate "unknown". Treat the array as read-only
   * once the cache is in use, especially if it may be accessed concurrently.
   *
   * @return the live backing {@code short[]} of encoded country codes, or {@code null} if none
   *     exists.
   */
  public short[] getCodes() {
    return codes;
  }

  /**
   * Returns the IP table associated with this cache.
   *
   * <p>The returned array is the live backing {@code int[]} provided to the constructor; it is not
   * a defensive copy. Values are commonly compared as unsigned 32-bit integers (for example via
   * {@code value & 0xffffffffL}) when looking up an IPv4 address represented as a {@code long}.
   * Mutating the array affects all readers of this cache instance.
   *
   * @return the live backing {@code int[]} of IPv4 table entries, or {@code null} if none exists.
   */
  public int[] getIps() {
    return ips;
  }
}
