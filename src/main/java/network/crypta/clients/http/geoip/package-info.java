/**
 * GeoIP lookup helpers for the HTTP UI.
 *
 * <p>This package provides a small, best-effort utility layer that maps an IP address to an
 * approximate country or region code by consulting an on-disk IP range table. The table is expected
 * to be downloaded and refreshed by the node's update system, and the lookup logic is written to
 * tolerate missing or corrupted inputs: when the database is unavailable or cannot be parsed,
 * callers typically receive no location information rather than a hard failure.
 *
 * <p>The primary entry point is {@code IPConverter}, which loads the database file, builds a
 * compact in-memory representation, and performs lookups via binary search. Lookups may be memoized
 * in a small cache to reduce repeated work for common addresses. The in-memory table representation
 * is carried by {@code Cache}, which intentionally stores and exposes primitive arrays without
 * defensive copies for efficiency.
 *
 * <p><b>Intended usage and constraints</b>
 *
 * <ul>
 *   <li>This is used by the HTTP interface (for example, the peer UI) to display approximate
 *       locations such as a country label and, when resources exist, a corresponding flag icon.
 *   <li>Results are derived from a third-party range database and are not authoritative; they
 *       should not be treated as an identity or security boundary.
 *   <li>Threading expectations are conservative: the converter and its caches are mutable and are
 *       generally intended for single-threaded use unless callers provide their own
 *       synchronization.
 * </ul>
 *
 * <p>Example flow:
 *
 * <pre>{@code
 * File dbFile = new File("/path/to/geoip-range-table");
 * IPConverter converter = IPConverter.getInstance(dbFile);
 * IPConverter.Country country = converter.locateIP("203.0.113.7");
 * // country may be null when the database is missing or the address is unknown.
 * }</pre>
 *
 * <p>Input parsing errors may be reported via {@code IPConverterParseException}.
 */
package network.crypta.clients.http.geoip;
