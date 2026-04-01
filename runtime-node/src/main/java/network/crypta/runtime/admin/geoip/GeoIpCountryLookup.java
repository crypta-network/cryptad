package network.crypta.runtime.admin.geoip;

/**
 * Runtime-owned GeoIP lookup seam for legacy admin pages.
 *
 * <p>This interface gives {@code network.crypta.runtime.admin} a narrow, detached view of the GeoIP
 * functionality still implemented on the HTTP side of the legacy stack. The Connections page only
 * needs a best-effort country lookup keyed by raw peer-address bytes, so the seam exposes a single
 * method and returns a small immutable DTO instead of leaking {@code IPConverter} types into
 * runtime-admin code.
 *
 * <p>Implementations may perform file-backed lookups, cache results, or normalize IPv4 and IPv6
 * address forms internally. Callers should treat the seam as the best effort and be prepared for a
 * {@code null} result when the address cannot be resolved or when no country metadata is available.
 */
public interface GeoIpCountryLookup {
  /**
   * Resolves an IP address into detached country metadata for the legacy connections page.
   *
   * <p>The supplied bytes typically come from {@code PeerNodeStatus#getPeerAddressBytes()} and may
   * represent IPv4 or an implementation-supported IPv6 form. Implementations return a detached
   * value object when a lookup succeeds, or {@code null} when the address is unavailable,
   * unsupported, or not present in the active GeoIP database.
   *
   * @param ipAddressBytes raw peer-address bytes supplied by the legacy peer-status view
   * @return detached country metadata for UI rendering, or {@code null} when no mapping exists
   */
  GeoIpCountryInfo locate(byte[] ipAddressBytes);
}
