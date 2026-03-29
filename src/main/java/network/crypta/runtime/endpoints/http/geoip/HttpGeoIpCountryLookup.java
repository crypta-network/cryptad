package network.crypta.runtime.endpoints.http.geoip;

import java.io.File;
import java.util.Objects;
import network.crypta.clients.http.geoip.IPConverter.Country;
import network.crypta.clients.http.geoip.IPConverter;
import network.crypta.runtime.admin.geoip.GeoIpCountryInfo;
import network.crypta.runtime.admin.geoip.GeoIpCountryLookup;
import network.crypta.support.http.StaticResourcePaths;

/**
 * HTTP-backed adapter from the runtime GeoIP seam to the legacy GeoIP database lookup.
 *
 * <p>This bridge keeps the {@code IPConverter} dependency out of {@code runtime.admin} while
 * preserving the existing country-name and flag-path behavior used by the legacy connections page.
 * It remains intentionally small: the runtime-owned seam only needs a detached country DTO, while
 * this adapter handles the translation from the legacy singleton lookup and HTTP static-resource
 * conventions.
 *
 * <p>Instances are inexpensive and immutable. They do not keep their own GeoIP cache; instead, they
 * delegate to {@link IPConverter#getInstance(File)}, which preserves the historical singleton and
 * file-switching behavior already used by the legacy HTTP code.
 */
public final class HttpGeoIpCountryLookup implements GeoIpCountryLookup {
  private final File dbFile;

  /**
   * Creates an HTTP-backed GeoIP lookup bound to one GeoIP database file.
   *
   * <p>The file is passed through to the legacy {@link IPConverter} singleton on each lookup. That
   * preserves the current behavior where swapping to a different database file transparently
   * replaces the singleton instance without introducing an additional bridge-local state.
   *
   * @param dbFile GeoIP database file consumed by the legacy HTTP {@code IPConverter}
   * @throws NullPointerException if {@code dbFile} is {@code null}
   */
  public HttpGeoIpCountryLookup(File dbFile) {
    this.dbFile = Objects.requireNonNull(dbFile);
  }

  /**
   * Resolves raw address bytes through the legacy HTTP GeoIP lookup and adapts the result.
   *
   * <p>When the underlying {@link IPConverter} finds a matching country or region, this method
   * copies the display name into a detached runtime-owned DTO and expands any relative flag path
   * into the full static-resource URL expected by the legacy connections-page HTML. If the lookup
   * fails or the country has no bundled flag icon, the returned DTO either omits the flag URL or
   * the method returns {@code null}, matching the existing best-effort behavior.
   *
   * @param ipAddressBytes raw IPv4 or supported IPv6 bytes passed from runtime-admin code
   * @return detached country metadata, or {@code null} when the address cannot be resolved
   */
  @Override
  public GeoIpCountryInfo locate(byte[] ipAddressBytes) {
    Country country = IPConverter.getInstance(dbFile).locateIP(ipAddressBytes);
    if (country == null) {
      return null;
    }

    String flagPath = country.getFlagIconPath();
    String staticFlagUrl = flagPath == null ? null : StaticResourcePaths.ROOT_URL + flagPath;
    return new GeoIpCountryInfo(country.getName(), staticFlagUrl);
  }
}
