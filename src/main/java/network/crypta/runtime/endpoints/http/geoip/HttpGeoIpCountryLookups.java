package network.crypta.runtime.endpoints.http.geoip;

import java.io.File;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.runtime.admin.geoip.GeoIpCountryLookup;

/**
 * Factory methods for HTTP-backed GeoIP country lookups.
 *
 * <p>This utility keeps the file-selection logic for the HTTP GeoIP bridge inside the bridge
 * package. Runtime-admin code can ask for a {@link GeoIpCountryLookup} without depending on the
 * concrete {@link HttpGeoIpCountryLookup} constructor or on the daemon's GeoIP database path
 * lookup. The returned lookup preserves the existing behavior of the HTTP bridge: it reads the
 * current IPv4-to-country database for the supplied node and delegates country resolution to the
 * legacy HTTP adapter.
 *
 * <p>The class intentionally owns only the last piece of wiring that still depends on {@link
 * NodeFile}. It does not cache database handles, inspect the selected file, or reinterpret the
 * lookup results. Callers therefore keep the same best-effort GeoIP behavior that the Connections
 * page already used, while runtime-admin depends only on its own lookup seam plus this narrow
 * bridge-owned entry point.
 */
public final class HttpGeoIpCountryLookups {
  private HttpGeoIpCountryLookups() {}

  /**
   * Creates a GeoIP lookup backed by the HTTP bridge for the supplied node.
   *
   * <p>The method resolves the current IPv4-to-country database file from the node and uses it to
   * construct the existing HTTP GeoIP adapter. It does not cache the resulting lookup, interpret
   * the database contents, or change how country or flag resolution works. Repeated calls therefore
   * continue to create fresh bridge instances in the same way the old runtime-admin wiring did,
   * leaving database selection and singleton behavior to the underlying HTTP GeoIP implementation.
   *
   * @param node live daemon node used to locate the current IPv4-to-country database file
   * @return GeoIP lookup that resolves countries through the existing HTTP bridge for {@code node}
   */
  public static GeoIpCountryLookup forNode(Node node) {
    File dbFile = NodeFile.IPV4_TO_COUNTRY.getFile(node);
    return new HttpGeoIpCountryLookup(dbFile);
  }
}
