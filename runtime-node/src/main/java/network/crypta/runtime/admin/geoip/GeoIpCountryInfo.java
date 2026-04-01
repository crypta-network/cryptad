package network.crypta.runtime.admin.geoip;

import java.util.Objects;

/**
 * Immutable country metadata used by the runtime-owned GeoIP seam.
 *
 * <p>This record carries the small amount of information that the legacy connections page needs
 * after resolving a peer address against the GeoIP database. Runtime-admin code only needs a
 * display label for tooltip text and an optional fully qualified static-resource URL for the flag
 * icon. Keeping that data in a detached record avoids any direct dependency on the HTTP GeoIP
 * implementation while preserving the exact HTML attributes that the legacy page already emits.
 *
 * <p>Instances are immutable and thread-safe. Callers may cache or pass them across runtime and
 * endpoint boundaries without coordinating with the underlying GeoIP lookup implementation.
 *
 * @param displayName non-null UI label for the located country or region
 * @param staticFlagUrl full static-resource URL for the flag icon, or {@code null} when absent
 */
public record GeoIpCountryInfo(String displayName, String staticFlagUrl) {
  /**
   * Creates one detached GeoIP country description for legacy page rendering.
   *
   * <p>The display name is required because the Connections page uses it directly for flag tooltip
   * text. The flag URL may be absent when the lookup resolves a country or region that does not
   * have a bundled static icon.
   *
   * @param displayName non-null country or region label suitable for direct UI display
   * @param staticFlagUrl full static-resource URL for the country flag, or {@code null} if absent
   * @throws NullPointerException if {@code displayName} is {@code null}
   */
  public GeoIpCountryInfo {
    Objects.requireNonNull(displayName);
  }
}
