package network.crypta.clients.http.utils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import network.crypta.config.Option;
import network.crypta.support.MultiValueTable;

/**
 * Parses request scheme/host information for the URI filter proxy from the current request context.
 *
 * <p>This helper is used by the HTTP layer to derive a safe, displayable "base URL" made up of a
 * scheme and a host (optionally including a port). It combines three sources of information:
 * explicit request values ({@code uriScheme}/{@code uriHost}), reverse-proxy forwarding headers
 * (for example {@code X-Forwarded-Proto} and {@code X-Forwarded-Host}), and local node
 * configuration ({@code fProxy.bindTo} and {@code fProxy.port}).
 *
 * <p>The parser is deliberately defensive: it only accepts a small allow-list of protocols, and it
 * only accepts hosts that match the configured bind addresses (with and without the configured
 * port). If a value is missing or not allow-listed, it falls back to a loopback-based default. The
 * returned value is immutable and safe to cache per request. This class is stateless and
 * thread-safe.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> choose a scheme/host pair from inputs and headers.
 *   <li><b>Notable behavior:</b> allow-list protocols and bind-to hosts, with conservative
 *       fallbacks.
 * </ul>
 */
public class UriFilterProxyHeaderParser {
  /** Utility class; this type only exposes static parsing helpers. */
  private UriFilterProxyHeaderParser() {}

  /**
   * Determine a safe scheme and host (with port) for proxy-facing URLs.
   *
   * <p>This method selects the scheme and host primarily from forwarding headers when present, and
   * otherwise falls back to the explicit {@code uriScheme}/{@code uriHost} values. The resulting
   * scheme is restricted to {@code http} or {@code https}. The host is restricted to the configured
   * bind targets (from {@code fProxyBindToConfig}), and also to those same targets with the
   * configured proxy port appended.
   *
   * <p>The method is pure with respect to its inputs: it does not mutate configuration objects or
   * the header table. Callers typically use the returned value to build absolute links or for UI
   * display. When inputs are missing or do not match the allow-list, the result falls back to a
   * loopback address and a default port.
   *
   * @param fProxyPortConfig configuration option providing the proxy port as a string, possibly
   *     empty.
   * @param fProxyBindToConfig configuration option providing comma-separated bind host(s), possibly
   *     empty.
   * @param uriScheme explicit request scheme; if {@code null} or blank, header/default fallback is
   *     used.
   * @param uriHost explicit request host; if {@code null} or blank, header fallback is consulted.
   * @param headers request headers used for proxy forwarding values, especially {@code
   *     x-forwarded-proto}, {@code x-forwarded-host}, and {@code host}.
   * @return an immutable scheme and host pair suitable for building proxy-facing absolute URLs.
   */
  public static SchemeAndHostWithPort parse(
      Option<?> fProxyPortConfig,
      Option<?> fProxyBindToConfig,
      String uriScheme,
      String uriHost,
      MultiValueTable<String, String> headers) {
    Set<String> safeProtocols = new HashSet<>(Arrays.asList("http", "https"));

    List<String> bindToHosts =
        Arrays.stream(fProxyBindToConfig.getValueString().split(","))
            .map(host -> host.contains(":") ? "[" + host + "]" : host)
            .toList();
    String firstBindToHost = bindToHosts.getFirst();
    // set default values
    if (firstBindToHost.isEmpty()) {
      firstBindToHost = "127.0.0.1";
    }
    String port =
        fProxyPortConfig.getValueString().isEmpty() ? "8888" : fProxyPortConfig.getValueString();
    // allow all bindToHosts
    Set<String> safeHosts = new HashSet<>(bindToHosts);
    // also allow bindTo hosts with the fProxyPortConfig added
    safeHosts.addAll(safeHosts.stream().map(host -> host + ":" + port).toList());

    // check uri host and headers
    String schemeFallback = uriScheme != null && !uriScheme.trim().isEmpty() ? uriScheme : "http";
    String protocol =
        headers.containsKey("x-forwarded-proto")
            ? headers.getFirst("x-forwarded-proto")
            : schemeFallback;
    String hostFallback =
        uriHost != null && !uriHost.trim().isEmpty() ? uriHost : headers.getFirst("host");
    String host =
        headers.containsKey("x-forwarded-host")
            ? headers.getFirst("x-forwarded-host")
            : hostFallback;
    // check allow list
    if (!safeProtocols.contains(protocol)) {
      protocol = "http";
    }
    if (!safeHosts.contains(host)) {
      host = firstBindToHost + ":" + port;
    }
    return new SchemeAndHostWithPort(protocol, host);
  }

  /**
   * Value object holding a scheme and a host (optionally including a port).
   *
   * <p>This type is intentionally minimal: it stores the chosen scheme and host as strings and
   * formats them as a URI authority prefix via {@link #toString()}. Instances are immutable and
   * safe to share between threads.
   */
  public static class SchemeAndHostWithPort {
    /** URI scheme component such as {@code http} or {@code https}. */
    private final String scheme;

    /** Host component, optionally including a {@code :port} suffix. */
    private final String host;

    SchemeAndHostWithPort(String scheme, String host) {
      this.scheme = scheme;
      this.host = host;
    }

    /**
     * Render this value as {@code <scheme>://<host>} suitable for prefixing paths.
     *
     * <p>This is a convenience representation for logging and UI display. It does not attempt to
     * normalize, encode, or validate the host beyond what {@link #parse(Option, Option, String,
     * String, MultiValueTable)} already enforces.
     *
     * @return a URI-like string consisting of the scheme, {@code ://}, and the stored host.
     */
    public String toString() {
      return scheme + "://" + host;
    }
  }
}
