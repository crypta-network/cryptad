// (c) Copyright 2000 Justin F. Chapweske
// (c) Copyright 2000 Ry4an C. Brase

package com.onionnetworks.util;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.logging.Logger;

/**
 * Networking utility methods for expanding host-based URLs into IP-literal variants.
 *
 * <p>NetUtil centralizes helpers that convert a hostname within a URL into concrete IP addresses
 * supplied by the local resolver. The class is entirely stateless and thread-safe, making it safe
 * to reuse across concurrent request flows or diagnostic tooling. Typical usage is to parse a URL
 * once, pass it to the provided method, and iterate over the resulting list when balancing or
 * retrying requests against every DNS record returned for that host. When the input lacks a host,
 * the original URL is returned untouched to avoid surprising {@link java.net.UnknownHostException}
 * failures.
 *
 * <p>The returned URLs preserve user info, port, path, query parameters, and fragment identifiers
 * so that callers can forward them directly to HTTP clients or logging pipelines without additional
 * reconstruction. Because the class never caches resolver results, each invocation reflects the
 * current system DNS state and any rotation policies configured on the host.
 *
 * <ul>
 *   <li>Stateless static API; no construction or configuration required.
 *   <li>Preserves caller-specified URL components verbatim while substituting the host.
 *   <li>Falls back to the original URL when the host is null or empty.
 * </ul>
 */
public class NetUtil {

  private static final Logger LOGGER = Logger.getLogger(NetUtil.class.getName());

  private NetUtil() {}

  /**
   * Returns IP-literal variants of the provided URL for each DNS address.
   *
   * <p>The method calls {@link InetAddress#getAllByName(String)} for the host portion of the
   * supplied URL, substitutes each textual address into the host field, and preserves protocol,
   * user info, port, path, query, and fragment components. When the host is null or empty, the
   * original URL is returned in a single-element array to avoid resolver failures. The order of the
   * returned URLs mirrors the resolver output, so callers can respect the system's preferred
   * address ordering.
   *
   * @param url non-null URL whose hostname should be expanded into concrete IP addresses; other
   *     components remain unchanged.
   * @return array of URLs with IP literal hosts; length matches the number of resolved addresses or
   *     one when no host is provided; each element is independent of the input instance.
   * @throws IOException if DNS resolution fails or a resolved address cannot be converted back into
   *     a valid URL.
   * @author Ry4an Brase (ry4an@onionnetworks.com)
   */
  public static URL[] getIpUrlsByName(URL url) throws IOException {
    String userInfo = url.getUserInfo();
    String protocol = url.getProtocol();
    String host = url.getHost();
    String path = url.getPath();
    String query = url.getQuery();
    String ref = url.getRef();
    int port = url.getPort();

    if (host == null || host.isEmpty()) { // avoids UnknownHostException
      return new URL[] {url};
    }

    InetAddress[] addrs = InetAddress.getAllByName(host);
    URL[] retval = new URL[addrs.length];
    for (int i = 0; i < addrs.length; i++) {
      try {
        URI uri =
            new URI(
                protocol,
                userInfo,
                addrs[i].getHostAddress(),
                port, // -1 is okay
                path,
                query,
                ref);
        retval[i] = uri.toURL();
      } catch (URISyntaxException e) {
        throw new IOException("Unable to build URL for host " + host, e);
      }
    }

    return retval;
  }

  /**
   * Demonstrates resolving each provided URL into IP-specific variants and logs the results.
   *
   * <p>When no arguments are supplied, the method exercises several representative URLs covering
   * credentials, fragments, and missing hosts so the output can be inspected manually. Each input
   * string is parsed into a {@link URI}, converted to a {@link URL}, and passed to {@link
   * #getIpUrlsByName(URL)}; the resulting URLs are emitted via the class logger. This entry point
   * is intended for ad hoc testing and will terminate on the first parsing or resolution failure
   * rather than attempting recovery.
   *
   * @param args optional URL strings to resolve; when empty, built-in examples are used to showcase
   *     common edge cases.
   */
  static void main(String[] args) throws IOException {

    if (args.length == 0) {
      args =
          new String[] {

            // with ref
            "http://cnn.com:14234/dir/foobar?param&adsf=2312#anc",

            // user w/ no pass
            "http://user@cnn.com:14234/dir/foobar?param&adsf=2312#anc",

            // no user or pass
            "http://cnn.com:14234/dir/foobar?param&adsf=2312#anc",

            // no host
            "http:/dir/foobar?param&adsf=2312#anc",

            // bare bones
            "http://cnn.com/",

            // IP for the host makes this useless but harmless
            "http://192.0.2.4:14234/dir/foobar",
          };
    }

    for (final String currentArg : args) {
      LOGGER.info(() -> "----------[ Matches for: " + currentArg);
      URI example = URI.create(currentArg);
      URL[] urls = getIpUrlsByName(example.toURL());

      for (URL url : urls) {
        LOGGER.info(url::toExternalForm);
      }
    }
  }
}
