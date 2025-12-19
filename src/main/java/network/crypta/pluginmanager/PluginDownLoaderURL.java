package network.crypta.pluginmanager;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import network.crypta.pluginmanager.PluginManager.PluginProgress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Downloads a plugin artifact from a URL-like source string.
 *
 * <p>This downloader is used when a plugin update source is specified as a URL (for example,
 * HTTP(S), FTP, or a {@code file:} URL). It validates the source string, derives a stable plugin
 * name from the URL path, and opens a streaming {@link InputStream} for the content. Callers
 * typically set the source via the shared {@link PluginDownLoader} workflow, invoke {@link
 * #checkSource(String)} to validate/normalize it, and then stream bytes via {@link
 * #getInputStream(PluginProgress)} while reporting progress.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Disables connection-level caching and user interaction for downloads.
 *   <li>Manually follows HTTP redirects with explicit validation of redirect targets and a small
 *       maximum redirect depth.
 *   <li>Treats malformed URLs that look like missing local paths as "not found" rather than a parse
 *       failure, to provide a more actionable error message.
 * </ul>
 *
 * <p>This type does not attempt to provide synchronization. Instances are expected to be used as
 * short-lived, per-download helpers and should not be shared across threads unless the caller
 * provides external coordination.
 */
public class PluginDownLoaderURL extends PluginDownLoader<URL> {
  private static final Logger LOG = LoggerFactory.getLogger(PluginDownLoaderURL.class);

  /**
   * Creates a new downloader instance.
   *
   * <p>The instance holds no internal state beyond what is managed by the {@link PluginDownLoader}
   * base class. Construction performs no I/O; validation occurs in {@link #checkSource(String)} and
   * streaming begins in {@link #getInputStream(PluginProgress)}.
   */
  public PluginDownLoaderURL() {
    // Intentionally empty: this downloader is stateless and relies on the base class for lifecycle
    // and source management; validation and I/O happen in checkSource() and getInputStream().
  }

  /**
   * Parses and validates a plugin download source string as a {@link URL}.
   *
   * <p>The source string is converted via {@link URI#create(String)} and {@link URI#toURL()}, which
   * allows common URL forms while ensuring a consistent conversion path. If the string cannot be
   * parsed as a URL, this method performs a small heuristic check for "looks like a local file path
   * but does not exist" and reports that as a not-found condition. All other parse failures are
   * reported as a {@link PluginNotFoundException} with the original parsing exception attached as
   * the cause.
   *
   * <p>This method is idempotent: calling it repeatedly with the same {@code source} produces the
   * same result or the same exception.
   *
   * <pre>{@code
   * URL url = new PluginDownLoaderURL().checkSource("https://example.invalid/plugin.jar");
   * }</pre>
   *
   * @param source the user-supplied plugin source string to interpret as a URL; must be non-null
   *     and should be a complete URL or URI accepted by {@link URI#create(String)}.
   * @return a {@link URL} representing the validated plugin source; never {@code null} when
   *     returned normally.
   * @throws PluginNotFoundException if the source cannot be parsed as a URL, or if it appears to be
   *     a missing local file path rather than a valid URL.
   */
  @Override
  public URL checkSource(String source) throws PluginNotFoundException {
    try {
      return toUrl(source);
    } catch (MalformedURLException e) {
      // Generate a meaningful error message when file not found falls back to a URL.
      // Maybe it's a file?
      // If we've reached this point then it doesn't exist.
      if (isMissingLocalFile(source)) {
        throw new PluginNotFoundException("File not found: " + source);
      }

      LOG.error("Build plugin URL failed for source={}", source);
      throw new PluginNotFoundException("could not build plugin url for " + source, e);
    }
  }

  private static URL toUrl(String source) throws MalformedURLException {
    try {
      return URI.create(source).toURL();
    } catch (IllegalArgumentException e) {
      MalformedURLException malformed = new MalformedURLException(e.getMessage());
      malformed.initCause(e);
      throw malformed;
    }
  }

  private static boolean isMissingLocalFile(String source) {
    File[] roots = File.listRoots();
    for (File root : roots) {
      if (source.startsWith(root.getName()) && !new File(source).exists()) {
        return true;
      }
    }
    return false;
  }

  @Override
  InputStream getInputStream(PluginProgress progress) throws IOException {
    URLConnection urlConnection = getSource().openConnection();
    urlConnection.setUseCaches(false);
    urlConnection.setAllowUserInteraction(false);
    return openConnectionCheckRedirects(urlConnection);
  }

  @Override
  String getPluginName(String source) {
    String name = source.substring(source.lastIndexOf('/') + 1);
    if (name.endsWith(".url")) {
      name = name.substring(0, name.length() - 4);
    }
    return name;
  }

  @Override
  String getSHA1sum() {
    return null;
  }

  static InputStream openConnectionCheckRedirects(URLConnection c) throws IOException {
    int redirects = 0;
    URLConnection currentConnection = c;

    while (true) {
      disableHttpAutoRedirects(currentConnection);

      // We want to open the input stream before getting headers
      // because getHeaderField() et al swallow IOExceptions.
      InputStream inputStream = currentConnection.getInputStream();

      URL redirectTarget = getRedirectTargetOrNull(currentConnection);
      if (redirectTarget == null) {
        return inputStream;
      }

      closeOnRedirect(inputStream);
      currentConnection = openRedirectConnection(redirectTarget, redirects);
      redirects++;
    }
  }

  private static void disableHttpAutoRedirects(URLConnection connection) {
    if (connection instanceof HttpURLConnection http) {
      http.setInstanceFollowRedirects(false);
    }
  }

  private static URL getRedirectTargetOrNull(URLConnection connection) throws IOException {
    if (!(connection instanceof HttpURLConnection http)) {
      return null;
    }

    int stat = http.getResponseCode();
    if (!isRedirectStatus(stat)) {
      return null;
    }

    try {
      URL target = resolveRedirectTargetOrNull(http);
      if (target == null) {
        throw new SecurityException("illegal URL redirect");
      }
      return target;
    } finally {
      http.disconnect();
    }
  }

  private static boolean isRedirectStatus(int httpStatusCode) {
    return httpStatusCode >= 300
        && httpStatusCode <= 307
        && httpStatusCode != 306
        && httpStatusCode != HttpURLConnection.HTTP_NOT_MODIFIED;
  }

  private static URL resolveRedirectTargetOrNull(HttpURLConnection http) throws IOException {
    URL base = http.getURL();
    String location = http.getHeaderField("Location");
    if (location == null) {
      return null;
    }

    try {
      return base.toURI().resolve(location).toURL();
    } catch (URISyntaxException | IllegalArgumentException e) {
      MalformedURLException malformed = new MalformedURLException(e.getMessage());
      malformed.initCause(e);
      throw malformed;
    }
  }

  private static void closeOnRedirect(InputStream inputStream) throws IOException {
    inputStream.close();
  }

  private static URLConnection openRedirectConnection(URL target, int redirects)
      throws IOException {
    // Redirection should be allowed only for HTTP and HTTPS
    // and should be limited to 5 redirections at most.
    if (!isAllowedRedirectTarget(target) || redirects >= 5) {
      throw new SecurityException("illegal URL redirect");
    }
    return target.openConnection();
  }

  private static boolean isAllowedRedirectTarget(URL target) {
    String protocol = target.getProtocol();
    return protocol.equals("http") || protocol.equals("https") || protocol.equals("ftp");
  }

  @Override
  void tryCancel() {
    // Do nothing, not supported.
  }
}
