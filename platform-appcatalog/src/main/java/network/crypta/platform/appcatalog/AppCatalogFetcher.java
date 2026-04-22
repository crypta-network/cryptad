package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

/**
 * Fetches catalog properties and signature sidecars from local files or HTTP(S).
 *
 * <p>The fetcher uses finite JDK {@link HttpClient} timeouts, disables automatic redirects, and
 * enforces separate byte limits for catalog and signature payloads. Plain HTTP is accepted only for
 * loopback hosts by the source validation layer; non-local remote catalogs must use HTTPS.
 *
 * <p>A source points at {@code cryptad-app-catalog.properties}; the matching signature URI is
 * resolved as its sibling {@code cryptad-app-catalog.signature}. This class fetches bytes only. It
 * deliberately does not parse or verify the sidecars so callers can preserve the exact catalog
 * bytes for signature verification and persistence.
 */
public final class AppCatalogFetcher {
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

  private final HttpClient httpClient;

  /**
   * Creates a fetcher with the default no-redirect JDK HTTP client.
   *
   * <p>The default client uses a ten-second connect timeout and rejects redirects. Per-request
   * timeouts still apply to catalog and signature reads, which keeps a stalled remote source from
   * blocking catalog operations indefinitely.
   */
  public AppCatalogFetcher() {
    this(
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build());
  }

  /**
   * Creates a fetcher with an explicit HTTP client.
   *
   * <p>This overload is mainly for deterministic tests and embeddings with already configured
   * transport. The caller remains responsible for choosing a client whose redirect and proxy
   * behavior matches the catalog source policy.
   *
   * @param httpClient client used for HTTP and HTTPS catalog retrieval
   */
  public AppCatalogFetcher(HttpClient httpClient) {
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
  }

  /**
   * Fetches catalog properties and signature bytes for one source.
   *
   * <p>For local sources, both sidecars are read from the filesystem with symbolic-link rejection
   * and size checks. For remote sources, each sidecar must return HTTP 200 and fit within its
   * configured byte cap. Transport and response failures are reported as {@code
   * invalid_catalog_source} so API callers can distinguish bad or unavailable sources from internal
   * node faults.
   *
   * @param source validated catalog source descriptor
   * @return fetched catalog sidecar bytes, defensively copied by {@link FetchedCatalog}
   * @throws IOException if filesystem reads fail while checking local catalog sidecars
   */
  public FetchedCatalog fetch(AppCatalogSource source) throws IOException {
    AppCatalogSource checkedSource = Objects.requireNonNull(source, "source");
    return new FetchedCatalog(
        fetchBytes(checkedSource.uri(), AppCatalogSidecars.MAX_CATALOG_BYTES, "catalog properties"),
        fetchBytes(
            checkedSource.signatureUri(),
            AppCatalogSidecars.MAX_SIGNATURE_BYTES,
            "catalog signature"));
  }

  private byte[] fetchBytes(URI uri, long maxBytes, String description) throws IOException {
    String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
    if ("file".equals(scheme)) {
      return AppCatalogSidecars.readRequiredBytes(
          Path.of(uri), maxBytes, description, AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    }
    return fetchRemoteBytes(uri, maxBytes, description);
  }

  private byte[] fetchRemoteBytes(URI uri, long maxBytes, String description) {
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .timeout(REQUEST_TIMEOUT)
            .header("Accept", "text/plain, application/octet-stream")
            .GET()
            .build();
    HttpResponse<InputStream> response;
    try {
      response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
    } catch (IOException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "failed to fetch " + description, exception);
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "interrupted while fetching " + description,
          exception);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "invalid catalog fetch URI", exception);
    }
    try (InputStream input = response.body()) {
      if (response.statusCode() != 200) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_SOURCE,
            "failed to fetch " + description + ": HTTP " + response.statusCode());
      }
      return AppCatalogSidecars.readLimitedCatalogSource(input, maxBytes, description);
    } catch (IOException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE, "failed to read " + description, exception);
    }
  }
}
