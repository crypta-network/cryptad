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
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * Fetches catalog properties and signature sidecars from local files, HTTP(S), or Crypta content.
 *
 * <p>The fetcher uses finite JDK {@link HttpClient} timeouts, disables automatic redirects, and
 * enforces separate byte limits for catalog and signature payloads. Plain HTTP is accepted only for
 * loopback hosts by the source validation layer; non-local remote catalogs must use HTTPS.
 *
 * <p>A source points at {@code cryptad-app-catalog.properties}; the matching signature URI is
 * resolved as its sibling {@code cryptad-app-catalog.signature}, except for CHK-backed Crypta
 * sources that must declare an explicit immutable signature companion. When a Crypta catalog fetch
 * reports a resolved USK or SSK key, the signature sidecar is fetched from the matching resolved
 * sibling so both sidecars come from the same edition. This class fetches bytes only. It
 * deliberately does not parse or verify the sidecars so callers can preserve the exact catalog
 * bytes for signature verification and persistence.
 */
public final class AppCatalogFetcher {
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
  private static final String CATALOG_PROPERTIES_DESCRIPTION = "catalog properties";
  private static final String CATALOG_SIGNATURE_DESCRIPTION = "catalog signature";

  private final HttpClient httpClient;
  private final ContentFetchPort contentFetchPort;

  /**
   * Creates a fetcher with the default no-redirect JDK HTTP client.
   *
   * <p>The default client uses a ten-second connect timeout and rejects redirects. Per-request
   * timeouts still apply to catalog and signature reads, which keeps a stalled remote source from
   * blocking catalog operations indefinitely.
   */
  public AppCatalogFetcher() {
    this(defaultHttpClient(), null);
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
    this(httpClient, null);
  }

  /**
   * Creates a fetcher with the default HTTP client and a Crypta content fetch collaborator.
   *
   * <p>The runtime SPI port is used only for {@code crypta:} catalog sources. Existing file, HTTPS,
   * and loopback HTTP sources continue to use their original fetch paths.
   *
   * @param contentFetchPort runtime content fetch port for {@code crypta:} sources
   */
  public AppCatalogFetcher(ContentFetchPort contentFetchPort) {
    this(defaultHttpClient(), contentFetchPort);
  }

  /**
   * Creates a fetcher with explicit HTTP and optional Crypta content fetch collaborators.
   *
   * <p>The content fetch port is optional so tests and embeddings that do not support Crypta
   * catalog sources can keep using the same fetcher. Attempting to fetch a {@code crypta:} source
   * without the port fails closed with {@code catalog_fetch_unavailable}.
   *
   * @param httpClient client used for HTTP and HTTPS catalog retrieval
   * @param contentFetchPort runtime content fetch port for {@code crypta:} sources, or {@code null}
   */
  public AppCatalogFetcher(HttpClient httpClient, ContentFetchPort contentFetchPort) {
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    this.contentFetchPort = contentFetchPort;
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
    if (checkedSource.kind() == AppCatalogSourceKind.CRYPTA) {
      CryptaCatalogUri cryptaUri = checkedSource.cryptaCatalogUri();
      FetchedBytes catalogBytes =
          fetchCryptaBytes(
              cryptaUri.catalogFetchKey(),
              AppCatalogSidecars.MAX_CATALOG_BYTES,
              CATALOG_PROPERTIES_DESCRIPTION);
      FetchedBytes signatureBytes =
          fetchCryptaBytes(
              cryptaUri.signatureFetchKeyForResolvedCatalog(catalogBytes.resolvedUri()),
              AppCatalogSidecars.MAX_SIGNATURE_BYTES,
              CATALOG_SIGNATURE_DESCRIPTION);
      return new FetchedCatalog(
          catalogBytes.bytes(), signatureBytes.bytes(), catalogBytes.resolvedUri());
    }
    return new FetchedCatalog(
        fetchBytes(
            checkedSource.uri(),
            AppCatalogSidecars.MAX_CATALOG_BYTES,
            CATALOG_PROPERTIES_DESCRIPTION),
        fetchBytes(
            checkedSource.signatureUri(),
            AppCatalogSidecars.MAX_SIGNATURE_BYTES,
            CATALOG_SIGNATURE_DESCRIPTION));
  }

  private byte[] fetchBytes(URI uri, long maxBytes, String description) throws IOException {
    String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
    if ("file".equals(scheme)) {
      return AppCatalogSidecars.readRequiredBytes(
          Path.of(uri), maxBytes, description, AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    }
    return fetchRemoteBytes(uri, maxBytes, description);
  }

  private FetchedBytes fetchCryptaBytes(String fetchKey, long maxBytes, String description) {
    ContentFetchPort port = requireContentFetchPort();
    try {
      BoundedContentFetchResult result =
          port.fetchContent(
              new BoundedContentFetchRequest(fetchKey, maxBytes, REQUEST_TIMEOUT, description));
      byte[] bytes = result.bytes();
      if (bytes.length > maxBytes) {
        throw new AppCatalogException(
            AppCatalogSidecars.CATALOG_FETCH_FAILED, description + " exceeds the allowed size");
      }
      return new FetchedBytes(bytes, result.resolvedUri());
    } catch (ContentFetchException exception) {
      throw new AppCatalogException(
          mapContentFetchErrorCode(exception, description),
          "failed to fetch " + description,
          exception);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "invalid Crypta catalog fetch request",
          exception);
    }
  }

  private static HttpClient defaultHttpClient() {
    return HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
  }

  private ContentFetchPort requireContentFetchPort() {
    if (contentFetchPort == null) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_FETCH_UNAVAILABLE,
          "Crypta catalog fetch runtime is unavailable");
    }
    return contentFetchPort;
  }

  private static String mapContentFetchErrorCode(
      ContentFetchException exception, String description) {
    String errorCode = exception.errorCode();
    if (ContentFetchException.INVALID_CATALOG_SOURCE.equals(errorCode)) {
      return AppCatalogSidecars.INVALID_CATALOG_SOURCE;
    }
    if (AppCatalogSidecars.CATALOG_FETCH_UNAVAILABLE.equals(errorCode)) {
      return AppCatalogSidecars.CATALOG_FETCH_UNAVAILABLE;
    }
    if (CATALOG_SIGNATURE_DESCRIPTION.equals(description)
        && AppCatalogSidecars.CATALOG_SIGNATURE_MISSING.equals(errorCode)) {
      return AppCatalogSidecars.CATALOG_SIGNATURE_MISSING;
    }
    return AppCatalogSidecars.CATALOG_FETCH_FAILED;
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

  @SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
  private static final class FetchedBytes {
    private final byte[] bytes;
    private final String resolvedUri;

    private FetchedBytes(byte[] bytes, String resolvedUri) {
      this.bytes = Objects.requireNonNull(bytes, "bytes").clone();
      this.resolvedUri = resolvedUri;
    }

    private byte[] bytes() {
      return bytes.clone();
    }

    private String resolvedUri() {
      return resolvedUri;
    }
  }
}
