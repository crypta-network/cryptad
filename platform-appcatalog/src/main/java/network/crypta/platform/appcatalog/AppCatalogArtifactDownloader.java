package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Downloads one catalog artifact into a host-owned temporary file.
 *
 * <p>The downloader never writes directly into an installed app tree. It streams the artifact to a
 * caller-supplied scratch directory, enforces the catalog-declared byte count and the absolute
 * safety cap, and verifies the catalog-declared SHA-256 digest before returning the temporary ZIP
 * path to the extractor.
 *
 * <p>Both local {@code file:} artifacts and remote HTTP(S) artifacts use the same size and digest
 * gate. Remote requests use finite JDK {@link HttpClient} timeouts, do not follow redirects, and
 * treat transport failures as catalog artifact failures rather than internal server errors. The
 * caller owns the scratch directory and is expected to delete it after AppHost has copied the
 * staged bundle into its managed installation tree.
 */
public final class AppCatalogArtifactDownloader {
  private static final Duration REQUEST_TIMEOUT = Duration.ofMinutes(2);

  private final HttpClient httpClient;
  private final ArtifactCleaner artifactCleaner;

  /**
   * Creates a downloader backed by the default no-redirect JDK HTTP client.
   *
   * <p>The default client uses a ten-second connect timeout and rejects redirects. Source policy
   * has already restricted artifact URIs to local files, HTTPS, or loopback HTTP, so this
   * constructor is appropriate for normal runtime composition.
   */
  public AppCatalogArtifactDownloader() {
    this(
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build());
  }

  /**
   * Creates a downloader with an explicit HTTP client.
   *
   * <p>This overload exists for tests and controlled embeddings that need a custom transport. The
   * downloader still sets per-request timeouts and performs response validation; callers should
   * keep redirect handling disabled unless they also enforce equivalent redirect policy outside
   * this class.
   *
   * @param httpClient client used for HTTP and HTTPS artifact retrieval
   */
  public AppCatalogArtifactDownloader(HttpClient httpClient) {
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    artifactCleaner = Files::deleteIfExists;
  }

  AppCatalogArtifactDownloader(HttpClient httpClient, ArtifactCleaner artifactCleaner) {
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    this.artifactCleaner = Objects.requireNonNull(artifactCleaner, "artifactCleaner");
  }

  /**
   * Downloads and verifies one entry artifact.
   *
   * <p>The returned path names a temporary ZIP in {@code scratchDirectory}. If downloading or
   * verification fails, the partially written file is deleted before the original failure is
   * rethrown. A successful return means the file byte count equals {@link
   * AppCatalogEntry#bundleSizeBytes()} and its SHA-256 digest equals {@link
   * AppCatalogEntry#bundleSha256()}.
   *
   * @param entry catalog entry whose ZIP artifact should be retrieved and checked
   * @param scratchDirectory host-owned temporary directory for the artifact file
   * @return path to the verified artifact ZIP inside the scratch directory
   * @throws IOException if scratch directory creation or temporary-file deletion fails
   */
  public Path download(AppCatalogEntry entry, Path scratchDirectory) throws IOException {
    AppCatalogEntry checkedEntry = Objects.requireNonNull(entry, "entry");
    Path scratchRoot = Objects.requireNonNull(scratchDirectory, "scratchDirectory");
    Files.createDirectories(scratchRoot);
    Path artifact = Files.createTempFile(scratchRoot, "catalog-artifact-", ".zip");
    try {
      copyArtifact(checkedEntry, artifact);
      return artifact;
    } catch (RuntimeException exception) {
      deleteArtifactAfterFailure(artifact, exception);
      throw exception;
    }
  }

  private void deleteArtifactAfterFailure(Path artifact, RuntimeException originalException) {
    try {
      artifactCleaner.deleteIfExists(artifact);
    } catch (IOException cleanupException) {
      originalException.addSuppressed(cleanupException);
    }
  }

  private void copyArtifact(AppCatalogEntry entry, Path destination) {
    URI uri = entry.bundleUri();
    String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
    if ("file".equals(scheme)) {
      copyLocalArtifact(entry, uri, destination);
      return;
    }
    copyRemoteArtifact(entry, destination);
  }

  private static void copyLocalArtifact(AppCatalogEntry entry, URI uri, Path destination) {
    try {
      copyAndVerify(entry, Files.newInputStream(Path.of(uri)), destination);
    } catch (IOException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED,
          "failed to read local artifact for app: " + entry.appId(),
          exception);
    }
  }

  private void copyRemoteArtifact(AppCatalogEntry entry, Path destination) {
    HttpRequest request =
        HttpRequest.newBuilder(entry.bundleUri())
            .timeout(REQUEST_TIMEOUT)
            .header("Accept", "application/zip, application/octet-stream")
            .GET()
            .build();
    HttpResponse<InputStream> response;
    try {
      response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
    } catch (IOException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED,
          "failed to download artifact for app: " + entry.appId(),
          exception);
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED,
          "interrupted while downloading artifact for app: " + entry.appId(),
          exception);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED,
          "invalid artifact URI for app: " + entry.appId(),
          exception);
    }
    try (InputStream input = response.body()) {
      if (response.statusCode() != 200) {
        throw new AppCatalogException(
            AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED,
            "failed to download artifact for app "
                + entry.appId()
                + ": HTTP "
                + response.statusCode());
      }
      validateContentLength(entry, response);
      copyAndVerify(entry, input, destination);
    } catch (IOException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED,
          "failed to read artifact for app: " + entry.appId(),
          exception);
    }
  }

  private static void validateContentLength(
      AppCatalogEntry entry, HttpResponse<InputStream> response) {
    OptionalLong contentLength;
    try {
      contentLength = response.headers().firstValueAsLong("content-length");
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED,
          "artifact Content-Length is invalid for app: " + entry.appId(),
          exception);
    }
    if (contentLength.isPresent()) {
      rejectWrongContentLength(entry, contentLength.getAsLong());
    }
  }

  private static void rejectWrongContentLength(AppCatalogEntry entry, long contentLength) {
    if (contentLength != entry.bundleSizeBytes()) {
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH,
          "artifact size does not match catalog entry for app: " + entry.appId());
    }
  }

  private static void copyAndVerify(AppCatalogEntry entry, InputStream input, Path destination)
      throws IOException {
    MessageDigest digest = AppCatalogSidecars.newArtifactSha256Digest();
    long bytesCopied = 0L;
    byte[] buffer = new byte[64 * 1024];
    try (InputStream in = input;
        OutputStream out = Files.newOutputStream(destination)) {
      int bytesRead;
      while ((bytesRead = in.read(buffer)) >= 0) {
        if (bytesRead == 0) {
          continue;
        }
        bytesCopied += bytesRead;
        if (bytesCopied > entry.bundleSizeBytes()
            || bytesCopied > AppCatalogSidecars.MAX_ARTIFACT_BYTES) {
          throw new AppCatalogException(
              AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH,
              "artifact size exceeds catalog entry for app: " + entry.appId());
        }
        digest.update(buffer, 0, bytesRead);
        out.write(buffer, 0, bytesRead);
      }
    }
    if (bytesCopied != entry.bundleSizeBytes()) {
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH,
          "artifact size does not match catalog entry for app: " + entry.appId());
    }
    String actualSha256 = AppCatalogSidecars.lowercaseHex(digest.digest());
    if (!entry.bundleSha256().equals(actualSha256)) {
      throw new AppCatalogException(
          AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH,
          "artifact digest does not match catalog entry for app: " + entry.appId());
    }
  }

  @FunctionalInterface
  interface ArtifactCleaner {
    boolean deleteIfExists(Path artifact) throws IOException;
  }
}
