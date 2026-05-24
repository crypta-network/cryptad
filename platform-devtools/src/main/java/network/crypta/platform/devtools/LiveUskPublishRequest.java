package network.crypta.platform.devtools;

import java.net.URI;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Secret-bearing request passed only to the live USK insertion adapter.
 *
 * <p>This value contains the private insert URI, form password, and retained staging directory
 * needed for the localhost daemon call. It deliberately overrides {@link #toString()} so accidental
 * diagnostics cannot expose those values. Publication summaries must be built from {@code
 * LiveUskPublishResponse} and {@code LiveUskPublicationResult}, not from this request.
 *
 * <p>The request also carries exact catalog and signature bytes for optional post-publish
 * verification. Those arrays are defensively copied on construction and access so a publisher
 * cannot accidentally mutate the service's validation snapshot. The class is package-local because
 * it is an implementation boundary between the CLI service and the insertion backend, not a stable
 * public API.
 */
final class LiveUskPublishRequest {
  private final URI nodeBaseUrl;
  private final String formPassword;
  private final String privateInsertUri;
  private final Path stagingDirectory;
  private final String identifier;
  private final String publicCatalogSource;
  private final String publicSignatureSource;
  private final byte[] catalogBytes;
  private final byte[] signatureBytes;
  private final boolean verifyLiveFetch;

  private LiveUskPublishRequest(Builder builder) {
    this.nodeBaseUrl = Objects.requireNonNull(builder.nodeBaseUrl, "nodeBaseUrl");
    this.formPassword = Objects.requireNonNull(builder.formPassword, "formPassword");
    this.privateInsertUri = Objects.requireNonNull(builder.privateInsertUri, "privateInsertUri");
    this.stagingDirectory = Objects.requireNonNull(builder.stagingDirectory, "stagingDirectory");
    this.identifier = Objects.requireNonNull(builder.identifier, "identifier");
    this.publicCatalogSource =
        Objects.requireNonNull(builder.publicCatalogSource, "publicCatalogSource");
    this.publicSignatureSource =
        Objects.requireNonNull(builder.publicSignatureSource, "publicSignatureSource");
    this.catalogBytes = Objects.requireNonNull(builder.catalogBytes, "catalogBytes").clone();
    this.signatureBytes = Objects.requireNonNull(builder.signatureBytes, "signatureBytes").clone();
    this.verifyLiveFetch = builder.verifyLiveFetch;
  }

  static Builder builder() {
    return new Builder();
  }

  URI nodeBaseUrl() {
    return nodeBaseUrl;
  }

  String formPassword() {
    return formPassword;
  }

  String privateInsertUri() {
    return privateInsertUri;
  }

  Path stagingDirectory() {
    return stagingDirectory;
  }

  String identifier() {
    return identifier;
  }

  String publicCatalogSource() {
    return publicCatalogSource;
  }

  String publicSignatureSource() {
    return publicSignatureSource;
  }

  /**
   * Returns a copy of the verified catalog bytes.
   *
   * <p>The returned array can be used for live fetch comparison or tests without exposing the
   * request's internal storage to mutation.
   *
   * @return defensive copy of the catalog properties bytes
   */
  byte[] catalogBytes() {
    return catalogBytes.clone();
  }

  /**
   * Returns a copy of the verified signature sidecar bytes.
   *
   * <p>The returned array is the exact sidecar content validated before queueing the live insert,
   * copied so callers cannot alter the request after construction.
   *
   * @return defensive copy of the catalog signature bytes
   */
  byte[] signatureBytes() {
    return signatureBytes.clone();
  }

  boolean verifyLiveFetch() {
    return verifyLiveFetch;
  }

  @Override
  public String toString() {
    return "LiveUskPublishRequest[redacted]";
  }

  /**
   * Builder for the secret-bearing live publish adapter request.
   *
   * <p>The builder keeps construction readable at call sites while the resulting request remains an
   * immutable, redacted value. Byte arrays are copied when accepted and again when the request is
   * built so a caller cannot mutate the exact sidecar bytes used for live fetch verification.
   */
  static final class Builder {
    private URI nodeBaseUrl;
    private String formPassword;
    private String privateInsertUri;
    private Path stagingDirectory;
    private String identifier;
    private String publicCatalogSource;
    private String publicSignatureSource;
    private byte[] catalogBytes;
    private byte[] signatureBytes;
    private boolean verifyLiveFetch;

    Builder nodeBaseUrl(URI nodeBaseUrl) {
      this.nodeBaseUrl = Objects.requireNonNull(nodeBaseUrl, "nodeBaseUrl");
      return this;
    }

    Builder formPassword(String formPassword) {
      this.formPassword = Objects.requireNonNull(formPassword, "formPassword");
      return this;
    }

    Builder privateInsertUri(String privateInsertUri) {
      this.privateInsertUri = Objects.requireNonNull(privateInsertUri, "privateInsertUri");
      return this;
    }

    Builder stagingDirectory(Path stagingDirectory) {
      this.stagingDirectory = Objects.requireNonNull(stagingDirectory, "stagingDirectory");
      return this;
    }

    Builder identifier(String identifier) {
      this.identifier = Objects.requireNonNull(identifier, "identifier");
      return this;
    }

    Builder publicCatalogSource(String publicCatalogSource) {
      this.publicCatalogSource = Objects.requireNonNull(publicCatalogSource, "publicCatalogSource");
      return this;
    }

    Builder publicSignatureSource(String publicSignatureSource) {
      this.publicSignatureSource =
          Objects.requireNonNull(publicSignatureSource, "publicSignatureSource");
      return this;
    }

    Builder catalogBytes(byte[] catalogBytes) {
      this.catalogBytes = Objects.requireNonNull(catalogBytes, "catalogBytes").clone();
      return this;
    }

    Builder signatureBytes(byte[] signatureBytes) {
      this.signatureBytes = Objects.requireNonNull(signatureBytes, "signatureBytes").clone();
      return this;
    }

    Builder verifyLiveFetch(boolean verifyLiveFetch) {
      this.verifyLiveFetch = verifyLiveFetch;
      return this;
    }

    LiveUskPublishRequest build() {
      return new LiveUskPublishRequest(this);
    }

    @Override
    public String toString() {
      return "LiveUskPublishRequest.Builder[redacted]";
    }
  }
}
