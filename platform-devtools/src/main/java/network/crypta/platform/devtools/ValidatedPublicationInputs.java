package network.crypta.platform.devtools;

import java.nio.file.Path;
import java.util.Objects;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogSignature;

/**
 * Immutable snapshot of validated catalog publication inputs.
 *
 * <p>This package-scoped value coordinates the developer CLI's dry-run writer and live publication
 * service. It keeps the exact bytes needed for signature verification and live staging, plus only
 * derived report-safe metadata such as digests and file basenames. Callers should use {@link
 * AppTestRedactor#fileName(Path)} when rendering any of the local paths held here.
 *
 * <p>The class is intentionally not a record. Two fields are mutable byte arrays, and an ordinary
 * class avoids record-generated equality, hashing, and string rendering that would treat arrays by
 * identity or expose implementation details. Construction goes through a builder so the many
 * validation fields remain named at the call site without introducing a wide public constructor.
 */
final class ValidatedPublicationInputs {
  private final Path catalogFile;
  private final Path catalogSignatureFile;
  private final String catalogSource;
  private final Path output;
  private final byte[] catalogBytes;
  private final byte[] signatureBytes;
  private final AppCatalog catalog;
  private final AppCatalogSignature signature;
  private final String catalogSha256;
  private final String signatureSha256;

  private ValidatedPublicationInputs(Builder builder) {
    catalogFile = Objects.requireNonNull(builder.catalogFile, "catalogFile");
    catalogSignatureFile =
        Objects.requireNonNull(builder.catalogSignatureFile, "catalogSignatureFile");
    catalogSource = Objects.requireNonNull(builder.catalogSource, "catalogSource");
    output = Objects.requireNonNull(builder.output, "output");
    catalogBytes = Objects.requireNonNull(builder.catalogBytes, "catalogBytes").clone();
    signatureBytes = Objects.requireNonNull(builder.signatureBytes, "signatureBytes").clone();
    catalog = Objects.requireNonNull(builder.catalog, "catalog");
    signature = Objects.requireNonNull(builder.signature, "signature");
    catalogSha256 = Objects.requireNonNull(builder.catalogSha256, "catalogSha256");
    signatureSha256 = Objects.requireNonNull(builder.signatureSha256, "signatureSha256");
  }

  /**
   * Starts construction of a validated publication input snapshot.
   *
   * @return empty builder whose fields are populated by the validator
   */
  static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the normalized local catalog properties path.
   *
   * @return catalog properties file path selected by the operator
   */
  Path catalogFile() {
    return catalogFile;
  }

  /**
   * Returns the normalized local detached signature sidecar path.
   *
   * @return signature sidecar file path selected by the operator
   */
  Path catalogSignatureFile() {
    return catalogSignatureFile;
  }

  /**
   * Returns the public catalog source expected after dry-run planning or live publication.
   *
   * @return public {@code crypta:USK@.../cryptad-app-catalog.properties} source
   */
  String catalogSource() {
    return catalogSource;
  }

  /**
   * Returns the normalized publication report output path.
   *
   * @return dry-run plan or live summary output path
   */
  Path output() {
    return output;
  }

  /**
   * Returns the exact catalog properties bytes captured during validation.
   *
   * @return defensive copy of the validated catalog bytes
   */
  byte[] catalogBytes() {
    return catalogBytes.clone();
  }

  /**
   * Returns the exact detached signature sidecar bytes captured during validation.
   *
   * @return defensive copy of the validated signature bytes
   */
  byte[] signatureBytes() {
    return signatureBytes.clone();
  }

  /**
   * Returns parsed catalog metadata.
   *
   * @return parsed signed-catalog properties model
   */
  AppCatalog catalog() {
    return catalog;
  }

  /**
   * Returns parsed detached signature metadata.
   *
   * @return parsed catalog signature sidecar
   */
  AppCatalogSignature signature() {
    return signature;
  }

  /**
   * Returns the stable SHA-256 digest of the validated catalog bytes.
   *
   * @return lowercase hexadecimal catalog digest
   */
  String catalogSha256() {
    return catalogSha256;
  }

  /**
   * Returns the stable SHA-256 digest of the validated signature bytes.
   *
   * @return lowercase hexadecimal signature digest
   */
  String signatureSha256() {
    return signatureSha256;
  }

  /** Builder used by {@link PublicationInputValidator} after all local inputs pass validation. */
  static final class Builder {
    private Path catalogFile;
    private Path catalogSignatureFile;
    private String catalogSource;
    private Path output;
    private byte[] catalogBytes;
    private byte[] signatureBytes;
    private AppCatalog catalog;
    private AppCatalogSignature signature;
    private String catalogSha256;
    private String signatureSha256;

    private Builder() {}

    Builder catalogFile(Path catalogFile) {
      this.catalogFile = Objects.requireNonNull(catalogFile, "catalogFile");
      return this;
    }

    Builder catalogSignatureFile(Path catalogSignatureFile) {
      this.catalogSignatureFile =
          Objects.requireNonNull(catalogSignatureFile, "catalogSignatureFile");
      return this;
    }

    Builder catalogSource(String catalogSource) {
      this.catalogSource = Objects.requireNonNull(catalogSource, "catalogSource");
      return this;
    }

    Builder output(Path output) {
      this.output = Objects.requireNonNull(output, "output");
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

    Builder catalog(AppCatalog catalog) {
      this.catalog = Objects.requireNonNull(catalog, "catalog");
      return this;
    }

    Builder signature(AppCatalogSignature signature) {
      this.signature = Objects.requireNonNull(signature, "signature");
      return this;
    }

    Builder catalogSha256(String catalogSha256) {
      this.catalogSha256 = Objects.requireNonNull(catalogSha256, "catalogSha256");
      return this;
    }

    Builder signatureSha256(String signatureSha256) {
      this.signatureSha256 = Objects.requireNonNull(signatureSha256, "signatureSha256");
      return this;
    }

    ValidatedPublicationInputs build() {
      return new ValidatedPublicationInputs(this);
    }
  }
}
