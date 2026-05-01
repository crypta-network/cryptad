package network.crypta.platform.appcatalog;

import java.util.Objects;
import java.util.Optional;

/**
 * Holds the exact catalog sidecar bytes retrieved from one catalog source.
 *
 * <p>The catalog verifier signs and verifies the raw {@code cryptad-app-catalog.properties} bytes
 * rather than a parsed or normalized representation, so callers must preserve these byte arrays
 * exactly between fetch, persistence, and verification. Instances defensively copy input and output
 * arrays so callers cannot mutate stored sidecar data after construction.
 *
 * <p>The type is intentionally a small class rather than a record because arrays are mutable. Its
 * accessor methods return fresh copies and its constructor clones inputs immediately. That keeps
 * cached sidecar bytes stable even when test fixtures or fetch buffers are reused by callers.
 */
public final class FetchedCatalog {
  private final byte[] catalogBytes;
  private final byte[] signatureBytes;
  private final String resolvedCatalogUri;

  /**
   * Creates a fetched catalog sidecar pair.
   *
   * <p>The provided arrays are copied immediately. Callers may safely reuse or clear their original
   * buffers after construction without altering the bytes that will be verified or persisted.
   *
   * @param catalogBytes exact bytes of {@code cryptad-app-catalog.properties}
   * @param signatureBytes exact bytes of {@code cryptad-app-catalog.signature}
   */
  public FetchedCatalog(byte[] catalogBytes, byte[] signatureBytes) {
    this(catalogBytes, signatureBytes, null);
  }

  /**
   * Creates a fetched catalog sidecar pair with optional resolved source metadata.
   *
   * <p>The resolved URI is diagnostic metadata reported by a transport implementation, for example
   * the latest URI observed while fetching a mutable Crypta source. It is not used for trust
   * decisions.
   *
   * @param catalogBytes exact bytes of {@code cryptad-app-catalog.properties}
   * @param signatureBytes exact bytes of {@code cryptad-app-catalog.signature}
   * @param resolvedCatalogUri transport-reported resolved catalog URI, or {@code null}
   */
  public FetchedCatalog(byte[] catalogBytes, byte[] signatureBytes, String resolvedCatalogUri) {
    this.catalogBytes = Objects.requireNonNull(catalogBytes, "catalogBytes").clone();
    this.signatureBytes = Objects.requireNonNull(signatureBytes, "signatureBytes").clone();
    this.resolvedCatalogUri =
        resolvedCatalogUri == null
            ? null
            : AppCatalogSidecars.requireNonBlankSingleLine(
                resolvedCatalogUri,
                "resolved catalog URI",
                AppCatalogSidecars.INVALID_CATALOG_SOURCE);
  }

  /**
   * Returns the exact fetched catalog properties bytes.
   *
   * <p>The returned array is a defensive copy. Modifying it does not affect this instance or any
   * later signature verification using this instance.
   *
   * @return defensive copy of {@code cryptad-app-catalog.properties}
   */
  public byte[] catalogBytes() {
    return catalogBytes.clone();
  }

  /**
   * Returns the exact fetched catalog signature bytes.
   *
   * <p>The returned array is a defensive copy. Modifying it does not affect this instance or the
   * source store when these bytes are persisted later.
   *
   * @return defensive copy of {@code cryptad-app-catalog.signature}
   */
  public byte[] signatureBytes() {
    return signatureBytes.clone();
  }

  /**
   * Returns transport-reported resolved catalog URI metadata, when available.
   *
   * @return optional resolved catalog URI
   */
  public Optional<String> resolvedCatalogUri() {
    return Optional.ofNullable(resolvedCatalogUri);
  }
}
