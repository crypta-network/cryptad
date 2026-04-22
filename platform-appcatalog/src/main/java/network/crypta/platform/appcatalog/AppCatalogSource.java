package network.crypta.platform.appcatalog;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Operator-configured location for a signed app catalog.
 *
 * <p>A source identifies the catalog properties file. The matching signature is resolved as a
 * sibling named {@code cryptad-app-catalog.signature}. Local filesystem paths are converted to
 * {@code file:} URIs at construction time so the fetcher can apply one scheme-based policy for
 * local, HTTPS, and loopback-HTTP sources.
 *
 * <p>The source model stores a URI, not raw operator input. Parsing accepts common local path
 * forms, including Windows drive-letter paths, before falling back to URI handling. Remote
 * non-loopback sources must use HTTPS. Plain HTTP is reserved for explicit loopback development and
 * test sources after host validation in {@link AppCatalogSidecars}.
 *
 * @param uri absolute source URI for {@code cryptad-app-catalog.properties}
 */
public record AppCatalogSource(URI uri) {
  private static final Pattern WINDOWS_DRIVE_PATH_PATTERN = Pattern.compile("[A-Za-z]:[\\\\/].*");

  /**
   * Creates a validated source descriptor.
   *
   * <p>The URI is normalized and checked for supported scheme, host, fragment, user-info, and local
   * file restrictions. The constructor does not check that the target exists; fetching is
   * responsible for reading the catalog and signature sidecars.
   *
   * @param uri absolute source URI for {@code cryptad-app-catalog.properties}
   * @throws AppCatalogException if the URI uses an unsupported or unsafe scheme
   */
  public AppCatalogSource {
    uri = AppCatalogSidecars.requireSafeCatalogSourceUri(uri);
  }

  /**
   * Parses an operator-supplied source string.
   *
   * <p>Strings without a URI scheme are treated as local filesystem paths. Drive-letter paths are
   * detected before URI parsing so {@code C:/...} is not mistaken for a one-letter URI scheme on
   * Windows. Syntax that is neither a valid URI nor a valid local path is rejected with {@code
   * invalid_catalog_source}.
   *
   * @param rawSource local path, {@code file:} URI, {@code https:} URI, or loopback {@code http:}
   *     URI
   * @return validated catalog source descriptor
   * @throws AppCatalogException if the source cannot be parsed or is not allowed
   */
  public static AppCatalogSource parse(String rawSource) throws AppCatalogException {
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(
            rawSource, "source", AppCatalogSidecars.INVALID_CATALOG_SOURCE);
    if (WINDOWS_DRIVE_PATH_PATTERN.matcher(value).matches()) {
      return parseLocalPathSource(value, null);
    }
    try {
      URI parsed = new URI(value);
      if (parsed.getScheme() == null) {
        return parseLocalPathSource(value, null);
      }
      return new AppCatalogSource(parsed);
    } catch (URISyntaxException exception) {
      return parseLocalPathSource(value, exception);
    }
  }

  private static AppCatalogSource parseLocalPathSource(
      String value, URISyntaxException uriException) throws AppCatalogException {
    try {
      return new AppCatalogSource(Path.of(value).toAbsolutePath().normalize().toUri());
    } catch (InvalidPathException pathException) {
      if (uriException != null) {
        uriException.addSuppressed(pathException);
        throw invalidSource(value, uriException);
      }
      throw invalidSource(value, pathException);
    }
  }

  private static AppCatalogException invalidSource(String value, Exception exception) {
    return new AppCatalogException(
        AppCatalogSidecars.INVALID_CATALOG_SOURCE, "invalid catalog source: " + value, exception);
  }

  /**
   * Returns the sibling URI where the signature sidecar is expected.
   *
   * <p>The catalog format fixes signature placement beside the properties file. Callers should not
   * derive alternate signature names or fetch a remote signature from an unrelated authority.
   *
   * @return sibling signature URI for this source
   */
  public URI signatureUri() {
    return uri.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME);
  }

  /**
   * Returns the source URI as a stable string for storage and API display.
   *
   * <p>The returned value is the normalized URI text persisted by the source store. It may expose a
   * local file URI, so UI layers should avoid displaying it in contexts where host filesystem paths
   * are sensitive.
   *
   * @return normalized URI text
   */
  public String displayUri() {
    return Objects.toString(uri);
  }
}
