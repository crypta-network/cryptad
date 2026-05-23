package network.crypta.platform.devtools;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import network.crypta.keys.FreenetURI;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appcatalog.AppCatalogVerifier;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Coordinates live USK catalog publication from validated local sidecars.
 *
 * <p>The service keeps the high-risk pieces ordered and testable: validate the same local inputs as
 * dry-run planning, verify the signed catalog against explicit trusted public keys, validate live
 * node and secure secret inputs without echoing them, confirm the private USK insert URI matches
 * the configured public source, stage only the canonical catalog/signature filenames into a
 * retained directory, invoke an injected live insertion adapter, then write a sanitized summary. It
 * never stores private insert material or form passwords in the result model.
 *
 * <p>The class is deliberately stateless. Production code supplies the Platform API publisher,
 * while tests can supply a fake publisher that observes the sanitized request boundary. Publication
 * either fails before the live adapter is called, or returns a report-safe result after the adapter
 * accepts the insertion request. Staged sidecars are retained because the live queue uses
 * disk-backed source files that may be consumed after the HTTP call returns.
 */
final class LiveUskPublicationService {
  /** Public Crypta URI scheme used by catalog sources. */
  private static final String CRYPTA_SCHEME = "crypta:";

  /** Public catalog source prefix required for first-party live USK publication. */
  private static final String CRYPTA_USK_PREFIX = CRYPTA_SCHEME + "USK@";

  /** Owner-only permissions for retained staging directories on POSIX filesystems. */
  private static final Set<PosixFilePermission> OWNER_ONLY_DIRECTORY =
      Set.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE);

  /** Status used when the caller did not request immediate public-source fetch verification. */
  private static final String POST_PUBLISH_NOT_REQUESTED = "not_requested";

  /**
   * Path-free warning recorded whenever disk-backed sidecars remain available for the live queue.
   */
  private static final String STAGING_RETAINED_WARNING =
      "staging_sidecars_retained_until_live_insert_completion";

  /** Prevents construction of this stateless service. */
  private LiveUskPublicationService() {}

  /**
   * Publishes one signed catalog through the supplied live insertion adapter.
   *
   * @param request live publication inputs and secure values
   * @param trustedKeys trusted catalog signing keys used before insertion
   * @param publisher configured live insertion adapter
   * @return report-safe live publication result
   * @throws IOException if local files or the live adapter fail
   */
  static LiveUskPublicationResult publish(
      Request request, TrustedAppKeys trustedKeys, LiveUskPublisher publisher) throws IOException {
    ValidatedPublicationInputs inputs =
        PublicationInputValidator.validate(
            request.catalogFile(),
            request.catalogSignatureFile(),
            request.catalogSource(),
            request.output());
    AppCatalogVerifier.verify(inputs.catalogBytes(), inputs.signatureBytes(), trustedKeys);
    URI nodeBaseUrl = normalizeNodeBaseUrl(request.nodeBaseUrl());
    String privateInsertUri = requirePrivateInsertUri(request.privateInsertUri());
    requireInsertUriMatchesPublicSource(privateInsertUri, inputs.catalogSource());
    String formPassword = requireFormPassword(request.formPassword());
    String publicSignatureSource = publicSignatureSource(inputs.catalogSource());
    List<String> cleanupWarnings = new ArrayList<>();
    Path stagingDirectory = stageSidecars(inputs);
    LiveUskPublishRequest publishRequest =
        LiveUskPublishRequest.builder()
            .nodeBaseUrl(nodeBaseUrl)
            .formPassword(formPassword)
            .privateInsertUri(privateInsertUri)
            .stagingDirectory(stagingDirectory)
            .identifier(publicationIdentifier(inputs))
            .publicCatalogSource(inputs.catalogSource())
            .publicSignatureSource(publicSignatureSource)
            .catalogBytes(inputs.catalogBytes())
            .signatureBytes(inputs.signatureBytes())
            .verifyLiveFetch(request.verifyLiveFetch())
            .build();
    LiveUskPublishResponse response = publisher.publish(publishRequest);
    cleanupWarnings.add(STAGING_RETAINED_WARNING);
    List<String> warnings = new ArrayList<>(response.warnings());
    warnings.addAll(cleanupWarnings);
    if (!request.verifyLiveFetch()
        && POST_PUBLISH_NOT_REQUESTED.equals(response.postPublishVerificationStatus())) {
      warnings.add("post_publish_fetch_verification_not_requested");
    }
    LiveUskPublicationResult result =
        new LiveUskPublicationResult(
            inputs.catalog().catalogId(),
            AppTestRedactor.fileName(inputs.catalogFile()),
            AppTestRedactor.fileName(inputs.catalogSignatureFile()),
            inputs.catalogSource(),
            publicSignatureSource,
            response.resolvedCatalogSource(),
            edition(response.resolvedCatalogSource().orElse(inputs.catalogSource())),
            inputs.catalogSha256(),
            inputs.signatureSha256(),
            inputs.signature().keyId(),
            inputs.catalog().entries().size(),
            response.catalogInsertStatus(),
            response.signatureInsertStatus(),
            response.postPublishVerificationStatus(),
            response.schedulerRefreshVerificationStatus(),
            sanitizeWarnings(warnings),
            inputs.output());
    LiveUskPublicationResultWriter.write(result);
    return result;
  }

  /**
   * Normalizes and validates the localhost Platform API base URL.
   *
   * <p>Live publication is allowed only through local HTTP(S) endpoints. The method rejects user
   * info, query strings, fragments, and non-loopback hosts before any secret-bearing form is built.
   * It does not resolve DNS names other than the literal {@code localhost}; accepting DNS aliases
   * would make the private insert URI and form password dependent on external name resolution.
   *
   * @param rawNodeBaseUrl operator-supplied node or Platform API base URL
   * @return normalized URI safe to use as the base for local Platform API routes
   * @throws AppDistributionException if the URL is malformed or not a localhost HTTP(S) URL
   */
  private static URI normalizeNodeBaseUrl(String rawNodeBaseUrl) throws AppDistributionException {
    String value = rawNodeBaseUrl == null ? "" : rawNodeBaseUrl.trim();
    if (value.isEmpty()) {
      throw new AppDistributionException("live publish requires --node-base-url");
    }
    URI uri;
    try {
      uri = new URI(value);
    } catch (URISyntaxException exception) {
      throw new AppDistributionException("live publish node base URL is malformed", exception);
    }
    String scheme = uri.getScheme();
    String host = uri.getHost();
    if (scheme == null
        || host == null
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null
        || uri.getRawUserInfo() != null
        || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
      throw new AppDistributionException(
          "live publish node base URL must be a localhost HTTP(S) URL without query text");
    }
    if (!isLoopbackHost(host)) {
      throw new AppDistributionException("live publish node base URL must use a localhost host");
    }
    return uri.normalize();
  }

  /**
   * Checks whether a host string is an accepted loopback literal.
   *
   * <p>The accepted set is intentionally narrow: {@code localhost}, IPv4 {@code 127.0.0.0/8}
   * literals, and the common IPv6 loopback forms. Hostnames that merely start with loopback text
   * are rejected by {@link #isIpv4LoopbackLiteral(String)} because they are DNS names, not IP
   * literals.
   *
   * @param host raw host component returned by {@link URI#getHost()}
   * @return {@code true} when the host is accepted for secret-bearing local publication
   */
  private static boolean isLoopbackHost(String host) {
    String normalized = stripIpv6Brackets(host.toLowerCase(java.util.Locale.ROOT));
    return "localhost".equals(normalized)
        || isIpv4LoopbackLiteral(normalized)
        || "::1".equals(normalized)
        || "0:0:0:0:0:0:0:1".equals(normalized);
  }

  /**
   * Removes square brackets from an IPv6 host literal when present.
   *
   * <p>{@link URI#getHost()} normally returns IPv6 hosts without brackets, but this helper keeps
   * the loopback check robust if a future caller passes a bracketed literal directly.
   *
   * @param host lower-cased host string to inspect
   * @return host without enclosing IPv6 brackets, or the original string
   */
  private static String stripIpv6Brackets(String host) {
    if (host.length() >= 2 && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
      return host.substring(1, host.length() - 1);
    }
    return host;
  }

  /**
   * Validates a dotted IPv4 loopback literal without accepting DNS names.
   *
   * <p>The method requires exactly four numeric labels, the first label {@code 127}, and every
   * label in the byte range. That accepts the full IPv4 loopback block while rejecting strings such
   * as {@code 127.0.0.1.example} and malformed decimal forms.
   *
   * @param host lower-cased host string without IPv6 brackets
   * @return {@code true} when {@code host} is a valid dotted IPv4 loopback literal
   */
  private static boolean isIpv4LoopbackLiteral(String host) {
    String[] parts = host.split("\\.", -1);
    if (parts.length != 4 || !"127".equals(parts[0])) {
      return false;
    }
    for (String part : parts) {
      if (part.isEmpty() || !part.chars().allMatch(Character::isDigit)) {
        return false;
      }
      try {
        if (Integer.parseInt(part) > 255) {
          return false;
        }
      } catch (NumberFormatException _) {
        return false;
      }
    }
    return true;
  }

  /**
   * Validates the private insert URI string loaded from a secure source.
   *
   * <p>The live directory insert requires a private USK insert URI for the catalog parent path. The
   * value must be single-line text and must not include the public {@code crypta:} scheme. The
   * source correlation check later derives the corresponding public request URI and compares it
   * with the operator-supplied public catalog source.
   *
   * @param rawPrivateInsertUri text loaded from the configured environment variable or protected
   *     file
   * @return trimmed private USK insert URI text
   * @throws AppDistributionException if the value is missing, multi-line, public, or not USK-shaped
   */
  private static String requirePrivateInsertUri(String rawPrivateInsertUri)
      throws AppDistributionException {
    String value = requireSingleLine(rawPrivateInsertUri, "private insert URI");
    if (value.startsWith(CRYPTA_SCHEME)) {
      throw new AppDistributionException(
          "private insert URI must not use the public crypta scheme");
    }
    String lower = value.toLowerCase(java.util.Locale.ROOT);
    if (!lower.startsWith("usk@")) {
      throw new AppDistributionException("private insert URI must be a USK insert URI");
    }
    return value;
  }

  /**
   * Ensures the private insert URI corresponds to the advertised public catalog source.
   *
   * <p>Without this check, an operator typo could enqueue bytes to one USK while writing release
   * evidence for another public source. The method derives the public request URI from the private
   * insert URI, appends the catalog filename for the directory insert, and compares it with the
   * configured {@code crypta:USK@.../cryptad-app-catalog.properties} source.
   *
   * @param privateInsertUri validated private USK insert URI text
   * @param publicCatalogSource validated public catalog source from the CLI request
   * @throws AppDistributionException if parsing fails or the public/private sources do not match
   */
  private static void requireInsertUriMatchesPublicSource(
      String privateInsertUri, String publicCatalogSource) throws AppDistributionException {
    FreenetURI privateUri = parseBareUri(privateInsertUri, "private insert URI");
    FreenetURI actualPublicSource =
        parseBareUri(stripCryptaScheme(publicCatalogSource), "public catalog source");
    FreenetURI expectedPublicSource = expectedPublicCatalogSource(privateUri);
    if (!expectedPublicSource.equals(actualPublicSource)) {
      throw new AppDistributionException("private insert URI does not match public catalog source");
    }
  }

  /**
   * Derives the expected public catalog source from a private USK directory insert URI.
   *
   * <p>The Platform API queue insert publishes a directory whose manifest children are the catalog
   * properties and signature sidecar. The private URI therefore points at the directory root, and
   * this method adds the canonical catalog filename after deriving the public request URI.
   *
   * @param privateUri parsed private USK insert URI for the catalog directory root
   * @return parsed public catalog source expected for the catalog properties child
   * @throws AppDistributionException if the private URI cannot be converted to a request URI
   */
  private static FreenetURI expectedPublicCatalogSource(FreenetURI privateUri)
      throws AppDistributionException {
    try {
      FreenetURI publicBase = privateUri.deriveRequestURIFromInsertURI();
      return parseBareUri(
          publicBase.toString(false, false) + "/" + AppCatalogSignature.CATALOG_FILE_NAME,
          "derived public catalog source");
    } catch (MalformedURLException exception) {
      throw new AppDistributionException(
          "private insert URI must be an insert URI matching the public catalog source", exception);
    }
  }

  /**
   * Parses a bare Crypta key URI and requires USK semantics.
   *
   * <p>The internal key parser expects values without the public {@code crypta:} scheme. The {@code
   * label} is used only in sanitized validation errors and must not contain the URI value.
   *
   * @param value bare key URI text such as {@code USK@.../catalog/42}
   * @param label sanitized name of the field being parsed
   * @return parsed USK key URI
   * @throws AppDistributionException if the key cannot be parsed or is not a USK
   */
  private static FreenetURI parseBareUri(String value, String label)
      throws AppDistributionException {
    try {
      FreenetURI uri = new FreenetURI(value);
      if (!uri.isUSK()) {
        throw new AppDistributionException(label + " must be a USK URI");
      }
      return uri;
    } catch (MalformedURLException exception) {
      throw new AppDistributionException(label + " is not a valid USK URI", exception);
    }
  }

  /**
   * Removes the public {@code crypta:} scheme from a catalog source before key parsing.
   *
   * <p>Validation has already required the public source shape. This helper keeps the parser call
   * explicit and avoids accepting other schemes in the private URI path.
   *
   * @param publicCatalogSource catalog source value from validated publication inputs
   * @return source text without the leading {@code crypta:} scheme when present
   */
  private static String stripCryptaScheme(String publicCatalogSource) {
    return publicCatalogSource.startsWith(CRYPTA_SCHEME)
        ? publicCatalogSource.substring(CRYPTA_SCHEME.length())
        : publicCatalogSource;
  }

  /**
   * Validates the form password loaded from a secure source.
   *
   * <p>The password is needed only to authenticate the localhost mutation route. The returned value
   * is passed directly to the live insertion adapter and is never copied into the result model.
   *
   * @param rawFormPassword text loaded from the configured environment variable or protected file
   * @return trimmed single-line form password
   * @throws AppDistributionException if the value is missing or multi-line
   */
  private static String requireFormPassword(String rawFormPassword)
      throws AppDistributionException {
    return requireSingleLine(rawFormPassword, "form password");
  }

  /**
   * Requires one non-empty line of secret-bearing configuration.
   *
   * <p>The helper rejects embedded line breaks and NUL characters so accidental file concatenation
   * or malformed environment values cannot leak into HTTP form construction. Error messages mention
   * only the field label, not the supplied value.
   *
   * @param value raw field text, possibly null or padded with whitespace
   * @param label sanitized field name used in validation messages
   * @return trimmed single-line value
   * @throws AppDistributionException if the value is empty or contains forbidden characters
   */
  private static String requireSingleLine(String value, String label)
      throws AppDistributionException {
    String checked = value == null ? "" : value.trim();
    if (checked.isEmpty()) {
      throw new AppDistributionException("live publish requires " + label);
    }
    if (checked.indexOf('\n') >= 0
        || checked.indexOf('\r') >= 0
        || checked.indexOf('\u0000') >= 0) {
      throw new AppDistributionException(label + " must be a single-line value");
    }
    return checked;
  }

  /**
   * Computes the public sibling signature source for a public catalog source.
   *
   * <p>The publication input validator has already required a catalog source ending in the
   * canonical catalog filename. Replacing the final path segment keeps the signature sidecar at the
   * same USK path and edition.
   *
   * @param publicCatalogSource validated public catalog source for the properties file
   * @return public source for {@code cryptad-app-catalog.signature}
   */
  private static String publicSignatureSource(String publicCatalogSource) {
    int slash = publicCatalogSource.lastIndexOf('/');
    return publicCatalogSource.substring(0, slash + 1) + AppCatalogSignature.SIGNATURE_FILE_NAME;
  }

  /**
   * Builds a deterministic queue identifier for the publication attempt.
   *
   * <p>The identifier combines the catalog id with a short catalog digest prefix. It is stable
   * enough for operators to correlate queue entries without including local paths, private insert
   * material, or full catalog contents in the identifier.
   *
   * @param inputs validated local publication snapshot
   * @return deterministic queue identifier safe for node request metadata
   */
  private static String publicationIdentifier(ValidatedPublicationInputs inputs) {
    return "cryptad-catalog-"
        + inputs.catalog().catalogId()
        + "-"
        + inputs.catalogSha256().substring(0, 12);
  }

  /**
   * Stages canonical catalog and signature sidecars for the disk-backed directory insert.
   *
   * <p>The staging directory is created beside the requested summary output when possible, so
   * release jobs can keep live-publication evidence and retained sidecars in the same controlled
   * area. Only the canonical public sidecar filenames are written. The directory is intentionally
   * not removed here because the live queue may read these files after the HTTP call returns.
   *
   * @param inputs validated publication inputs containing exact catalog and signature bytes
   * @return retained staging directory containing the two public sidecar files
   * @throws IOException if the directory or sidecar files cannot be created
   */
  private static Path stageSidecars(ValidatedPublicationInputs inputs) throws IOException {
    Path stagingDirectory = createPrivateStagingDirectory(stagingParent(inputs.output()));
    Files.write(
        stagingDirectory.resolve(AppCatalogSignature.CATALOG_FILE_NAME),
        inputs.catalogBytes(),
        StandardOpenOption.CREATE_NEW,
        StandardOpenOption.WRITE);
    Files.write(
        stagingDirectory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
        inputs.signatureBytes(),
        StandardOpenOption.CREATE_NEW,
        StandardOpenOption.WRITE);
    return stagingDirectory;
  }

  /**
   * Chooses the parent that should hold retained live-publication sidecars.
   *
   * <p>When the output path has no parent, the current working directory is used instead of the JVM
   * default temp directory so staging stays with operator-controlled release output.
   *
   * @param output requested summary output path
   * @return existing directory that can contain the retained staging directory
   * @throws IOException if the requested output parent cannot be created
   */
  private static Path stagingParent(Path output) throws IOException {
    Path outputParent = output.getParent();
    if (outputParent == null) {
      return Path.of("").toAbsolutePath().normalize();
    }
    return Files.createDirectories(outputParent);
  }

  /**
   * Creates an owner-only retained staging directory below the selected parent.
   *
   * <p>The directory name is generated atomically. POSIX hosts receive owner-only permissions at
   * creation time; other filesystems are restricted immediately through the portable {@link
   * java.io.File} permission API before any sidecar bytes are written.
   *
   * @param stagingParent parent directory for retained live-publication sidecars
   * @return owner-only staging directory
   * @throws IOException if the directory cannot be created or restricted
   */
  // The directory is created under an operator-selected parent and locked down before any catalog
  // sidecar bytes are staged for the disk-backed live insert queue.
  @SuppressWarnings("java:S5443")
  private static Path createPrivateStagingDirectory(Path stagingParent) throws IOException {
    try {
      return Files.createTempDirectory(
          stagingParent,
          "cryptad-live-usk-catalog-",
          PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIRECTORY));
    } catch (UnsupportedOperationException _) {
      Path stagingDirectory = Files.createTempDirectory(stagingParent, "cryptad-live-usk-catalog-");
      try {
        restrictPortableOwnerOnlyDirectory(stagingDirectory);
        return stagingDirectory;
      } catch (IOException | RuntimeException exception) {
        Files.deleteIfExists(stagingDirectory);
        throw exception;
      }
    }
  }

  /**
   * Applies owner-only access to a retained staging directory on non-POSIX filesystems.
   *
   * @param stagingDirectory staging directory that must be accessible only by the current owner
   * @throws IOException if any portable permission operation is rejected by the runtime
   */
  private static void restrictPortableOwnerOnlyDirectory(Path stagingDirectory) throws IOException {
    java.io.File file = stagingDirectory.toFile();
    if (!file.setReadable(false, false)
        || !file.setWritable(false, false)
        || !file.setExecutable(false, false)
        || !file.setReadable(true, true)
        || !file.setWritable(true, true)
        || !file.setExecutable(true, true)) {
      throw new IOException("failed to restrict live publication staging directory");
    }
  }

  /**
   * Extracts a numeric USK edition from a public catalog source.
   *
   * <p>The parser is intentionally lightweight because the catalog source was already validated
   * elsewhere. It looks at the path segment immediately before the catalog filename and returns it
   * only when that segment is an integer, including negative moving-edition notation.
   *
   * @param publicSource public catalog source or resolved catalog source
   * @return numeric edition segment when one is present
   */
  private static Optional<String> edition(String publicSource) {
    if (!publicSource.startsWith(CRYPTA_USK_PREFIX)) {
      return Optional.empty();
    }
    int fileSlash = publicSource.lastIndexOf('/');
    if (fileSlash <= CRYPTA_USK_PREFIX.length()) {
      return Optional.empty();
    }
    int editionSlash = publicSource.lastIndexOf('/', fileSlash - 1);
    if (editionSlash < CRYPTA_USK_PREFIX.length()) {
      return Optional.empty();
    }
    String candidate = publicSource.substring(editionSlash + 1, fileSlash);
    return candidate.matches("-?\\d+") ? Optional.of(candidate) : Optional.empty();
  }

  /**
   * Redacts and deduplicates warnings before they reach release evidence.
   *
   * <p>Publisher implementations should already return safe warnings, but the service applies the
   * shared app-test redactor as a final guard and preserves first occurrence order through the
   * stream distinct operation.
   *
   * @param warnings warning strings from the publisher and local publication checks
   * @return sanitized warning strings with duplicates removed
   */
  private static List<String> sanitizeWarnings(List<String> warnings) {
    return warnings.stream().map(AppTestRedactor::redact).distinct().toList();
  }

  /**
   * Live publication request with secrets already loaded from secure sources.
   *
   * @param catalogFile local catalog properties file
   * @param catalogSignatureFile local catalog signature sidecar
   * @param catalogSource public catalog source
   * @param output sanitized summary output path
   * @param privateInsertUri private insert URI loaded from env or protected file
   * @param nodeBaseUrl localhost node or Platform API base URL
   * @param formPassword form password loaded from env or protected file
   * @param verifyLiveFetch require immediate live fetch verification after queue insertion
   */
  record Request(
      Path catalogFile,
      Path catalogSignatureFile,
      String catalogSource,
      Path output,
      String privateInsertUri,
      String nodeBaseUrl,
      String formPassword,
      boolean verifyLiveFetch) {}
}
