package network.crypta.platform.devtools;

import java.io.IOException;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Publishes catalog sidecars through the localhost Platform API queue insertion route.
 *
 * <p>The current runtime exposes live inserts through the queue API rather than a catalog-specific
 * publication SPI. This adapter stages the catalog and signature as a two-file directory and asks
 * the daemon to enqueue one persistent directory insert at the private USK insert URI. The public
 * catalog source then addresses {@code cryptad-app-catalog.properties} as a manifest child, and the
 * signature sidecar addresses the sibling {@code cryptad-app-catalog.signature}. Optional live
 * fetch verification uses the same Platform API content-fetch route and compares exact bytes
 * without recording response bodies.
 */
final class PlatformApiLiveUskPublisher implements LiveUskPublisher {
  /** Per-request network bound so a live publication command cannot wait indefinitely. */
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

  /** Media type used by the existing Platform API form endpoints. */
  private static final String FORM_CONTENT_TYPE =
      "application/x-www-form-urlencoded; charset=UTF-8";

  /**
   * Queue outcome that means the daemon accepted the persistent insert request.
   *
   * <p>This is not treated as proof that publication has propagated or that disk-backed staging
   * files have been consumed; the caller retains staging for operator cleanup.
   */
  private static final String OUTCOME_STARTED = "STARTED";

  /** Sanitized status recorded when the queue accepts a catalog or signature insert request. */
  private static final String STATUS_QUEUED = "queued";

  /** Summary value used when the operator did not request live fetch verification. */
  private static final String POST_PUBLISH_NOT_REQUESTED = "not_requested";

  /** Summary value used only after fetched catalog and signature bytes match local sidecars. */
  private static final String POST_PUBLISH_VERIFIED = "verified";

  /** Scheduler compatibility is reported by the service layer, not this low-level publisher. */
  private static final String SCHEDULER_REFRESH_NOT_RUN = "not_run";

  /** Verification fetch cap for catalog properties; production catalogs should be much smaller. */
  private static final long MAX_CATALOG_BYTES = 1024L * 1024L;

  /** Verification fetch cap for detached signature sidecars. */
  private static final long MAX_SIGNATURE_BYTES = 64L * 1024L;

  /** Internal sentinel used when a fetch response does not report a resolved public source. */
  private static final String ABSENT_RESOLVED_SOURCE = "";

  /** HTTP transport used for localhost Platform API requests. */
  private final HttpClient httpClient;

  /**
   * Creates a publisher with a bounded no-proxy, no-redirect HTTP client.
   *
   * <p>The CLI has already validated that the base URL points at localhost. The client still avoids
   * inherited JVM proxy selectors and redirects so a misconfigured runtime cannot silently forward
   * private insert material or a form password outside the validated loopback endpoint.
   */
  PlatformApiLiveUskPublisher() {
    this(
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .proxy(ProxySelector.of(null))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build());
  }

  /**
   * Creates a publisher with an explicit client for tests.
   *
   * @param httpClient HTTP client used for Platform API requests
   */
  PlatformApiLiveUskPublisher(HttpClient httpClient) {
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
  }

  @Override
  public LiveUskPublishResponse publish(LiveUskPublishRequest request) throws IOException {
    boolean queueAccepted = false;
    try {
      enqueueDirectoryInsert(request);
      queueAccepted = true;
      Optional<String> resolvedCatalogSource = Optional.empty();
      String postPublishStatus = POST_PUBLISH_NOT_REQUESTED;
      if (request.verifyLiveFetch()) {
        resolvedCatalogSource = verifyFetchedSidecars(request);
        postPublishStatus = POST_PUBLISH_VERIFIED;
      }
      return new LiveUskPublishResponse(
          STATUS_QUEUED,
          STATUS_QUEUED,
          resolvedCatalogSource,
          postPublishStatus,
          SCHEDULER_REFRESH_NOT_RUN,
          List.of());
    } catch (IOException exception) {
      if (queueAccepted) {
        throw LiveUskPublishException.afterQueueAccepted(exception);
      }
      throw exception;
    }
  }

  /**
   * Enqueues the staged catalog directory as one persistent USK insert.
   *
   * <p>The queue API receives the private insert URI, form password, and local staging path. Those
   * values are intentionally kept inside the request body and are never copied into exception
   * messages or publication summaries.
   *
   * @param request live publication request with validated public/private source correlation
   * @throws IOException when the daemon cannot be contacted
   */
  private void enqueueDirectoryInsert(LiveUskPublishRequest request) throws IOException {
    String body =
        form(
            "formPassword",
            request.formPassword(),
            "sourcePath",
            request.stagingDirectory().toString(),
            "insertUri",
            request.privateInsertUri(),
            "identifier",
            request.identifier(),
            "compatibilityMode",
            "COMPAT_CURRENT");
    HttpResponse<String> response =
        sendPost(apiEndpoint(request.nodeBaseUrl(), "queue/inserts/directory"), body);
    if (response.statusCode() != 200 && response.statusCode() != 201) {
      throw new AppDistributionException(
          "live_publish_failed: node returned HTTP "
              + response.statusCode()
              + " while enqueueing catalog USK insert");
    }
    String outcome =
        jsonString(response.body(), "outcome")
            .orElseThrow(
                () ->
                    new AppDistributionException(
                        "live_publish_failed: node did not report a queue insert outcome"));
    if (!OUTCOME_STARTED.equals(outcome)) {
      throw new AppDistributionException(
          "live_publish_failed: node did not start catalog USK insert");
    }
  }

  /**
   * Fetches the public catalog and matching sibling signature, then compares both to local bytes.
   *
   * <p>If the catalog fetch resolves a moving USK to a concrete edition, the signature fetch is
   * derived from that resolved catalog source so both sidecars are verified at the same edition.
   * The method returns only the sanitized resolved catalog source that the final report may expose.
   *
   * @param request live publication request containing local sidecar bytes and public sources
   * @return resolved public catalog source, when reported by the node
   * @throws IOException when either verification fetch cannot complete
   */
  private Optional<String> verifyFetchedSidecars(LiveUskPublishRequest request) throws IOException {
    FetchResult catalog =
        fetchContent(
            request.nodeBaseUrl(),
            request.formPassword(),
            request.publicCatalogSource(),
            MAX_CATALOG_BYTES);
    String signatureFetchSource =
        catalog
            .resolvedSource()
            .map(PlatformApiLiveUskPublisher::signatureSiblingSource)
            .orElse(request.publicSignatureSource());
    FetchResult signature =
        fetchContent(
            request.nodeBaseUrl(),
            request.formPassword(),
            signatureFetchSource,
            MAX_SIGNATURE_BYTES);
    if (!Arrays.equals(request.catalogBytes(), catalog.bytes())) {
      throw new AppDistributionException(
          "live_publish_verification_failed: fetched catalog bytes do not match local catalog");
    }
    if (!Arrays.equals(request.signatureBytes(), signature.bytes())) {
      throw new AppDistributionException(
          "live_publish_verification_failed: fetched signature bytes do not match local signature");
    }
    return catalog.resolvedSource();
  }

  /**
   * Replaces the catalog file name in a public source with the signature sidecar name.
   *
   * @param catalogSource public catalog source, preferably resolved to a concrete edition
   * @return sibling source for {@code cryptad-app-catalog.signature}
   */
  private static String signatureSiblingSource(String catalogSource) {
    int slash = catalogSource.lastIndexOf('/');
    if (slash < 0) {
      return catalogSource;
    }
    return catalogSource.substring(0, slash + 1) + AppCatalogSignature.SIGNATURE_FILE_NAME;
  }

  /**
   * Fetches one public sidecar through the Platform API content route.
   *
   * <p>The node response is decoded from base64 and reduced to bytes plus an optional sanitized
   * resolved URI. HTTP status codes and parse failures are reported without echoing response
   * bodies.
   *
   * @param nodeBaseUrl localhost Platform API base URL
   * @param formPassword form password for the local node
   * @param publicSource public Crypta source to fetch
   * @param maxBytes maximum response size accepted by the node route
   * @return fetched bytes and optional resolved public source
   * @throws IOException when the fetch request cannot be sent
   */
  private FetchResult fetchContent(
      URI nodeBaseUrl, String formPassword, String publicSource, long maxBytes) throws IOException {
    String body =
        form(
            "formPassword",
            formPassword,
            "uri",
            publicSource,
            "format",
            "base64",
            "maxBytes",
            Long.toString(maxBytes),
            "purpose",
            "live-usk-catalog-publication");
    HttpResponse<String> response = sendPost(apiEndpoint(nodeBaseUrl, "content/fetch"), body);
    if (response.statusCode() != 200) {
      throw new AppDistributionException(
          "live_publish_verification_failed: node returned HTTP "
              + response.statusCode()
              + " while fetching published sidecars");
    }
    String contentBase64 =
        jsonString(response.body(), "contentBase64")
            .orElseThrow(
                () ->
                    new AppDistributionException(
                        "live_publish_verification_failed: content fetch response was incomplete"));
    byte[] bytes;
    try {
      bytes = Base64.getDecoder().decode(contentBase64);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(
          "live_publish_verification_failed: content fetch bytes were malformed", exception);
    }
    Optional<String> resolvedSource =
        jsonString(response.body(), "resolvedUri").flatMap(this::resolvedSource);
    return new FetchResult(bytes, resolvedSource.orElse(ABSENT_RESOLVED_SOURCE));
  }

  /**
   * Sends one bounded JSON-accepting POST request to the local node.
   *
   * @param endpoint full Platform API endpoint
   * @param body already encoded form body
   * @return HTTP response body for internal parsing only
   * @throws IOException when transport fails or the request is interrupted
   */
  private HttpResponse<String> sendPost(URI endpoint, String body) throws IOException {
    HttpRequest request =
        HttpRequest.newBuilder(endpoint)
            .timeout(REQUEST_TIMEOUT)
            .header("Content-Type", FORM_CONTENT_TYPE)
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
    try {
      return httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new IOException("interrupted while contacting live node", exception);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException("live publish node endpoint is malformed", exception);
    }
  }

  /**
   * Builds a Platform API v1 endpoint from an operator-supplied base URL.
   *
   * @param nodeBaseUrl validated local node base URL, with or without {@code /api/v1}
   * @param relativePath endpoint path below {@code /api/v1}
   * @return normalized endpoint URI
   */
  private static URI apiEndpoint(URI nodeBaseUrl, String relativePath) {
    String base = nodeBaseUrl.toString();
    while (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    if (!base.endsWith("/api/v1")) {
      base = base + "/api/v1";
    }
    return URI.create(base + "/" + relativePath);
  }

  /**
   * Builds a UTF-8 {@code application/x-www-form-urlencoded} body.
   *
   * @param fields alternating field names and values
   * @return encoded form body
   * @throws IllegalArgumentException if the argument list is not name/value paired
   */
  private static String form(String... fields) {
    if (fields.length % 2 != 0) {
      throw new IllegalArgumentException("form fields must be name/value pairs");
    }
    StringBuilder builder = new StringBuilder();
    for (int index = 0; index < fields.length; index += 2) {
      if (index > 0) {
        builder.append('&');
      }
      builder.append(encode(fields[index])).append('=').append(encode(fields[index + 1]));
    }
    return builder.toString();
  }

  /**
   * Percent-encodes a single form field value.
   *
   * @param value raw field name or value
   * @return form-encoded representation
   */
  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  /**
   * Extracts one JSON string field from a small Platform API response.
   *
   * <p>This intentionally narrow scanner avoids adding a dependency to the devtools CLI path while
   * still honoring JSON string escaping for the fields this adapter consumes. It only accepts a
   * quoted string value after the named field and returns no raw response text to callers.
   *
   * @param body JSON response body kept in memory only for this parse
   * @param fieldName scalar field to extract
   * @return decoded field value when present
   */
  private static Optional<String> jsonString(String body, String fieldName) {
    String fieldToken = "\"" + fieldName + "\"";
    int searchFrom = 0;
    while (searchFrom < body.length()) {
      int fieldStart = body.indexOf(fieldToken, searchFrom);
      if (fieldStart < 0) {
        return Optional.empty();
      }
      int valueStart = stringValueStart(body, fieldStart + fieldToken.length());
      if (valueStart >= 0) {
        return readJsonString(body, valueStart);
      }
      searchFrom = fieldStart + 1;
    }
    return Optional.empty();
  }

  /**
   * Finds the opening content position of a JSON string field value.
   *
   * @param body JSON response body
   * @param afterFieldName index immediately after the quoted field name
   * @return first character inside the string value, or {@code -1} when the match is not a string
   */
  private static int stringValueStart(String body, int afterFieldName) {
    int colon = skipWhitespace(body, afterFieldName);
    if (colon >= body.length() || body.charAt(colon) != ':') {
      return -1;
    }
    int quote = skipWhitespace(body, colon + 1);
    if (quote >= body.length() || body.charAt(quote) != '"') {
      return -1;
    }
    return quote + 1;
  }

  /**
   * Advances over JSON whitespace.
   *
   * @param value string to scan
   * @param start first index to inspect
   * @return index of the next non-whitespace character, possibly {@code value.length()}
   */
  private static int skipWhitespace(String value, int start) {
    int index = start;
    while (index < value.length() && Character.isWhitespace(value.charAt(index))) {
      index++;
    }
    return index;
  }

  /**
   * Reads a JSON string from its first content character.
   *
   * @param body JSON response body
   * @param contentStart first character after the opening quote
   * @return decoded JSON string value, or empty when the string is incomplete
   */
  private static Optional<String> readJsonString(String body, int contentStart) {
    StringBuilder builder = new StringBuilder();
    int index = contentStart;
    while (index < body.length()) {
      char character = body.charAt(index);
      if (character == '"') {
        return Optional.of(builder.toString());
      }
      if (character == '\\') {
        int escapedIndex = index + 1;
        if (escapedIndex >= body.length()) {
          return Optional.empty();
        }
        index = appendJsonEscape(builder, body, escapedIndex);
      } else {
        builder.append(character);
        index++;
      }
    }
    return Optional.empty();
  }

  /**
   * Appends one JSON escape sequence and returns the next scan index.
   *
   * @param builder decoded JSON string accumulator
   * @param body JSON response body
   * @param escapedIndex index of the character immediately after the backslash
   * @return next index to inspect in {@code body}
   */
  private static int appendJsonEscape(StringBuilder builder, String body, int escapedIndex) {
    char escaped = body.charAt(escapedIndex);
    switch (escaped) {
      case 'b' -> builder.append('\b');
      case 'f' -> builder.append('\f');
      case 'n' -> builder.append('\n');
      case 'r' -> builder.append('\r');
      case 't' -> builder.append('\t');
      case 'u' -> {
        return appendUnicodeEscape(builder, body, escapedIndex);
      }
      default -> builder.append(escaped);
    }
    return escapedIndex + 1;
  }

  /**
   * Appends a JSON Unicode escape when valid, otherwise preserves the escaped marker.
   *
   * @param builder decoded JSON string accumulator
   * @param body JSON response body
   * @param escapedIndex index of the {@code u} escape marker
   * @return next index to inspect in {@code body}
   */
  private static int appendUnicodeEscape(StringBuilder builder, String body, int escapedIndex) {
    Optional<Character> unicode = unicodeEscape(body, escapedIndex + 1);
    if (unicode.isPresent()) {
      builder.append(unicode.orElseThrow());
      return escapedIndex + 5;
    }
    builder.append('u');
    return escapedIndex + 1;
  }

  /**
   * Decodes one four-hex-digit JSON Unicode escape.
   *
   * @param body JSON response body
   * @param hexStart first hex digit after the JSON Unicode escape prefix
   * @return decoded character when all four hex digits are present and valid
   */
  private static Optional<Character> unicodeEscape(String body, int hexStart) {
    if (hexStart + 4 > body.length()) {
      return Optional.empty();
    }
    int value = 0;
    for (int offset = 0; offset < 4; offset++) {
      int digit = Character.digit(body.charAt(hexStart + offset), 16);
      if (digit < 0) {
        return Optional.empty();
      }
      value = (value << 4) + digit;
    }
    return Optional.of((char) value);
  }

  /**
   * Sanitizes and normalizes a node-reported resolved source.
   *
   * <p>The release summary may include public fetch URIs, so this helper rejects control
   * characters, query strings, and fragments before accepting either a {@code crypta:} URI or a
   * bare Crypta key with a public scheme added.
   *
   * @param rawResolvedUri value reported by the node's fetch response
   * @return sanitized public source safe for publication evidence
   */
  private Optional<String> resolvedSource(String rawResolvedUri) {
    if (rawResolvedUri == null || rawResolvedUri.isBlank()) {
      return Optional.empty();
    }
    String value = rawResolvedUri.trim();
    if (value.indexOf('\n') >= 0
        || value.indexOf('\r') >= 0
        || value.indexOf('\u0000') >= 0
        || value.indexOf('?') >= 0
        || value.indexOf('#') >= 0) {
      return Optional.empty();
    }
    String lower = value.toLowerCase(java.util.Locale.ROOT);
    if (lower.startsWith("crypta:")) {
      return Optional.of(value);
    }
    if (lower.startsWith("usk@")
        || lower.startsWith("ssk@")
        || lower.startsWith("chk@")
        || lower.startsWith("ksk@")) {
      return Optional.of("crypta:" + value);
    }
    return Optional.empty();
  }

  /** Fetch response reduced to immutable bytes and optional public resolved-source metadata. */
  private static final class FetchResult {
    private final byte[] bytes;
    private final String resolvedSource;

    private FetchResult(byte[] bytes, String resolvedSource) {
      this.bytes = Objects.requireNonNull(bytes, "bytes").clone();
      this.resolvedSource = Objects.requireNonNull(resolvedSource, "resolvedSource");
    }

    /**
     * Returns a defensive copy of the fetched sidecar bytes.
     *
     * @return fetched bytes
     */
    byte[] bytes() {
      return bytes.clone();
    }

    Optional<String> resolvedSource() {
      return resolvedSource.isEmpty() ? Optional.empty() : Optional.of(resolvedSource);
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof FetchResult that)) {
        return false;
      }
      return Arrays.equals(bytes, that.bytes) && resolvedSource.equals(that.resolvedSource);
    }

    @Override
    public int hashCode() {
      return 31 * Arrays.hashCode(bytes) + resolvedSource.hashCode();
    }

    @Override
    public String toString() {
      return "FetchResult[bytesLength="
          + bytes.length
          + ", bytesHashCode="
          + Arrays.hashCode(bytes)
          + ", resolvedSource="
          + resolvedSource()
          + "]";
    }
  }
}
