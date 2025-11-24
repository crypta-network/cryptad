package network.crypta.clients.http;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import javax.naming.SizeLimitExceededException;
import network.crypta.support.Fields;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.HTTPUploadedFile;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.LineReadingInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Concrete {@link HTTPRequest} implementation that parses URIs, headers, and multipart bodies into
 * accessible parameters and buckets for plugin handlers.
 *
 * <p>This class is created by the toadlet layer to expose request data to plugins and other
 * components that expect the stable {@code HTTPRequest} API. It accepts either a pre-parsed {@link
 * URI} or discrete path/query inputs, extracts query parameters into a multimap, and—when a body is
 * present—parses {@code application/x-www-form-urlencoded} payloads or {@code multipart/form-data}
 * uploads into {@link Bucket} instances. Parsed form fields are preserved in insertion order, and
 * uploaded file bodies are stored in {@link RandomAccessBucket} instances supplied by the provided
 * {@link BucketFactory}. The object is intentionally mutable for the duration of request handling
 * but should be treated as confined to a single request-processing thread; it does not perform
 * internal synchronization.
 *
 * <p>Typical usage: create an instance inside request dispatch, read scalar parameters via {@link
 * #getParam(String)} or {@link #getIntParam(String)}, access uploaded files through {@link
 * #getUploadedFile(String)}, and finally call {@link #freeParts()} once processing is complete to
 * release bucket resources. Callers should not modify the returned buckets directly unless they
 * fully own their lifecycle.
 */
public class HTTPRequestImpl implements HTTPRequest {
  private static final Logger LOG = LoggerFactory.getLogger(HTTPRequestImpl.class);

  /**
   * This map is used to store all parameter values.
   *
   * <p>Don't access this map directly, use {@link #getParameterValueList(String)} and {@link
   * #isParameterSet(String)} instead
   */
  private final Map<String, List<String>> parameterNameValuesMap = new HashMap<>();

  /** the original URI as given to the constructor */
  private final URI uri;

  /** The headers sent by the client */
  private MultiValueTable<String, String> headers;

  /** The data sent in the connection */
  private final Bucket data;

  /** A hashmap of buckets that we use to store all the parts for a multipart/form-data request */
  private final HashMap<String, RandomAccessBucket> parts;

  private boolean freedParts;

  /** A map for uploaded files. */
  private final Map<String, HTTPUploadedFileImpl> uploadedFiles = new HashMap<>();

  private final BucketFactory bucketfactory;

  private final String method;

  // Legacy Logger threshold callbacks removed; use LOG.isDebugEnabled() directly for minor logs.

  /**
   * Builds a request wrapper for a URI that contains only a query string (no entity body).
   *
   * <p>The constructor immediately parses the raw query into parameter lists so callers can read
   * values through the convenience accessors. Use this overload when the transport layer already
   * provided a complete {@link URI} and no payload needs to be streamed.
   *
   * @param uri the absolute or path-only URI being requested; must not be {@code null}
   * @param method HTTP method name as received on the wire (for example, {@code "GET"} or {@code
   *     "HEAD"})
   */
  public HTTPRequestImpl(URI uri, String method) {
    this.uri = uri;
    this.parseRequestParameters(uri.getRawQuery(), false);
    this.data = null;
    this.parts = null;
    this.bucketfactory = null;
    this.method = method;
  }

  /**
   * Builds a request from discrete path and query components, decoding neither at construction
   * time.
   *
   * <p>This overload is useful for tests or callers that already separated the path from the query
   * string. The constructor assembles the components into a {@link URI}, parses the query portion
   * into parameters, and records the method verb. No body data is expected; multipart parsing will
   * not be attempted.
   *
   * @param path request path such as {@code "/test/test.html"}; should be URL-encoded if it was
   *     encoded on the wire
   * @param encodedQueryString URL-encoded query content like {@code "a=some+text&b=abc%40def.de"};
   *     may be {@code null} or empty to indicate no parameters
   * @param method HTTP method name that triggered the request
   * @throws URISyntaxException if the concatenated path and query cannot form a valid URI
   */
  public HTTPRequestImpl(String path, String encodedQueryString, String method)
      throws URISyntaxException {
    this.data = null;
    this.parts = null;
    this.bucketfactory = null;
    if ((encodedQueryString != null) && !encodedQueryString.isEmpty()) {
      this.uri = new URI(path + '?' + encodedQueryString);
    } else {
      this.uri = new URI(path);
    }
    this.method = method;
    this.parseRequestParameters(uri.getRawQuery(), false);
  }

  /**
   * Builds a request that includes headers and an optional entity body, enabling multipart parsing.
   *
   * <p>The constructor stores caller-supplied headers and bucket factory from the {@link
   * ToadletContext}, parses query parameters, and, when a body is present, attempts to extract form
   * fields or uploaded files depending on the detected {@code Content-Type}. Uploaded parts are
   * materialized as {@link RandomAccessBucket} instances owned by this request until {@link
   * #freeParts()} is called. Errors during multipart parsing are logged but do not abort
   * construction so that callers can fall back to alternative handling.
   *
   * @param uri the target URI as received over HTTP; must be syntactically valid
   * @param d bucket containing the raw request body; may be {@code null} when no payload is present
   * @param ctx toadlet context supplying request headers and a {@link BucketFactory} for allocating
   *     part buckets
   * @param method HTTP method name such as {@code "POST"}; stored verbatim for later retrieval
   */
  public HTTPRequestImpl(URI uri, Bucket d, ToadletContext ctx, String method) {
    this.uri = uri;
    this.headers = ctx.getHeaders();
    this.parseRequestParameters(uri.getRawQuery(), false);
    this.data = d;
    this.parts = new HashMap<>();
    this.bucketfactory = ctx.getBucketFactory();
    this.method = method;
    if (data != null) {
      try {
        this.parseMultiPartData();
      } catch (IOException ioe) {
        LOG.error("Temporary files error ? Could not parse: {}", ioe, ioe);
      }
    }
  }

  /**
   * Returns the decoded request path component without query or fragment parts.
   *
   * <p>The value is derived directly from the stored {@link URI} and therefore reflects any
   * normalization or encoding that occurred upstream. Callers can rely on this method to be side
   * effect free; it does not mutate internal state and can be invoked multiple times during request
   * processing.
   *
   * @return absolute or relative path portion of the request URI, never {@code null} but possibly
   *     empty for edge-case URIs
   */
  @Override
  public String getPath() {
    return this.uri.getPath();
  }

  /**
   * Reports whether any query or body parameters have been parsed for this request.
   *
   * <p>The method inspects the internal parameter multimap populated during construction or
   * multipart parsing. It does not trigger additional parsing work, making it inexpensive to call
   * in routing logic that needs to short-circuit when no form data is present.
   *
   * @return {@code true} when at least one parameter name is recorded; {@code false} otherwise
   */
  @Override
  public boolean hasParameters() {
    return !this.parameterNameValuesMap.isEmpty();
  }

  /**
   * Returns a live view of all parameter names currently stored on the request.
   *
   * <p>The returned collection reflects both query parameters and URL-encoded form fields that were
   * parsed at construction time. The collection is backed by the internal map, so later additions
   * or removals to that map are observable. Callers should not mutate the map itself, but iterating
   * the key set is safe for typical read scenarios.
   *
   * @return collection of parameter names; iteration order follows insertion order from the parser
   */
  @Override
  public Collection<String> getParameterNames() {
    return parameterNameValuesMap.keySet();
  }

  /**
   * Parse the query string and populate {@link #parameterNameValuesMap} with the lists of values
   * for each parameter. If this method is not called at all, all other methods would be useless.
   * Because they rely on the parameter map to be filled.
   *
   * @param queryString the query string in its raw form (not yet url-decoded)
   */
  private void parseRequestParameters(String queryString, boolean asParts) {

    if (LOG.isDebugEnabled()) LOG.debug("queryString is {} , doUrlDecoding=true", queryString);

    Map<String, List<String>> parameters = parseUriParameters(queryString, true);

    if (asParts) {
      for (Entry<String, List<String>> parameterValues : parameters.entrySet()) {
        List<String> values = parameterValues.getValue();
        String value = values.getLast();
        byte[] buf = value.getBytes(StandardCharsets.UTF_8);
        RandomAccessBucket b = new SimpleReadOnlyArrayBucket(buf);
        parts.put(parameterValues.getKey(), b);
        if (LOG.isDebugEnabled())
          LOG.debug("Added as part: name={} value={}", parameterValues.getKey(), value);
      }
    } else {
      parameterNameValuesMap.clear();
      parameterNameValuesMap.putAll(parameters);
    }
  }

  /**
   * Get the first value of the parameter with the given name.
   *
   * @param name the name of the parameter to get
   * @return the first value or <code>null</code> if the parameter was not set
   */
  private String getParameterValue(String name) {
    if (!this.isParameterSet(name)) {
      return null;
    }
    List<String> allValues = this.getParameterValueList(name);
    return allValues.getFirst();
  }

  /**
   * Get the list of all values for the parameter with the given name. When this method is called
   * for a given parameter for the first time, a new empty list of values is created and stored in
   * {@link #parameterNameValuesMap}. This list is returned and should be used to add parameter
   * values. If you only want to check if a parameter is set at all, you must use {@link
   * #isParameterSet(String)}.
   *
   * @param name the name of the parameter to get
   * @return the list of all values for this parameter that were parsed so far.
   */
  private List<String> getParameterValueList(String name) {
    return parameterNameValuesMap.computeIfAbsent(name, ignored -> new LinkedList<>());
  }

  /**
   * Parses a {@code name=value&...} query string into a multimap of parameter names to value lists.
   *
   * <p>This utility performs minimal allocation while preserving duplicate keys in the order they
   * are encountered. When {@code doUrlDecoding} is {@code true}, both names and values are decoded
   * with UTF-8 using {@link URLDecoder}. Tokens lacking an {@code '='} character are treated as
   * keys with an empty value. The method never returns {@code null}; absent or empty input produces
   * an empty map.
   *
   * @param queryString raw query portion as received on the wire; may be {@code null} or empty
   * @param doUrlDecoding whether to URL-decode names and values using UTF-8 before storing them
   * @return mutable map from parameter name to list of values in encounter order; the caller owns
   *     the returned structure
   */
  public static Map<String, List<String>> parseUriParameters(
      String queryString, boolean doUrlDecoding) {
    if (LOG.isDebugEnabled())
      LOG.debug("queryString is {} , doUrlDecoding={}", queryString, doUrlDecoding);

    Map<String, List<String>> parameters = new HashMap<>();
    if ((queryString == null) || queryString.isEmpty()) {
      return parameters;
    }

    StringTokenizer tokenizer = new StringTokenizer(queryString, "&");
    while (tokenizer.hasMoreTokens()) {
      String nameValueToken = tokenizer.nextToken();
      if (LOG.isDebugEnabled()) LOG.debug("Token: {}", nameValueToken);
      ParameterNameValue parsedToken = parseNameValueToken(nameValueToken, doUrlDecoding);
      parameters
          .computeIfAbsent(parsedToken.name(), ignored -> new ArrayList<>())
          .add(parsedToken.value());
    }

    return parameters;
  }

  private static ParameterNameValue parseNameValueToken(
      String nameValueToken, boolean doUrlDecoding) {
    String name;
    String value = "";
    int indexOfEqualsChar = nameValueToken.indexOf('=');
    if (indexOfEqualsChar < 0) {
      name = nameValueToken;
      if (LOG.isDebugEnabled()) LOG.debug("Name: {}", name);
    } else if (indexOfEqualsChar == nameValueToken.length() - 1) {
      name = nameValueToken.substring(0, indexOfEqualsChar);
      if (LOG.isDebugEnabled()) LOG.debug("Name: {}", name);
    } else {
      name = nameValueToken.substring(0, indexOfEqualsChar);
      value = nameValueToken.substring(indexOfEqualsChar + 1);
      if (LOG.isDebugEnabled()) LOG.debug("Name: {} Value: {}", name, value);
    }

    if (doUrlDecoding) {
      name = URLDecoder.decode(name, StandardCharsets.UTF_8);
      value = URLDecoder.decode(value, StandardCharsets.UTF_8);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Decoded name: {}", name);
        LOG.debug("Decoded value: {}", value);
      }
    }
    return new ParameterNameValue(name, value);
  }

  private record ParameterNameValue(String name, String value) {}

  /**
   * Builds a URL query string from a multimap of parameter names to values.
   *
   * <p>Each entry in {@code parameterValues} results in one token per value, joined with {@code
   * '&'} and encoded via {@link URLEncoder#encode(String, boolean)}. Names and values are appended
   * in map iteration order, and empty collections are serialized as an empty string. The method
   * does not prepend a leading question mark, allowing callers to embed the string in broader URLs
   * as needed.
   *
   * @param parameterValues map of parameter names to one or more values; null keys or values are
   *     not supported and should be filtered by the caller
   * @param doUrlEncoding {@code true} to perform full header-safe encoding; {@code false} to encode
   *     only unsafe characters
   * @return a newly constructed query string without a leading {@code '?';} may be empty when the
   *     input map has no entries
   */
  public static String createQueryString(
      Map<String, List<String>> parameterValues, boolean doUrlEncoding) {
    StringBuilder queryString = new StringBuilder();
    for (Entry<String, List<String>> parameter : parameterValues.entrySet()) {
      for (String value : parameter.getValue()) {
        if (!queryString.isEmpty()) {
          queryString.append('&');
        }
        queryString.append(URLEncoder.encode(parameter.getKey(), doUrlEncoding));
        queryString.append('=');
        queryString.append(URLEncoder.encode(value, doUrlEncoding));
      }
    }
    return queryString.toString();
  }

  /**
   * Indicates whether a parameter with the given name has been parsed.
   *
   * <p>The lookup checks the internal multimap exactly as populated by query parsing or URL-encoded
   * bodies. It does not inspect multipart parts; use {@link #isPartSet(String)} for that purpose.
   *
   * @param name parameter name to test; comparison is case-sensitive
   * @return {@code true} when the parameter map contains the name, even if its value list is empty
   */
  @Override
  public boolean isParameterSet(String name) {
    return this.parameterNameValuesMap.containsKey(name);
  }

  /**
   * Returns the first value of the named parameter or an empty string when absent.
   *
   * <p>This convenience method delegates to {@link #getParam(String, String)} with an empty
   * default, making it suitable for optional text fields. It performs no trimming or type
   * conversion; use typed helpers such as {@link #getIntParam(String)} when numeric coercion is
   * required.
   *
   * @param name parameter name to look up; case-sensitive
   * @return first parsed value or {@code ""} when the parameter is unset or empty
   */
  @Override
  public String getParam(String name) {
    return this.getParam(name, "");
  }

  /**
   * Returns the first value of the named parameter, falling back to a caller-supplied default.
   *
   * <p>The method is tolerant of missing or blank parameters: when the parameter does not exist or
   * its first value is the empty string, the provided {@code defaultValue} is returned unchanged.
   * Subsequent values in the list are ignored by design; callers needing all entries should call
   * {@link #getMultipleParam(String)} instead.
   *
   * @param name parameter name to retrieve; case-sensitive and expected to be URL-decoded
   * @param defaultValue value returned when no usable parameter is present; may be {@code null}
   * @return the first non-empty parameter value or {@code defaultValue} when no value is available
   */
  @Override
  public String getParam(String name, String defaultValue) {
    String value = this.getParameterValue(name);
    if (value == null || value.isEmpty()) {
      return defaultValue;
    }
    return value;
  }

  /**
   * Parses the named parameter as an integer, returning {@code 0} on failure.
   *
   * <p>The method delegates to {@link #getIntParam(String, int)} with a default of {@code 0}. It is
   * resilient to missing parameters and {@link NumberFormatException}s, making it useful for
   * optional numeric inputs such as pagination offsets.
   *
   * @param name parameter name to parse
   * @return parsed integer value or {@code 0} when absent or invalid
   */
  @Override
  public int getIntParam(String name) {
    return this.getIntParam(name, 0);
  }

  /**
   * Parses the named parameter as an integer with a caller-supplied fallback.
   *
   * <p>If the parameter is missing, {@code null}, or cannot be parsed as base-10, the provided
   * {@code defaultValue} is returned. Overflow and format errors are caught and suppressed. This
   * method reads only query or URL-encoded body parameters; multipart values are accessible through
   * {@link #getIntPart(String, int)}.
   *
   * @param name parameter name to parse
   * @param defaultValue value to return when parsing is not possible
   * @return parsed integer or {@code defaultValue} on absence or parse failure
   */
  @Override
  public int getIntParam(String name, int defaultValue) {
    if (!this.isParameterSet(name)) {
      return defaultValue;
    }
    String value = this.getParameterValue(name);
    if (value == null) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }

  /**
   * Parses a multipart form field as an integer with a default fallback.
   *
   * <p>The lookup is performed against {@link #parts}, which contains multipart form fields and
   * file uploads. The method reads the part content as UTF-8 text, then attempts integer parsing.
   * When the part is missing or unparseable, {@code defaultValue} is returned. Binary file uploads
   * are not appropriate inputs for this helper.
   *
   * @param name multipart field name to parse; must match the {@code name} attribute of the form
   *     input
   * @param defaultValue value returned when the part is absent or cannot be parsed
   * @return parsed integer value or {@code defaultValue} if the part is missing or invalid
   */
  @Override
  public int getIntPart(String name, int defaultValue) {
    if (!this.isPartSet(name)) {
      return defaultValue;
    }
    String value = this.getPartAsStringFailsafe(name, 32);
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }

  // Additional helpers (long, boolean, etc.) can be added when required.

  /**
   * Returns all values associated with a parameter name as an array.
   *
   * <p>The values come from query or URL-encoded body parsing and preserve encounter order. Missing
   * parameters yield an empty array rather than {@code null}. The returned array is a shallow copy,
   * so callers may modify it without affecting the underlying request state.
   *
   * @param name parameter name whose values should be returned
   * @return array of parameter values in encounter order; never {@code null}
   */
  @Override
  public String[] getMultipleParam(String name) {
    List<String> valueList = this.getParameterValueList(name);
    String[] values = new String[valueList.size()];
    valueList.toArray(values);
    return values;
  }

  /**
   * Returns all parseable integer values for the given parameter name.
   *
   * <p>Each raw string is parsed individually; values that cannot be converted are silently
   * skipped. The resulting array therefore contains only successful parses and may be shorter than
   * the number of supplied values. Order is preserved for all successfully parsed entries.
   *
   * @param name parameter name to read
   * @return array of integers parsed from the parameter values; empty when none are parseable
   */
  @Override
  public int[] getMultipleIntParam(String name) {
    List<String> valueList = this.getParameterValueList(name);

    // try parsing all values and put the valid Integers in a new list
    List<Integer> intValueList = new ArrayList<>();
    for (String s : valueList) {
      try {
        intValueList.add(Integer.valueOf(s));
      } catch (Exception e) {
        // ignore invalid parameter values
      }
    }

    // convert the valid Integers to an array of ints
    int[] values = new int[intValueList.size()];
    for (int i = 0; i < intValueList.size(); i++) {
      values[i] = intValueList.get(i);
    }
    return values;
  }

  // Additional helpers for other primitive types can be added when required.

  /**
   * Parse submitted data from a bucket. Note that if this is application/x-www-form-urlencoded, it
   * will come out as params, whereas if it is multipart/form-data it will be separated into
   * buckets.
   */
  private void parseMultiPartData() throws IOException {
    if (data == null) {
      return;
    }

    String contentTypeHeader = this.headers.getFirst("content-type");
    if (contentTypeHeader == null) {
      return;
    }

    if (LOG.isDebugEnabled()) LOG.debug("Uploaded content-type: {}", contentTypeHeader);

    String[] contentTypeParts = contentTypeHeader.split(";");
    if (isUrlEncoded(contentTypeParts)) {
      parseUrlEncodedBody();
      return;
    }

    if (!isMultipartFormData(contentTypeParts)) {
      return;
    }

    String boundary = extractBoundary(contentTypeParts);
    if ((boundary == null) || boundary.isEmpty()) {
      return;
    }

    processMultipartBody(boundary);
  }

  private boolean isUrlEncoded(String[] contentTypeParts) {
    return contentTypeParts.length > 0
        && contentTypeParts[0].equalsIgnoreCase("application/x-www-form-urlencoded");
  }

  private void parseUrlEncodedBody() throws IOException {
    if (data.size() > 1024 * 1024) throw new IOException("Too big");
    byte[] buf = BucketTools.toByteArray(data);
    String body = new String(buf, StandardCharsets.US_ASCII);
    parseRequestParameters(body, true);
  }

  private boolean isMultipartFormData(String[] contentTypeParts) {
    return contentTypeParts.length >= 2
        && contentTypeParts[0].trim().equalsIgnoreCase("multipart/form-data");
  }

  private String extractBoundary(String[] contentTypeParts) {
    String boundary = null;
    for (String contentTypePart : contentTypeParts) {
      String[] subparts = contentTypePart.split("=");
      if ((subparts.length == 2) && subparts[0].trim().equalsIgnoreCase("boundary")) {
        boundary = subparts[1];
      }
    }
    return boundary;
  }

  private void processMultipartBody(String rawBoundary) throws IOException {
    String boundary = normalizeBoundary(rawBoundary);

    if (LOG.isDebugEnabled()) LOG.debug("Boundary is: {}", boundary);

    try (InputStream is = this.data.getInputStream();
        LineReadingInputStream lis = new LineReadingInputStream(is)) {

      if (!advanceToFirstBoundary(is, lis, boundary)) {
        return;
      }

      readMultipartParts(is, lis, "\r\n" + boundary);
    }
  }

  private String normalizeBoundary(String boundary) {
    String normalized = boundary;
    if (!normalized.isEmpty() && normalized.charAt(0) == '"') {
      normalized = normalized.substring(1);
    }
    if (!normalized.isEmpty() && normalized.charAt(normalized.length() - 1) == '"') {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return "--" + normalized;
  }

  private boolean advanceToFirstBoundary(
      InputStream is, LineReadingInputStream lis, String boundary) throws IOException {
    String line = lis.readLine(100, 100, false); // really it's US-ASCII, but ISO-8859-1 is close.
    while ((is.available() > 0) && (line != null) && !line.equals(boundary)) {
      line = lis.readLine(100, 100, false);
    }
    return boundary.equals(line);
  }

  private void readMultipartParts(
      InputStream is, LineReadingInputStream lis, String boundaryWithPrefix) throws IOException {
    boolean finished = false;
    while (!finished && is.available() > 0) {
      PartMetadata metadata = readPartMetadata(lis);
      if (metadata.name() != null) {
        RandomAccessBucket filedata = this.bucketfactory.makeBucket(is.available());
        writePartData(is, boundaryWithPrefix, filedata);

        parts.put(metadata.name(), filedata);
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Name = {} length = {} filename = {}",
              metadata.name(),
              filedata.size(),
              metadata.filename());
        }
        if (metadata.filename() != null) {
          uploadedFiles.put(
              metadata.name(),
              new HTTPUploadedFileImpl(metadata.filename(), metadata.contentType(), filedata));
        }
      }

      // Consume the remainder of the boundary line (e.g., trailing CRLF or "--") so the next
      // metadata read starts at the following headers, and detect the closing boundary.
      String boundarySuffix = lis.readLine(200, 200, false);
      if (boundarySuffix == null || boundarySuffix.startsWith("--")) {
        finished = true; // reached the final boundary
      }
    }
  }

  private PartMetadata readPartMetadata(LineReadingInputStream lis) throws IOException {
    MutablePartMetadata metadata = new MutablePartMetadata();
    String line;

    while ((line = lis.readLine(200, 200, true)) != null) { // should be UTF-8
      if (line.isEmpty()) {
        break;
      }

      Header header = parseHeader(line);
      if (header != null) {
        if (header.name().equalsIgnoreCase("Content-Disposition")) {
          parseContentDisposition(header.value(), metadata);
        } else if (header.name().equalsIgnoreCase("Content-Type")) {
          metadata.contentType = header.value();
          if (LOG.isDebugEnabled()) LOG.debug("Parsed type: {}", metadata.contentType);
        }
      }
    }

    return metadata.toImmutable();
  }

  private Header parseHeader(String line) {
    String[] lineparts = line.split(":", 2);
    if (lineparts.length < 2) {
      return null;
    }
    return new Header(lineparts[0].trim(), lineparts[1].trim());
  }

  private void parseContentDisposition(String headerValue, MutablePartMetadata metadata) {
    String[] valueparts = headerValue.split(";");
    for (String valuepart : valueparts) {
      String[] subparts = valuepart.split("=", 2);
      if (subparts.length != 2) {
        continue;
      }
      String fieldname = subparts[0].trim();
      String value = stripWrappingQuotes(subparts[1].trim());
      if (fieldname.equalsIgnoreCase("name")) {
        metadata.name = value;
      } else if (fieldname.equalsIgnoreCase("filename")) {
        metadata.filename = value;
      }
    }
  }

  private String stripWrappingQuotes(String value) {
    if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
      return value.substring(1, value.length() - 1);
    }
    return value;
  }

  private void writePartData(InputStream is, String boundaryWithPrefix, RandomAccessBucket filedata)
      throws IOException {
    byte[] boundaryBytes = boundaryWithPrefix.getBytes(StandardCharsets.UTF_8);
    try (OutputStream bucketos = filedata.getOutputStream()) {
      int offset = 0;
      int read;
      while ((read = is.read()) != -1) {
        byte b = (byte) read;

        if (b == boundaryBytes[offset]) {
          offset++;
          if (offset == boundaryBytes.length) {
            break;
          }
        } else if (offset > 0) {
          bucketos.write(boundaryBytes, 0, offset);
          offset = (boundaryBytes[0] == b) ? 1 : 0;
          if (offset == 0) {
            bucketos.write(b);
          }
        } else {
          bucketos.write(b);
        }
      }
    }
  }

  private record PartMetadata(String name, String filename, String contentType) {}

  private record Header(String name, String value) {}

  private static final class MutablePartMetadata {
    private String name;
    private String filename;
    private String contentType;

    private PartMetadata toImmutable() {
      return new PartMetadata(name, filename, contentType);
    }
  }

  /**
   * Retrieves the uploaded file metadata and payload for the named multipart field.
   *
   * <p>The returned {@link HTTPUploadedFile} encapsulates the original filename, content type, and
   * a {@link Bucket} containing the file data. The object is backed by internal buckets managed by
   * this request and remains valid until {@link #freeParts()} is invoked. If the field name refers
   * to a regular form value rather than a file upload, this method returns {@code null}.
   *
   * @param name multipart field name corresponding to the file input element
   * @return uploaded file wrapper or {@code null} when no file part exists for the given name
   */
  @Override
  public HTTPUploadedFile getUploadedFile(String name) {
    return uploadedFiles.get(name);
  }

  /**
   * Retrieves the bucket for a multipart field or file by name.
   *
   * <p>The returned {@link RandomAccessBucket} contains the raw bytes of the part body and remains
   * owned by this request instance. Callers should avoid freeing or modifying the bucket unless
   * they fully control the lifecycle. Invoking this method after {@link #freeParts()} results in an
   * {@link IllegalStateException}.
   *
   * @param name multipart field name to look up
   * @return bucket containing the part data, or {@code null} if the field is absent
   * @throws IllegalStateException if the parts have already been freed
   */
  @Override
  public RandomAccessBucket getPart(String name) {
    if (freedParts) throw new IllegalStateException("Already freed");
    return this.parts.get(name);
  }

  /**
   * Indicates whether a multipart part with the given name exists.
   *
   * <p>Unlike {@link #isParameterSet(String)}, this method inspects only multipart/form-data parts.
   * It throws an exception if parts were already freed to avoid silent misuse.
   *
   * @param name multipart field name to test
   * @return {@code true} when a part with the name has been parsed; {@code false} otherwise
   * @throws IllegalStateException if {@link #freeParts()} was already called
   */
  @Override
  public boolean isPartSet(String name) {
    if (freedParts) throw new IllegalStateException("Already freed");
    if (parts == null) return false;

    return this.parts.containsKey(name);
  }

  /**
   * Returns the part content as a UTF-8 string, truncated to {@code maxlength} bytes if necessary.
   *
   * <p>When the part is absent, an empty array is returned and the conversion yields an empty
   * string. The method is lenient and does not throw on length overflow; callers needing strict
   * enforcement should use {@link #getPartAsStringThrowing(String, int)}.
   *
   * @param name multipart field name
   * @param maxlength maximum number of bytes to read before truncation
   * @return UTF-8 decoded string, possibly empty when the part is missing
   * @throws IllegalStateException if called after {@link #freeParts()}
   */
  @Override
  public String getPartAsString(String name, int maxlength) {
    return new String(getPartAsBytes(name, maxlength), StandardCharsets.UTF_8);
  }

  /**
   * Returns the part content as a UTF-8 string, enforcing presence and maximum length.
   *
   * <p>This variant throws {@link NoSuchElementException} when the part is missing and {@link
   * SizeLimitExceededException} when the part size exceeds {@code maxLength}. It is useful for
   * handlers that must differentiate between absent inputs and oversized submissions.
   *
   * @param name multipart field name
   * @param maxLength maximum allowable part size in bytes
   * @return decoded UTF-8 string representing the part content
   * @throws NoSuchElementException if the named part does not exist
   * @throws SizeLimitExceededException if the part size exceeds {@code maxLength}
   * @throws IllegalStateException if the parts have already been freed
   */
  @Override
  public String getPartAsStringThrowing(String name, int maxLength)
      throws NoSuchElementException, SizeLimitExceededException {
    if (freedParts) throw new IllegalStateException("Already freed");
    Bucket part = this.parts.get(name);

    if (part == null) throw new NoSuchElementException(name);

    if (part.size() > maxLength) throw new SizeLimitExceededException();

    return getPartAsLimitedString(part, maxLength);
  }

  /**
   * Returns the part content as a UTF-8 string, gracefully handling missing parts or size limits.
   *
   * <p>If the part is absent, an empty string is returned. When the part exceeds {@code maxLength},
   * the content is truncated to the provided limit rather than throwing an exception, making this
   * helper suitable for UI echo or logging of small previews.
   *
   * @param name multipart field name
   * @param maxLength maximum number of bytes to read from the part
   * @return decoded UTF-8 string, possibly empty, truncated to {@code maxLength} bytes
   * @throws IllegalStateException if called after {@link #freeParts()}
   */
  @Override
  public String getPartAsStringFailsafe(String name, int maxLength) {
    if (freedParts) throw new IllegalStateException("Already freed");
    Bucket part = this.parts.get(name);
    return part == null ? "" : getPartAsLimitedString(part, maxLength);
  }

  private String getPartAsLimitedString(Bucket part, int maxLength) {
    return new String(getPartAsLimitedBytes(part, maxLength), StandardCharsets.UTF_8);
  }

  /**
   * Returns the part content as a byte array, truncating when necessary.
   *
   * <p>This method reads up to {@code maxlength} bytes and returns them in a newly allocated array.
   * Missing parts yield an empty array. Use {@link #getPartAsBytesThrowing(String, int)} to enforce
   * strict size limits.
   *
   * @param name multipart field name
   * @param maxlength maximum number of bytes to read
   * @return byte array containing up to {@code maxlength} bytes; empty when part is absent
   * @throws IllegalStateException if invoked after {@link #freeParts()}
   */
  @Override
  public byte[] getPartAsBytes(String name, int maxlength) {
    if (freedParts) throw new IllegalStateException("Already freed");
    Bucket part = this.parts.get(name);
    if (part == null) return new byte[0];

    if (part.size() > maxlength) return new byte[0];

    try (InputStream is = part.getInputStream();
        DataInputStream dis = new DataInputStream(is)) {
      byte[] buf = new byte[(int) Math.min(part.size(), maxlength)];
      dis.readFully(buf);
      return buf;
    } catch (IOException ioe) {
      LOG.error("Caught IOE:{}", ioe.getMessage());
      return new byte[0];
    }
  }

  /**
   * Returns the part content as bytes, throwing on absence or excessive size.
   *
   * <p>This variant is suitable for security-sensitive handlers that must reject missing or
   * oversized inputs. It reads the entire part and enforces {@code maxLength} strictly, throwing
   * {@link SizeLimitExceededException} when the limit is exceeded.
   *
   * @param name multipart field name to read
   * @param maxLength maximum allowed part size in bytes
   * @return byte array containing the full part content
   * @throws NoSuchElementException if the part is not present
   * @throws SizeLimitExceededException if the part exceeds {@code maxLength}
   * @throws IllegalStateException if called after {@link #freeParts()}
   */
  @Override
  public byte[] getPartAsBytesThrowing(String name, int maxLength)
      throws NoSuchElementException, SizeLimitExceededException {
    if (freedParts) throw new IllegalStateException("Already freed");
    Bucket part = this.parts.get(name);

    if (part == null) throw new NoSuchElementException(name);

    if (part.size() > maxLength) throw new SizeLimitExceededException();

    return getPartAsLimitedBytes(part, maxLength);
  }

  /**
   * Returns the part content as bytes, tolerating missing parts and truncating on demand.
   *
   * <p>When the part is absent, the method returns an empty array. If the part size exceeds {@code
   * maxLength}, only the first {@code maxLength} bytes are returned, making this helper useful for
   * previewing or hashing without strict enforcement.
   *
   * @param name multipart field name to read
   * @param maxLength maximum number of bytes to include in the result
   * @return byte array (possibly empty) with up to {@code maxLength} bytes from the part
   * @throws IllegalStateException if parts have been freed
   */
  @Override
  public byte[] getPartAsBytesFailsafe(String name, int maxLength) {
    if (freedParts) throw new IllegalStateException("Already freed");
    Bucket part = this.parts.get(name);
    return part == null ? new byte[0] : getPartAsLimitedBytes(part, maxLength);
  }

  private byte[] getPartAsLimitedBytes(Bucket part, int maxLength) {
    try (InputStream is = part.getInputStream();
        DataInputStream dis = new DataInputStream(is)) {
      byte[] buf = new byte[(int) Math.min(part.size(), maxLength)];
      dis.readFully(buf, 0, buf.length);
      return buf;
    } catch (IOException ioe) {
      LOG.error("Caught IOE:{}", ioe.getMessage());
      return new byte[0];
    }
  }

  /**
   * Releases resources associated with parsed multipart parts.
   *
   * <p>The method iterates over all stored part buckets and invokes {@link Bucket#free()} on each,
   * then clears internal maps and marks the request as freed to prevent accidental reuse. Callers
   * should invoke this exactly once after they are done reading any multipart data. Subsequent
   * calls to part accessors will throw {@link IllegalStateException}.
   */
  @Override
  public void freeParts() {
    if (this.parts == null) return;

    for (Bucket b : this.parts.values()) {
      b.free();
    }
    parts.clear();
    freedParts = true;
    // Do not free data. Caller is responsible for that.
  }

  /**
   * Parses a parameter as a {@code long}, returning a default on failure.
   *
   * <p>The method uses {@link Fields#parseLong(String)} to support decimal and size-suffix formats
   * recognized elsewhere in the codebase. When the parameter is missing or malformed, the supplied
   * {@code defaultValue} is returned without throwing.
   *
   * @param name parameter name to parse
   * @param defaultValue value returned when parsing fails or the parameter is absent
   * @return parsed {@code long} value or {@code defaultValue} on error
   */
  @Override
  public long getLongParam(String name, long defaultValue) {
    if (!this.isParameterSet(name)) {
      return defaultValue;
    }
    String value = this.getParameterValue(name);
    try {
      return Fields.parseLong(value);
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }

  /**
   * Container for uploaded files in HTTP POST requests.
   *
   * <p>Instances wrap the filename, content type, and backing {@link Bucket} created during
   * multipart parsing. The bucket is owned by the enclosing {@link HTTPRequestImpl} and remains
   * valid until {@link HTTPRequestImpl#freeParts()} is invoked. Callers should treat this class as
   * a lightweight data carrier rather than a full file abstraction.
   */
  public static class HTTPUploadedFileImpl implements HTTPUploadedFile {

    /** The filename. */
    private final String filename;

    /** The content type. */
    private final String contentType;

    /** The data. */
    private final Bucket data;

    /**
     * Creates a new uploaded file wrapper backed by the provided bucket.
     *
     * <p>The constructor performs no validation beyond assignment. The {@code data} bucket is not
     * copied, so callers must ensure it remains valid for the duration of use.
     *
     * @param filename original filename supplied by the client; may be empty but not {@code null}
     * @param contentType MIME type declared for the upload; may be {@code null} when unspecified
     * @param data bucket containing the file contents; ownership is retained by the enclosing
     *     request
     */
    public HTTPUploadedFileImpl(String filename, String contentType, Bucket data) {
      this.filename = filename;
      this.contentType = contentType;
      this.data = data;
    }

    /**
     * Returns the MIME content type declared for the uploaded file.
     *
     * @return content type string as provided in the multipart headers; may be {@code null}
     */
    @Override
    public String getContentType() {
      return contentType;
    }

    /**
     * Returns the bucket containing the file data.
     *
     * @return {@link Bucket} with the uploaded bytes; callers must not free it directly
     */
    @Override
    public Bucket getData() {
      return data;
    }

    /**
     * Returns the filename reported by the client for this upload.
     *
     * @return original filename; may be empty but never {@code null}
     */
    @Override
    public String getFilename() {
      return filename;
    }
  }

  /**
   * Returns the HTTP method name exactly as supplied when the request was constructed.
   *
   * @return method token such as {@code "GET"}, {@code "POST"}, or any custom verb
   */
  @Override
  public String getMethod() {
    return method;
  }

  /**
   * Returns the raw body bucket as supplied at construction time.
   *
   * <p>The bucket may represent a streaming or in-memory payload depending on the transport layer.
   * Callers should not free it unless they own the overall request lifecycle.
   *
   * @return bucket containing the unparsed request body; may be {@code null} for bodyless methods
   */
  @Override
  public Bucket getRawData() {
    return data;
  }

  /**
   * Returns the first header value for the given lower-case header name.
   *
   * <p>Header lookup is case-sensitive and expects names to be pre-normalized to lower case to
   * avoid ambiguity. When the header is missing, {@code null} is returned. An {@link
   * IllegalArgumentException} is thrown if the supplied name is not lower-case, enforcing a
   * consistent convention across the codebase.
   *
   * @param name lower-case header name to retrieve
   * @return first matching header value or {@code null} when absent
   * @throws IllegalArgumentException if {@code name} contains any upper-case characters
   */
  @Override
  public String getHeader(String name) {
    if (!name.equals(name.toLowerCase())) {
      throw new IllegalArgumentException("Header name must be lower-case");
    }
    return this.headers.getFirst(name.toLowerCase());
  }

  /**
   * Returns the Content-Length header parsed as an integer, or {@code -1} when absent.
   *
   * <p>The method assumes the header was already validated by upstream parsing and therefore does
   * not catch {@link NumberFormatException}. It is intended for internal consumers that trust
   * request normalization.
   *
   * @return content length in bytes, or {@code -1} if no header was supplied
   */
  @Override
  public int getContentLength() {
    String slen = headers.getFirst("content-length");
    if (slen == null) return -1;
    // it is already parsed, so NumberFormatException can not happen here
    return Integer.parseInt(slen);
  }

  @Override
  public String[] getParts() {
    if (freedParts) throw new IllegalStateException("Already freed");
    return parts.keySet().toArray(new String[0]);
  }

  /**
   * Indicates whether the request was marked as incognito by a query parameter.
   *
   * <p>The method checks for a parameter named {@code incognito} and returns its boolean value
   * using {@link Boolean#parseBoolean(String)} semantics, defaulting to {@code false} when missing.
   *
   * @return {@code true} when the {@code incognito} parameter is present and set to a truthy value
   */
  @Override
  public boolean isIncognito() {
    if (isParameterSet("incognito")) return Boolean.parseBoolean(getParam("incognito"));
    return false;
  }

  /**
   * Heuristically determines whether the User-Agent header indicates Google Chrome.
   *
   * <p>The method performs a substring search for {@code "Chrome"} in the {@code user-agent}
   * header. It is intentionally simple and may produce false positives for Chromium-based browsers;
   * callers should use it only for coarse feature hints.
   *
   * @return {@code true} if the user-agent contains {@code "Chrome"}; {@code false} otherwise
   */
  @Override
  public boolean isChrome() {
    String ua = getHeader("user-agent");
    if (ua != null) {
      return ua.contains("Chrome");
    }
    return false;
  }
}
