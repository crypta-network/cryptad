package network.crypta.clients.http;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a single cookie sent by an HTTP client and parsed from the {@code Cookie} request
 * header. Instances hold the raw attributes supplied by the peer but defer validation until a
 * caller actually reads an attribute via the accessors. That lazy validation mirrors the inbound
 * nature of these cookies: many user agents attach large cookie headers while the server consumes
 * only a subset, so avoiding upfront parsing reduces CPU overhead for unused cookies.
 *
 * <p>Typical call flow is {@link #parseHeader(String)} during request handling, followed by
 * optional reads such as {@link #getName()} or {@link #getValue()} once the handler decides a
 * cookie is relevant. Parsed attributes are cached after the first successful validation to avoid
 * repeated work. The class is intentionally <strong>not thread-safe</strong>; treat each instance
 * as request-scoped and never share it across handlers or worker threads.
 *
 * <p>Notable behaviors include preservation of the original attribute map for diagnostics, strict
 * validation that throws {@link IllegalArgumentException} on malformed names, values, domains, or
 * paths, and refusal to encode back into headers because inbound cookies should not be re-emitted
 * without explicit reconstruction. Mutability is limited to internal lazy-initialization caches;
 * callers observe effectively immutable state once a field has been validated.
 *
 * <ul>
 *   <li>Responsibilities: parse inbound cookie headers, lazily validate attributes, expose
 *       canonicalized getters.
 *   <li>Trade-offs: reduced upfront CPU at the cost of possible runtime exceptions when attributes
 *       are first accessed.
 *   <li>Thread-safety: none; allocate per request to avoid cross-thread sharing.
 * </ul>
 *
 * @see Cookie
 * @see #parseHeader(String)
 * @author xor (xor@freenetproject.org)
 */
public final class ReceivedCookie extends Cookie {
  private static final Logger LOG = LoggerFactory.getLogger(ReceivedCookie.class);

  private static final int DEFAULT_COOKIE_CAPACITY = 4;
  private static final URI PLACEHOLDER_PATH = URI.create("/");
  private static final String PLACEHOLDER_NAME = "receivedcookie";
  private static final Instant PLACEHOLDER_EXPIRATION = Instant.MAX;

  private String notValidatedName;

  private final Map<String, String> content;
  private URI domain;
  private URI path;
  private String name;
  private String value;

  /**
   * Constructor for creating cookies from parsed key-value pairs.
   *
   * <p>Does not validate the names or values of the keys, each attribute is validated at the first
   * call to its getter method. Therefore, no CPU time is wasted if the client sends cookies which
   * we do not use.
   */
  private ReceivedCookie(String myName, Map<String, String> myContent) {
    super(PLACEHOLDER_PATH, PLACEHOLDER_NAME, "", PLACEHOLDER_EXPIRATION);
    // We do not validate the input here, we only parse it if someone actually tries to access this
    // cookie.
    notValidatedName = myName;
    content = myContent;
  }

  /**
   * Parses the raw value of an HTTP {@code Cookie} header into individual {@link ReceivedCookie}
   * instances while preserving arrival order.
   *
   * <p>The parser accepts multiple cookie pairs within a single header and tolerates multiple
   * {@code Cookie} header lines per request. Attribute names beginning with {@code $} are treated
   * as cookie attributes and attached to the current cookie; other key-value pairs start a new
   * cookie entry. Values may be quoted or unquoted and are trimmed of surrounding whitespace but
   * otherwise left untouched. Validation of names and values is deferred to the corresponding
   * accessor methods so unused cookies do not incur additional cost. The returned list is mutable
   * to allow callers to filter or reorder if needed.
   *
   * @param httpHeader Raw header value that follows the {@code Cookie:} prefix in the request.
   * @return List of parsed cookies in request order; entries validate lazily on first attribute
   *     access.
   * @throws ParseException If the general cookie formatting or quoting rules are violated.
   */
  static List<ReceivedCookie> parseHeader(String httpHeader) throws ParseException {

    if (LOG.isDebugEnabled()) LOG.debug("Received HTTP cookie header:{}", httpHeader);

    char[] header = httpHeader.toCharArray();

    String currentCookieName = null;
    Map<String, String> currentCookieContent = HashMap.newHashMap(16);

    ArrayList<ReceivedCookie> cookies =
        new ArrayList<>(DEFAULT_COOKIE_CAPACITY); // Capacity tuned for typical cookie counts

    int index = 0;
    while (index < header.length) {
      index = skipWhitespace(header, index);
      if (index >= header.length) {
        break;
      }

      ParsedAttribute attribute = parseAttribute(header, httpHeader, index);
      index = attribute.nextIndex;

      if (currentCookieName == null) {
        currentCookieName = applyNameOrAttribute(attribute, currentCookieContent);
      } else if (isCookieAttribute(attribute.key())) {
        currentCookieContent.put(attribute.key(), attribute.value());
      } else {
        cookies.add(new ReceivedCookie(currentCookieName, currentCookieContent));
        currentCookieName = attribute.key();
        currentCookieContent = HashMap.newHashMap(16);
        currentCookieContent.put(currentCookieName, attribute.value());
      }
    }

    if (currentCookieName != null) {
      cookies.add(new ReceivedCookie(currentCookieName, currentCookieContent));
    }

    return cookies;
  }

  private static String applyNameOrAttribute(
      ParsedAttribute attribute, Map<String, String> currentCookieContent) {
    if (isCookieAttribute(attribute.key())) {
      currentCookieContent.put(attribute.key(), attribute.value());
      return null;
    }

    currentCookieContent.put(attribute.key(), attribute.value());
    return attribute.key();
  }

  private static ParsedAttribute parseAttribute(char[] header, String httpHeader, int startIndex)
      throws ParseException {
    int index = startIndex;

    int keyBeginIndex = index;
    while (index < header.length && header[index] != '=' && header[index] != ';') {
      index++;
    }

    int keyEndIndex = index;
    while (keyEndIndex > keyBeginIndex && Character.isWhitespace(header[keyEndIndex - 1])) {
      keyEndIndex--;
    }

    String key =
        new String(header, keyBeginIndex, keyEndIndex - keyBeginIndex).toLowerCase(Locale.ROOT);

    if (key.isEmpty()) {
      throw new ParseException("Invalid cookie: Contains an empty key: " + httpHeader, index);
    }

    if (index >= header.length) {
      return new ParsedAttribute(key, "", header.length);
    }

    char separator = header[index];
    if (separator == ';') {
      return new ParsedAttribute(key, "", index + 1);
    }

    index++;
    index = skipWhitespace(header, index);

    if (index >= header.length) {
      return new ParsedAttribute(key, "", header.length);
    }

    if (header[index] == '\"') {
      return parseQuotedValue(header, httpHeader, key, index + 1);
    }

    return parseUnquotedValue(header, key, index);
  }

  private static ParsedAttribute parseQuotedValue(
      char[] header, String httpHeader, String key, int valueBeginIndex) throws ParseException {
    int index = valueBeginIndex;
    while (index < header.length && header[index] != '\"') {
      index++;
    }

    if (index >= header.length) {
      throw new ParseException("Invalid cookie: Unterminated quoted value: " + httpHeader, index);
    }

    String value = new String(header, valueBeginIndex, index - valueBeginIndex);
    index++;

    index = skipWhitespace(header, index);
    if (index < header.length && header[index] != ';') {
      throw new ParseException(
          "Invalid cookie: Missing terminating semicolon after value quotation: " + httpHeader,
          index);
    }

    if (index < header.length) {
      index++;
    }

    return new ParsedAttribute(key, value, index);
  }

  private static ParsedAttribute parseUnquotedValue(
      char[] header, String key, int valueBeginIndex) {
    int index = valueBeginIndex;
    while (index < header.length && header[index] != ';') {
      index++;
    }

    int valueEndIndex = index;
    while (valueEndIndex > valueBeginIndex && Character.isWhitespace(header[valueEndIndex - 1])) {
      valueEndIndex--;
    }

    String value = new String(header, valueBeginIndex, valueEndIndex - valueBeginIndex);

    if (index < header.length) {
      index++;
    }

    return new ParsedAttribute(key, value, index);
  }

  private static int skipWhitespace(char[] header, int index) {
    while (index < header.length && Character.isWhitespace(header[index])) {
      index++;
    }
    return index;
  }

  private static boolean isCookieAttribute(String key) {
    return key.charAt(0) == '$';
  }

  private record ParsedAttribute(String key, String value, int nextIndex) {}

  /**
   * Returns the validated cookie name, computing and caching it on first access.
   *
   * <p>The raw name provided by the user agent is validated lazily to avoid work when the cookie is
   * never consumed. Validation lowers the case, checks for illegal separator characters, and
   * enforces the outbound naming rules inherited from {@link Cookie}. After successful validation,
   * the result is cached and reused for later calls. If the stored name violates the constraints,
   * the method throws an {@link IllegalArgumentException} to surface the malformed header to
   * callers.
   *
   * @return Canonicalized cookie name; never {@code null} once validation succeeds and cached.
   * @throws IllegalArgumentException If the stored name fails, RFC-inspired validation checks.
   */
  @Override
  public String getName() {
    if (name == null) {
      name = Cookie.validateName(notValidatedName);
      notValidatedName = null;
    }

    return name;
  }

  /**
   * Returns the validated domain attribute as a {@link URI}, or {@code null} when absent.
   *
   * <p>The domain is parsed only when first requested to conserve resources for unused cookies. If
   * the client omitted a {@code $domain} attribute, the method returns {@code null}. Otherwise, the
   * attribute is validated via {@link Cookie#validateDomain(String)} and cached. Invalid domain
   * strings lead to {@link IllegalArgumentException}, wrapping the underlying {@link
   * URISyntaxException} to unify error signaling for callers.
   *
   * @return Normalized domain URI or {@code null} when the client did not specify a domain.
   * @throws IllegalArgumentException If domain parsing or validation fails for the stored value.
   */
  @Override
  public URI getDomain() {
    if (domain == null) {
      try {
        String domainString = content.get("$domain");
        if (domainString == null) return null;

        domain = Cookie.validateDomain(domainString);
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException(e);
      }
    }

    return domain;
  }

  /**
   * Returns the validated path attribute, defaulting to {@code null} when unspecified.
   *
   * <p>Path parsing is performed lazily using {@link Cookie#validatePath(URI)} to ensure the value
   * is a relative URI beginning with {@code /}. The validated result is cached to avoid repeat work
   * on later invocations. If the stored path string is malformed or violates the validation rules,
   * the method throws {@link IllegalArgumentException} to alert request handlers of bad input.
   *
   * @return Canonicalized path URI or {@code null} if no {@code $path} attribute was supplied.
   * @throws IllegalArgumentException If path parsing or validation fails for the recorded value.
   */
  @Override
  public URI getPath() {
    if (path == null) {
      try {
        path = Cookie.validatePath(content.get("$path"));
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException(e);
      }
    }

    return path;
  }

  /**
   * Returns the validated cookie value associated with the cookie name.
   *
   * <p>The value is fetched from the parsed attribute map, validated for illegal characters via the
   * shared {@link Cookie#validateValue(String)} routine, and cached for later calls. Because
   * validation occurs on demand, malformed values encountered here raise {@link
   * IllegalArgumentException} even if the cookie was otherwise accepted during parsing. Callers
   * should be prepared to handle that exception when processing untrusted headers.
   *
   * @return Canonicalized cookie value string; never {@code null} once successfully validated.
   * @throws IllegalArgumentException If value validation fails for the stored attribute content.
   */
  @Override
  public String getValue() {
    if (value == null) value = Cookie.validateValue(content.get(getName()));

    return value;
  }

  // Expiration parsing intentionally omitted because TimeUtil.parseHTTPDate() is not reliable here.

  /**
   * Always throws because inbound cookies must not be serialized back into the header form.
   *
   * <p>{@link ReceivedCookie} models client-supplied data and therefore does not support rendering
   * a {@code Set-Cookie} header. Attempting to call this method indicates a programming error; the
   * caller should construct a fresh {@link Cookie} instead. The exception message suggests using
   * the outbound cookie type to avoid accidentally echoing user-provided data.
   *
   * @return This method never returns; it always throws an {@link UnsupportedOperationException}.
   * @throws UnsupportedOperationException Always thrown to signal that encoding is unsupported for
   *     received cookies.
   */
  @SuppressWarnings("DoNotCallSuggester")
  @Override
  String encodeToHeaderValue() {
    throw new UnsupportedOperationException(
        "ReceivedCookie objects cannot be encoded to a HTTP header value, use Cookie objects!");
  }

  /** Returns true if this cookie has equal domain, path, and name as another Cookie. */
  @Override
  public boolean equals(Object obj) {
    if (obj == this) return true;

    if (!(obj instanceof Cookie other)) return false;

    URI myDomain = getDomain();
    URI otherDomain = other.getDomain();

    if (myDomain != null) {
      if (otherDomain == null || !otherDomain.toString().equals(myDomain.toString())) return false;
    } else if (otherDomain != null) return false;

    if (!getPath().toString().equals(other.getPath().toString())) return false;

    return getName().equals(other.getName());
  }

  @Override
  public int hashCode() {
    URI cookieDomain = getDomain();
    int domainHash = cookieDomain != null ? cookieDomain.hashCode() : 0;
    return domainHash + getPath().hashCode() + getName().hashCode();
  }
}
