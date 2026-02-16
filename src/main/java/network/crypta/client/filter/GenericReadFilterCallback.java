package network.crypta.client.filter;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import network.crypta.clients.http.ExternalLinkToadlet;
import network.crypta.clients.http.HTTPRequestImpl;
import network.crypta.clients.http.StaticToadlet;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.URIPreEncoder;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filters and normalizes URIs discovered while reading user-provided HTML content.
 *
 * <p>This callback is used by the HTML read filter to validate links, rewrite references into
 * Crypta-safe forms, and decide whether a particular URI should be allowed to pass through. It is
 * designed for untrusted input: the implementation prefers safety and determinism over permissive
 * behavior. Typical usage is as an instance passed to the HTML filter; the filter invokes the
 * methods defined by {@link FilterCallback} and {@link URIProcessor} whenever it encounters text,
 * tags, or attributes that may embed an address.
 *
 * <p>Key behaviors include:
 *
 * <ul>
 *   <li>Resolution of relative references against a base URI provided at construction time.
 *   <li>Protocol allow‑listing for external links and strict validation of Freenet-style keys.
 *   <li>Normalization and sanitization of fragments, queries, and character encodings.
 * </ul>
 *
 * <p>The class is mutable only with respect to the current base URI (it is updated when a valid
 * {@code <base href>} is encountered). All other operations are stateless and thread-safe with
 * regard to shared constants, but instances are not intended for concurrent reuse during a single
 * parse because they track base-URI state per document.
 *
 * @see FilterCallback
 * @see URIProcessor
 */
public final class GenericReadFilterCallback implements FilterCallback, URIProcessor {
  private static final Logger LOG = LoggerFactory.getLogger(GenericReadFilterCallback.class);

  private static final Set<String> allowedProtocols;

  // RFC3986
  //  unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
  /**
   * Pattern for an RFC 3986 "unreserved" character. The value matches ASCII letters, digits and the
   * characters {@code - . _ ~}. It is used as a building block for more complete expressions that
   * validate or sanitize user-supplied URI components. The constant is exposed as {@code protected}
   * for reuse in specialized filters.
   */
  static final String UNRESERVED = "[a-zA-Z0-9\\-._~]";

  //  pct-encoded   = "%" HEXDIG HEXDIG
  /**
   * Pattern for an RFC 3986 percent-encoded octet. It matches a percent sign followed by two
   * hexadecimal digits. Callers typically combine this with {@link #UNRESERVED} and other tokens to
   * recognize valid path/query fragments without decoding first.
   */
  static final String PCT_ENCODED = "%[0-9A-Fa-f][0-9A-Fa-f]";

  //  sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
  //                / "*" / "+" / "," / ";" / "="
  /**
   * Pattern for RFC 3986 sub-delimiters. These symbols are allowed in various URI components and
   * are treated as literals when percent-encoding is not required. Exposing the value enables
   * consistent validation across related filters.
   */
  static final String SUB_DELIMS = "[!$&'()*+,;=]";

  //  pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
  /**
   * Pattern for the RFC 3986 {@code pchar} production, combining unreserved characters,
   * percent-encoded octets, sub-delimiters, and the literal characters {@code :} and {@code @}.
   * Used to validate path segments and similar components without performing decoding.
   */
  static final String PCHAR = "(?>" + UNRESERVED + "|" + PCT_ENCODED + "|" + SUB_DELIMS + "|[:@])";

  /**
   * Pattern for RFC 3986 fragment content. It accepts a sequence of {@link #PCHAR} along with
   * forward slashes and question marks. This is intentionally permissive within the standard’s
   * constraints to allow safe passthrough of anchors.
   */
  static final String FRAGMENT = "(?>" + PCHAR + "|/|\\?)*";

  //  fragment      = *( pchar / "/" / "?" )
  static final String PLUGINS_PREFIX = "/plugins/";
  private static final Pattern anchorRegex;

  private static BaseL10n l10n = NodeL10n.getBase();

  static {
    allowedProtocols =
        Set.of("http", "https", "ftp", "mailto", "nntp", "news", "snews", "about", "irc");
    // file:// ?
  }

  static {
    anchorRegex = Pattern.compile("^#" + FRAGMENT + "$");
  }

  private final FoundURICallback cb;
  private final TagReplacerCallback trc;

  /** Provider for link filter exceptions. */
  private final LinkFilterExceptionProvider linkFilterExceptionProvider;

  private URI baseURI;
  private URI strippedBaseURI;

  private static final String ERROR_KEY = "error";

  /**
   * Creates a new callback from a {@link ContentFilterCallbacks} bundle.
   *
   * @param callbacks bundle describing the base URI and optional callbacks; must not be {@code
   *     null}
   */
  public GenericReadFilterCallback(ContentFilterCallbacks callbacks) {
    this(
        callbacks.baseURI(),
        callbacks.foundUriCallback(),
        callbacks.tagReplacerCallback(),
        callbacks.linkFilterExceptionProvider());
  }

  /**
   * Creates a new callback bound to a specific base {@link URI}. The base is used to resolve
   * relative references and may be updated later via a valid {@code <base href>} discovered during
   * processing.
   *
   * <p>The supplied callbacks are optional: when present, {@code cb} receives notifications about
   * URIs that were recognized, and {@code trc} can replace or rewrite parsed tags during filtering.
   * The exception provider allows explicit per-URI exemptions from strict filtering rules.
   *
   * @param uri Base URI used to resolve relative links and to compute stripped variants. Must be an
   *     absolute URI suitable for HTML resolution; {@code null} is not permitted.
   * @param cb Callback notified when URIs are found. May be {@code null} if the caller does not
   *     need notifications.
   * @param trc Tag replacement callback invoked for each parsed tag. May be {@code null} to disable
   *     tag-level rewrites.
   * @param linkFilterExceptionProvider Provider consulted to decide whether a given link should be
   *     excepted from standard filtering. May be {@code null} for default behavior.
   */
  public GenericReadFilterCallback(
      URI uri,
      FoundURICallback cb,
      TagReplacerCallback trc,
      LinkFilterExceptionProvider linkFilterExceptionProvider) {
    this.baseURI = uri;
    this.cb = cb;
    this.trc = trc;
    this.linkFilterExceptionProvider = linkFilterExceptionProvider;
    setStrippedURI(uri.toString());
  }

  /**
   * Creates a new callback from a {@code FreenetURI}. The URI is converted to a relative {@link
   * URI} suitable for use as a base for resolution.
   *
   * @param uri Base key represented as a {@code FreenetURI}. Must parse into a valid relative
   *     {@code URI} for later resolution operations.
   * @param cb Callback notified when URIs are found. May be {@code null} if the caller does not
   *     require notifications.
   * @param trc Tag replacement callback invoked for each parsed tag. May be {@code null} to disable
   *     tag-level rewrites.
   * @param linkFilterExceptionProvider Provider consulted to decide whether a given link should be
   *     excepted from standard filtering. May be {@code null} for default behavior.
   * @throws IllegalArgumentException if the {@code FreenetURI} cannot be converted to a relative
   *     {@code URI} due to a syntax error.
   */
  public GenericReadFilterCallback(
      FreenetURI uri,
      FoundURICallback cb,
      TagReplacerCallback trc,
      LinkFilterExceptionProvider linkFilterExceptionProvider) {
    try {
      this.baseURI = uri.toRelativeURI();
      setStrippedURI(baseURI.toString());
      this.cb = cb;
      this.trc = trc;
      this.linkFilterExceptionProvider = linkFilterExceptionProvider;
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Sets the {@link BaseL10n l10n provider} to use for translating some error messages. If this
   * method is not called, {@link NodeL10n}’s {@link NodeL10n#getBase() l10n provider} is used.
   *
   * <p>This method should only be called from tests.
   *
   * @param l10n The l10n provider to use
   */
  static void setBaseL10n(BaseL10n l10n) {
    GenericReadFilterCallback.l10n = l10n;
  }

  private static String l10n(String key, String pattern, String value) {
    return l10n.getString("GenericReadFilterCallback." + key, pattern, value);
  }

  private static String l10n(String key) {
    return l10n.getString("GenericReadFilterCallback." + key);
  }

  /**
   * Processes a single URI reference using default options.
   *
   * <p>The input is parsed, normalized, and either rewritten into a safe form or rejected based on
   * protocol and path rules. Relative references are resolved against the current base URI. Use the
   * multi-argument overloads to control base-href handling or inline context.
   *
   * @param u Raw URI string taken from markup or attribute content. Maybe absolute or relative, and
   *     may contain percent-encoded sequences.
   * @param overrideType Optional media-type override used when building internal links. When {@code
   *     null}, no override is applied.
   * @return A sanitized, ASCII-safe URI string suitable for emission back into the filtered
   *     document.
   * @throws CommentException if the input cannot be parsed, uses a disallowed protocol, or violates
   *     filter safety constraints.
   */
  @Override
  public String processURI(String u, String overrideType) throws CommentException {
    return processURI(u, overrideType, false, false);
  }

  /**
   * Processes a URI reference with explicit control over base-href semantics and inline context.
   *
   * <p>When {@code forBaseHref} is {@code true}, the input is treated as a candidate for {@code
   * <base href>} and must not be relative. The {@code inline} flag allows callers to annotate that
   * the URI was found in inline content; this only affects callbacks, not the rewriting logic.
   *
   * @param u Raw URI string as encountered. Must be syntactically valid after preprocessing.
   * @param overrideType Optional media-type override appended to internal links. {@code null} to
   *     omit.
   * @param forBaseHref Whether the value originates from a {@code <base href>} attribute; relative
   *     input is rejected in this mode.
   * @param inline Hints that the reference was found in inline content. Used for notifications.
   * @return The sanitized, resolved URI string appropriate for reinsertion into the document.
   * @throws CommentException if the value is malformed, forbidden by policy, or not acceptable in
   *     the requested mode.
   */
  @Override
  public String processURI(String u, String overrideType, boolean forBaseHref, boolean inline)
      throws CommentException {
    if (anchorRegex.matcher(u).matches()) {
      // Hack for anchors, see #710
      return u;
    }

    // evil hack, see #2451 and r24565,r24566
    u = u.replace(" #", " %23");

    ParsedUris parsed = parseAndResolve(u, forBaseHref);
    URI uri = parsed.uri;
    URI resolved = parsed.resolved;

    String path = uri.getPath();

    String special = handlePathSpecialCases(uri, path, forBaseHref);
    if (special != null) {
      return special;
    }

    String reason = l10n("deletedURI");

    URI origURI = uri;

    // Convert localhost uri to relative internal ones.
    uri = normalizeLocalhost(uri);

    String host = uri.getHost();
    String rpath = uri.getPath();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Path: \"{}\" rpath: \"{}\"", path, rpath);
    }

    if (host == null) {
      String absoluteProcessed = tryProcessAbsolutePath(rpath, uri, overrideType, inline);
      if (absoluteProcessed != null) {
        return absoluteProcessed;
      }
      reason = updateReasonIfAbsoluteMalformed(rpath, reason);

      if (!forBaseHref) {
        String relativeProcessed = tryProcessRelativePath(resolved, uri, overrideType, inline);
        if (relativeProcessed != null) {
          return relativeProcessed;
        }
        reason = updateReasonIfRelativeMalformed(reason);
      }
    }

    uri = origURI;

    if (forBaseHref) {
      throw new CommentException(l10n("bogusBaseHref"));
    }
    if (uri.getScheme() == null) {
      throw new CommentException(reason);
    }
    if (allowedProtocols.contains(uri.getScheme())) {
      return ExternalLinkToadlet.escape(uri.toString());
    }
    throw new CommentException(l10n("protocolNotEscaped", "protocol", uri.getScheme()));
  }

  /**
   * Processes a URI and, when the host is absent, prefixes it with a forced scheme/authority.
   *
   * <p>This overload is useful when filtering content that must resolve to an absolute address even
   * when the source provided a relative form. If the processed URI already contains a host, the
   * value is returned unchanged.
   *
   * @param u Raw URI string as encountered in the document.
   * @param overrideType Optional media-type override appended for internal links; may be {@code
   *     null}.
   * @param forceSchemeHostAndPort A literal prefix such as {@code http://localhost:8888} to be
   *     prepended when the processed URI does not specify a host.
   * @param inline Hints that the reference was found in inline content. Used for notifications.
   * @return A sanitized, absolute URI string, prefixed when necessary to include the given
   *     scheme/host/port.
   * @throws CommentException if the value is malformed or forbidden by policy.
   */
  @Override
  public String processURI(
      String u, String overrideType, String forceSchemeHostAndPort, boolean inline)
      throws CommentException {
    URI uri;
    String filtered;
    try {
      filtered = processURI(makeURIAbsolute(u), overrideType, true, inline);
      uri = URIPreEncoder.encodeURI(filtered).normalize();
    } catch (URISyntaxException e1) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("URI parse failed while forcing absolute: {}", String.valueOf(e1));
      }
      throw new CommentException(l10n("couldNotParseURIWithError", ERROR_KEY, e1.getMessage()));
    }
    if (uri.getHost() == null) {
      return forceSchemeHostAndPort + filtered;
    }
    return filtered;
  }

  /**
   * Resolves a possibly relative URI string against the current base and returns its ASCII form.
   *
   * <p>The input is first normalized using the project’s pre-encoder to ensure that reserved
   * characters are percent-encoded as required for safe transport.
   *
   * @param uri A possibly relative URI string found in content; {@code null} is not permitted.
   * @return An ASCII-only absolute URI string produced by resolution against the current base.
   * @throws URISyntaxException if the input cannot be parsed or normalized into a syntactically
   *     valid {@code URI}.
   */
  @Override
  public String makeURIAbsolute(String uri) throws URISyntaxException {
    return baseURI.resolve(URIPreEncoder.encodeURI(uri).normalize()).toASCIIString();
  }

  /**
   * Handles a {@code <base href>} declaration and updates the current base URI when valid.
   *
   * <p>The supplied value is sanitized through the general URI processing routine in {@code
   * forBaseHref} mode. When accepted, the internal base used for later relative resolution is
   * updated and the ASCII representation of the new base is returned.
   *
   * @param baseHref The candidate base-href value from markup.
   * @return The ASCII form of the updated base URI when accepted, or {@code null} when the value is
   *     rejected and the base remains unchanged.
   */
  @Override
  public String onBaseHref(String baseHref) {
    String ret;
    try {
      ret = processURI(baseHref, null, true, false);
    } catch (CommentException e1) {
      LOG.error("Failed to parse base href: {} -> {}", baseHref, e1.getMessage());
      ret = null;
    }
    if (ret == null) {
      LOG.error("onBaseHref() failed: cannot sanitize {}", baseHref);
      return null;
    } else {
      try {
        baseURI = new URI(ret);
        setStrippedURI(ret);
      } catch (URISyntaxException e) {
        throw new IllegalStateException(e); // Impossible
      }
      return baseURI.toASCIIString();
    }
  }

  /**
   * Reports a text node encountered during filtering.
   *
   * <p>When a {@code FoundURICallback} is configured, this method forwards the text and its type
   * together with the current base URI so callers can perform additional analysis or analytics. The
   * method does not modify the state and performs no rewriting.
   *
   * @param s The text content as extracted from the document. Maybe empty.
   * @param type A short classifier supplied by the caller describing the context of the text (for
   *     example, attribute kind or element name). May be {@code null} if unspecified.
   */
  @Override
  public void onText(String s, String type) {
    if (cb != null) {
      cb.onText(s, type, baseURI);
    }
  }

  /**
   * Processes a form action and method discovered in the document and determines whether it is
   * permitted. Only {@code GET} and {@code POST} methods are considered, and only actions targeting
   * safe internal endpoints are allowed. When invalid, {@code null} is returned to indicate the
   * element should be removed or left unchanged.
   *
   * @param method The HTTP method as found in markup. Case-insensitive; when {@code null}, defaults
   *     to {@code GET}. Values other than {@code GET} or {@code POST} are rejected.
   * @param action The raw action attribute to be validated. Must be a relative path targeting a
   *     permitted internal endpoint; absolute URIs and attempts to escape are disallowed.
   * @return A sanitized, ASCII-safe action string if the form is allowed; otherwise {@code null}
   *     when the action should be removed or ignored by the caller.
   * @throws CommentException if the action cannot be parsed into a valid URI or violates the
   *     filter’s safety rules.
   */
  @Override
  public String processForm(String method, String action) throws CommentException {
    if (action == null) {
      return null;
    }
    if (method == null) {
      method = "GET";
    }
    method = method.toUpperCase(Locale.ROOT);
    if (!(method.equals("POST") || method.equals("GET"))) {
      return null; // no irregular form sending methods
    }
    // Note: Access to other internal paths (e.g., /downloads/, /friends/) is not permitted here.
    // Allow access to Library for searching; form passwords are used for actions such as adding
    // bookmarks
    if (action.equals("/library/")) {
      return action;
    }
    try {
      URI uri = URIPreEncoder.encodeURI(action);
      if (uri.getScheme() != null
          || uri.getHost() != null
          || uri.getPort() != -1
          || uri.getUserInfo() != null) {
        throw new CommentException(l10n("invalidFormURI"));
      }
      String path = uri.getPath();
      if (path.startsWith(PLUGINS_PREFIX)) {
        String after = path.substring(PLUGINS_PREFIX.length());
        if (after.contains("../")) {
          throw new CommentException(l10n("invalidFormURIAttemptToEscape"));
        }
        if (after.matches("[A-Za-z0-9.]+")) {
          return uri.toASCIIString();
        }
      }
    } catch (URISyntaxException e) {
      throw new CommentException(
          l10n("couldNotParseFormURIWithError", ERROR_KEY, e.getLocalizedMessage()));
    }
    // Otherwise disallow.
    return null;
  }

  /**
   * Processes a single parsed tag and optionally replaces it using the configured {@code
   * TagReplacerCallback}.
   *
   * <p>When a replacer was supplied at construction, the tag is delegated to it together with this
   * callback for context. If no replacer is present, the method returns {@code null} to indicate
   * that the original tag should be left untouched by the caller.
   *
   * @param pt The parsed tag instance to consider for replacement. Must not be {@code null}; tag
   *     names and attributes are expected to be normalized by the caller’s parser.
   * @return The replacement text for the tag or {@code null} when no replacement is required.
   */
  @Override
  public String processTag(ParsedTag pt) {
    if (trc != null) {
      return trc.processTag(pt, this);
    } else {
      return null;
    }
  }

  /**
   * Signals that the current page/document has been fully processed.
   *
   * <p>If a {@code FoundURICallback} was provided at construction, its {@code onFinishedPage}
   * method is invoked to allow the caller to finalize any per-document bookkeeping.
   */
  @Override
  public void onFinished() {
    if (cb != null) {
      cb.onFinishedPage();
    }
  }

  private void setStrippedURI(String u) {
    int idx = u.lastIndexOf('/');
    if (idx > 0) {
      u = u.substring(0, idx + 1);
      try {
        strippedBaseURI = new URI(u);
      } catch (URISyntaxException e) {
        LOG.error("Can't strip base URI: {} parsing {}", e, u);
        strippedBaseURI = baseURI;
      }
    } else {
      strippedBaseURI = baseURI;
    }
  }

  private String processBookmark(HTTPRequest req) throws CommentException {
    // allow links to the root to add bookmarks
    String bookmarkKey = req.getParam("newbookmark");
    String bookmarkDesc = req.getParam("desc");
    String bookmarkActivelink = req.getParam("hasAnActivelink", "");

    try {
      FreenetURI furi = new FreenetURI(bookmarkKey);
      bookmarkKey = furi.toString();
      bookmarkDesc = URLEncoder.encode(bookmarkDesc, StandardCharsets.UTF_8);
    } catch (MalformedURLException e) {
      throw new CommentException("Invalid Crypta URI: " + e);
    }

    String url = "/?newbookmark=" + bookmarkKey + "&desc=" + bookmarkDesc;
    if (bookmarkActivelink.equals("true")) {
      url = url + "&hasAnActivelink=true";
    }
    return url;
  }

  private String finishProcess(
      HTTPRequest req, String overrideType, String path, URI u, boolean noRelative) {
    String typeOverride = computeTypeOverride(req, overrideType);

    // Other options are not supported here; only ?type= is considered.
    try {
      URI uri = buildUri(path, typeOverride, u, noRelative);

      if (!noRelative) {
        uri = strippedBaseURI.relativize(uri);
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Returning {} from {} from baseURI={} stripped base uri={}",
            uri.toASCIIString(),
            path,
            baseURI,
            strippedBaseURI);
      }
      return uri.toASCIIString();
    } catch (URISyntaxException e) {
      LOG.error(
          "Could not parse own URI: path={}, typeOverride={}, frag={} : {}",
          path,
          typeOverride,
          u.getFragment(),
          e,
          e);
      String p = path;
      if (typeOverride != null) {
        p += "?type=" + typeOverride;
      }
      if (u.getFragment() != null) {
        // Encode fragment for fallback safely
        p += URLEncoder.encode(u.getFragment(), StandardCharsets.UTF_8);
      }
      return p;
    }
  }

  private String processURI(
      FreenetURI furi, URI uri, String overrideType, boolean noRelative, boolean inline) {
    // Valid Freenet URI, allow it
    // Now what about the queries?
    HTTPRequest req = new HTTPRequestImpl(uri, "GET");
    if (cb != null) {
      cb.foundURI(furi);
    }
    if (cb != null) {
      cb.foundURI(furi, inline);
    }
    return finishProcess(req, overrideType, '/' + furi.toString(false, false), uri, noRelative);
  }

  private record ParsedUris(URI uri, URI resolved, boolean noRelative) {}

  private ParsedUris parseAndResolve(String u, boolean noRelative) throws CommentException {
    try {
      if (LOG.isDebugEnabled()) {
        LOG.debug("URI input raw: {}", u);
      }
      URI uri = URIPreEncoder.encodeURI(u).normalize();
      if (LOG.isDebugEnabled()) {
        LOG.debug("URI normalized: {}", uri);
      }
      if (u.startsWith("/") || u.startsWith("%2f")) {
        // Don't bother with relative URIs if it's obviously absolute.
        // Don't allow encoded /'s, they're just too confusing (here they would get decoded
        // and then coalesced with other slashes).
        noRelative = true;
      }
      URI resolved = noRelative ? uri : baseURI.resolve(uri);
      if (LOG.isDebugEnabled()) {
        LOG.debug("URI resolved against base: {}", resolved);
      }
      return new ParsedUris(uri, resolved, noRelative);
    } catch (URISyntaxException e1) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("URI parse failed in parseAndResolve: {}", String.valueOf(e1));
      }
      throw new CommentException(l10n("couldNotParseURIWithError", ERROR_KEY, e1.getMessage()));
    }
  }

  private String handlePathSpecialCases(URI uri, String path, boolean forBaseHref)
      throws CommentException {
    HTTPRequest req = new HTTPRequestImpl(uri, "GET");
    if (path != null) {
      if (path.equals("/") && req.isParameterSet("newbookmark") && !forBaseHref) {
        return processBookmark(req);
      } else if (path.startsWith(StaticToadlet.ROOT_URL)) {
        // @see bug #2297
        return path;
      } else if (linkFilterExceptionProvider != null
          && linkFilterExceptionProvider.isLinkExcepted(uri)) {
        return path + ((uri.getQuery() != null) ? ("?" + uri.getQuery()) : "");
      }
    }
    return null;
  }

  private URI normalizeLocalhost(URI uri) throws CommentException {
    String host = uri.getHost();
    if (host != null
        && (host.equals("localhost") || host.equals("127.0.0.1"))
        && uri.getPort() == 8888) {
      try {
        return new URI(null, null, null, -1, uri.getPath(), uri.getQuery(), uri.getFragment());
      } catch (URISyntaxException e) {
        // Avoid double-logging; rethrow with context only
        throw new CommentException("URI looked like localhost but could not parse: " + e);
      }
    }
    return uri;
  }

  private String tryProcessAbsolutePath(
      String rpath, URI uri, String overrideType, boolean inline) {
    if (rpath == null) return null;
    if (LOG.isDebugEnabled()) {
      LOG.debug("Resolved absolute path candidate: \"{}\"", rpath);
    }
    try {
      String p = stripLeadingSlashes(rpath);
      FreenetURI furi = new FreenetURI(p, true);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Parsed Freenet URI from absolute path: {}", furi);
      }
      return processURI(furi, uri, overrideType, true, inline);
    } catch (MalformedURLException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Freenet URI parse failed for absolute path: {}", e, e);
      }
      return null;
    }
  }

  private String updateReasonIfAbsoluteMalformed(String rpath, String currentReason) {
    if (rpath == null) return currentReason;
    // Not a FreenetURI
    return l10n("malformedAbsoluteURL", ERROR_KEY, "");
  }

  private String tryProcessRelativePath(URI resolved, URI uri, String overrideType, boolean inline)
      throws CommentException {
    String rpath = resolved.getPath();
    if (rpath == null) {
      throw new CommentException("No URI");
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Resolved relative path candidate: {}", rpath);
    }
    try {
      String p = stripLeadingSlashes(rpath);
      FreenetURI furi = new FreenetURI(p, true);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Parsed Freenet URI from relative path: {}", furi);
      }
      return processURI(furi, uri, overrideType, false, inline);
    } catch (MalformedURLException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Freenet URI parse failed for relative path: {}", e, e);
      }
      return null;
    }
  }

  private String updateReasonIfRelativeMalformed(String currentReason) {
    String msg = l10n("malformedRelativeURL", ERROR_KEY, "");
    return (msg != null) ? msg : currentReason;
  }

  private static String stripLeadingSlashes(String p) {
    String s = p;
    while (s.startsWith("/")) {
      s = s.substring(1);
    }
    return s;
  }

  private String computeTypeOverride(HTTPRequest req, String overrideType) {
    String typeOverride = req.getParam("type", null);
    if (overrideType != null) {
      typeOverride = overrideType;
    }
    if (typeOverride == null) return null;

    String[] split = HTMLFilter.splitType(typeOverride);
    if (split[1] != null) {
      String normalized = normalizeCharset(split[1]);
      return (normalized != null) ? (split[0] + "; charset=" + normalized) : split[0];
    }
    return typeOverride;
  }

  private String normalizeCharset(String charset) {
    String cs = charset;
    if (cs != null) {
      try {
        cs = URLDecoder.decode(cs, false);
      } catch (URLEncodedFormatException _) {
        cs = null;
      }
    }
    if (cs != null && cs.indexOf('&') != -1) {
      cs = null;
    }
    if (cs != null && !Charset.isSupported(cs)) {
      cs = null;
    }
    return cs;
  }

  private URI buildUri(String path, String typeOverride, URI u, boolean noRelative)
      throws URISyntaxException {
    StringBuilder sb = new StringBuilder();
    if (strippedBaseURI.getScheme() != null && !noRelative) {
      sb.append(strippedBaseURI.getScheme());
      sb.append("://");
      sb.append(strippedBaseURI.getAuthority());
      assert path.startsWith("/");
    }
    sb.append(path);
    if (typeOverride != null) {
      sb.append("?type=");
      sb.append(network.crypta.support.URLEncoder.encode(typeOverride, "", false, "="));
    }
    if (u.getFragment() != null) {
      sb.append('#');
      sb.append(u.getRawFragment());
    }
    return new URI(sb.toString());
  }
}
