package network.crypta.support.http;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses URI query strings into a multimap of parameter names and values.
 *
 * <p>This helper keeps the legacy query-token parsing rules in one neutral location so HTTP request
 * wrappers and content filters can share exactly the same behavior. Parameter names may appear more
 * than once, so the result stores each key in insertion order with all of its observed values.
 * Tokens without {@code =} are preserved with an empty-string value, matching the historic behavior
 * of the HTTP layer.
 *
 * <p>The returned map and per-key lists are mutable. Callers that expose the result more widely
 * should wrap or copy it if they need stronger immutability guarantees.
 */
public final class HttpQueryParameters {

  private static final Logger LOG = LoggerFactory.getLogger(HttpQueryParameters.class);

  private HttpQueryParameters() {}

  /**
   * Parses a raw URI query string into a map of parameter names to value lists.
   *
   * <p>The parser splits on {@code &}, preserves repeated keys, and treats missing values as empty
   * strings. When URL decoding is enabled, both parameter names and values are decoded as UTF-8
   * using the same rules as the legacy HTTP request implementation.
   *
   * @param queryString Raw query portion of a URI, without the leading {@code ?}.
   * @param doUrlDecoding {@code true} to decode names and values as UTF-8, {@code false} to keep
   *     the original escaped text.
   * @return Mutable map of parameter names to ordered lists of parsed values.
   */
  public static Map<String, List<String>> parseUriParameters(
      String queryString, boolean doUrlDecoding) {
    if (LOG.isDebugEnabled()) {
      int queryLength = queryString == null ? 0 : queryString.length();
      LOG.debug("Parse URI parameters (queryLength={} urlDecode={})", queryLength, doUrlDecoding);
    }

    Map<String, List<String>> parameters = new HashMap<>();
    if ((queryString == null) || queryString.isEmpty()) {
      return parameters;
    }

    StringTokenizer tokenizer = new StringTokenizer(queryString, "&");
    while (tokenizer.hasMoreTokens()) {
      String nameValueToken = tokenizer.nextToken();
      if (LOG.isDebugEnabled()) {
        LOG.debug("Parse query token (tokenLength={})", nameValueToken.length());
      }
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
      if (LOG.isDebugEnabled()) {
        LOG.debug("Parsed token without value (name={})", name);
      }
    } else if (indexOfEqualsChar == nameValueToken.length() - 1) {
      name = nameValueToken.substring(0, indexOfEqualsChar);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Parsed token with empty value (name={})", name);
      }
    } else {
      name = nameValueToken.substring(0, indexOfEqualsChar);
      value = nameValueToken.substring(indexOfEqualsChar + 1);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Parsed token with value (name={} valueLength={})", name, value.length());
      }
    }

    if (doUrlDecoding) {
      name = java.net.URLDecoder.decode(name, StandardCharsets.UTF_8);
      value = java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Decoded parameter name (name={})", name);
        LOG.debug("Decoded parameter value length (valueLength={})", value.length());
      }
    }
    return new ParameterNameValue(name, value);
  }

  private record ParameterNameValue(String name, String value) {}
}
