package network.crypta.platform.api.operator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Redacts support-bundle values before they leave the local operator API.
 *
 * <p>The dashboard service already prefers safe summaries over raw diagnostics. This helper is the
 * final structural guard for fields that can carry local paths, secrets, credentials, request
 * bodies, or content keys. It intentionally omits sensitive map fields instead of replacing their
 * values where a field name alone is enough to signal unsafe content.
 *
 * <p>Redaction is deterministic and JSON-tree oriented. Maps are copied in encounter order, lists
 * are copied element by element, primitive values are preserved, and strings are scrubbed for the
 * small set of high-risk patterns used by operator support evidence. The helper does not try to
 * classify all possible private text. Callers should continue to build safe summaries first and
 * treat this pass as defense in depth before an operator exports a support bundle.
 */
public final class OperatorSupportRedactor {
  private static final String REDACTED = "<redacted>";
  private static final Pattern CONTENT_URI =
      Pattern.compile("(?i)\\b(?:crypta:)?(?:CHK|SSK|USK|KSK)@[^\\s\"'<>]+");
  private static final Pattern UNIX_ABSOLUTE_PATH =
      Pattern.compile(
          "(?<![A-Za-z0-9])/(?:home|root|work|tmp|var|etc|opt|Users|private|mnt|srv|run|build)/[^\\s\"'<>]*");
  private static final Pattern WINDOWS_ABSOLUTE_PATH = Pattern.compile("[A-Za-z]:\\\\[^\\s\"'<>]+");
  private static final Pattern AUTHORIZATION_OR_COOKIE_HEADER =
      Pattern.compile(
          "(?i)\\b((?:authorization|proxy-authorization|cookie|set-cookie|x-crypta-app-session|"
              + "x-crypta-form-password)\\s*:\\s*)[^\\r\\n]*");
  private static final Pattern SECRET_ASSIGNMENT_PREFIX =
      Pattern.compile("(?i)(?<!\\w)([\"']?)(\\w[-.\\w]*)(\\1\\s*[:=]\\s*)");
  private static final Pattern QUERY_PARAMETER = Pattern.compile("([?&])([^=&#\\s]+)=([^&#\\s]+)");
  private static final Set<String> SENSITIVE_FIELD_NAMES =
      Set.of(
          "authorization",
          "proxyauthorization",
          "cookie",
          "setcookie",
          "token",
          "apptoken",
          "cryptadapptoken",
          "xcryptaappsession",
          "xcryptaformpassword",
          "sessiontoken",
          "browsersession",
          "formpassword",
          "password",
          "secret",
          "secretvalue",
          "privatekey",
          "seed",
          "recoveryphrase",
          "requestbody",
          "rawbody",
          "body",
          "plaintextbody",
          "plaintext",
          "plaintextexport",
          "commandline",
          "command",
          "path",
          "sourcepath",
          "stageddir",
          "stagedpath",
          "scratchpath",
          "rollbackpath",
          "directory",
          "dir",
          "file");
  private static final List<String> PATTERNS_CHECKED =
      List.of(
          "crypta_or_freenet_content_uri",
          "unix_absolute_path",
          "windows_absolute_path",
          "authorization_or_cookie_header",
          "secret_assignment",
          "sensitive_query_parameter",
          "sensitive_field_name");

  private OperatorSupportRedactor() {}

  /**
   * Returns the support-bundle redaction patterns applied by this helper.
   *
   * <p>The names are stable, human-readable evidence labels for the support bundle's redaction
   * metadata. They describe categories checked by the current implementation rather than exposing
   * the regular expressions themselves, which keeps reports compact and avoids encouraging callers
   * to depend on exact pattern text.
   *
   * @return stable redaction pattern names in the order they are applied or checked
   */
  public static List<String> patternsChecked() {
    return PATTERNS_CHECKED;
  }

  /**
   * Redacts one JSON-compatible object tree.
   *
   * <p>The input may be a nested combination of maps, lists, strings, numbers, booleans, and {@code
   * null}. Map entries with sensitive field names are omitted entirely and their original keys are
   * recorded in the result. String values that remain in the tree are pattern-scrubbed for content
   * URIs, local paths, credential headers, secret assignments, and sensitive query parameters. The
   * input object is not mutated.
   *
   * @param value JSON-compatible value to sanitize before export
   * @return redacted value plus the structural field names omitted during traversal
   */
  public static RedactionResult redact(Object value) {
    LinkedHashSet<String> omittedFields = new LinkedHashSet<>();
    return new RedactionResult(redactValue(value, omittedFields), List.copyOf(omittedFields));
  }

  private static Object redactValue(Object value, Set<String> omittedFields) {
    if (value instanceof Map<?, ?> map) {
      return redactMap(map, omittedFields);
    }
    if (value instanceof List<?> list) {
      return list.stream().map(item -> redactValue(item, omittedFields)).toList();
    }
    if (value instanceof String text) {
      return redactString(text);
    }
    return value;
  }

  private static Map<String, Object> redactMap(Map<?, ?> map, Set<String> omittedFields) {
    LinkedHashMap<String, Object> redacted = LinkedHashMap.newLinkedHashMap(map.size());
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      String key = String.valueOf(entry.getKey());
      if (isSensitiveFieldName(key)) {
        omittedFields.add(key);
        continue;
      }
      redacted.put(key, redactValue(entry.getValue(), omittedFields));
    }
    return redacted;
  }

  private static boolean isSensitiveFieldName(String fieldName) {
    String normalized = normalizeFieldName(fieldName);
    return isSensitiveCredentialKey(normalized);
  }

  private static String redactString(String input) {
    String redacted = Objects.requireNonNull(input, "input");
    redacted = CONTENT_URI.matcher(redacted).replaceAll("<redacted-content-uri>");
    redacted = UNIX_ABSOLUTE_PATH.matcher(redacted).replaceAll("<redacted-path>");
    redacted = WINDOWS_ABSOLUTE_PATH.matcher(redacted).replaceAll("<redacted-path>");
    redacted = AUTHORIZATION_OR_COOKIE_HEADER.matcher(redacted).replaceAll("$1" + REDACTED);
    redacted = redactAssignments(redacted);
    redacted = redactQueryParameters(redacted);
    return redacted;
  }

  private static String redactAssignments(String input) {
    Matcher matcher = SECRET_ASSIGNMENT_PREFIX.matcher(input);
    StringBuilder redacted = null;
    int appendFrom = 0;
    while (matcher.find()) {
      int valueStart = matcher.end();
      int valueEnd = assignmentValueEnd(input, valueStart);
      if (matcher.start() >= appendFrom
          && valueEnd > valueStart
          && isSensitiveCredentialKey(normalizeFieldName(matcher.group(2)))) {
        if (redacted == null) {
          redacted = new StringBuilder(input.length());
        }
        redacted.append(input, appendFrom, valueStart);
        redacted.append(redactedAssignmentValue(input, valueStart, valueEnd));
        appendFrom = valueEnd;
      }
    }
    if (redacted == null) {
      return input;
    }
    return redacted.append(input, appendFrom, input.length()).toString();
  }

  private static String redactQueryParameters(String input) {
    Matcher matcher = QUERY_PARAMETER.matcher(input);
    StringBuilder redacted = null;
    int appendFrom = 0;
    while (matcher.find()) {
      if (!isSensitiveQueryParameterKey(normalizeFieldName(matcher.group(2)))) {
        continue;
      }
      if (redacted == null) {
        redacted = new StringBuilder(input.length());
      }
      redacted.append(input, appendFrom, matcher.start());
      redacted.append(matcher.group(1)).append(matcher.group(2)).append('=').append(REDACTED);
      appendFrom = matcher.end();
    }
    if (redacted == null) {
      return input;
    }
    return redacted.append(input, appendFrom, input.length()).toString();
  }

  private static int assignmentValueEnd(String input, int valueStart) {
    if (valueStart >= input.length()) {
      return valueStart;
    }
    char first = input.charAt(valueStart);
    if (isQuote(first)) {
      return quotedAssignmentValueEnd(input, valueStart, first);
    }
    int firstTokenEnd = unquotedAssignmentTokenEnd(input, valueStart);
    if (isAuthScheme(input, valueStart, firstTokenEnd)) {
      int nextTokenStart = skipHorizontalWhitespace(input, firstTokenEnd);
      if (nextTokenStart > firstTokenEnd) {
        int secondTokenEnd = unquotedAssignmentTokenEnd(input, nextTokenStart);
        if (secondTokenEnd > nextTokenStart) {
          return secondTokenEnd;
        }
      }
    }
    return firstTokenEnd;
  }

  private static int quotedAssignmentValueEnd(String input, int valueStart, char quote) {
    for (int index = valueStart + 1; index < input.length(); index++) {
      char current = input.charAt(index);
      if (current == quote) {
        return index + 1;
      }
      if (current == '\r' || current == '\n') {
        return index;
      }
    }
    return input.length();
  }

  private static int unquotedAssignmentTokenEnd(String input, int valueStart) {
    int index = valueStart;
    while (index < input.length() && !isUnquotedAssignmentDelimiter(input.charAt(index))) {
      index++;
    }
    return index;
  }

  private static int skipHorizontalWhitespace(String input, int valueStart) {
    int index = valueStart;
    while (index < input.length()) {
      char current = input.charAt(index);
      if (current != ' ' && current != '\t') {
        break;
      }
      index++;
    }
    return index;
  }

  private static String redactedAssignmentValue(String input, int valueStart, int valueEnd) {
    char first = input.charAt(valueStart);
    if (!isQuote(first)) {
      return REDACTED;
    }
    boolean closed = valueEnd > valueStart && input.charAt(valueEnd - 1) == first;
    return closed ? first + REDACTED + first : first + REDACTED;
  }

  private static boolean isQuote(char value) {
    return value == '"' || value == '\'';
  }

  private static boolean isUnquotedAssignmentDelimiter(char value) {
    return Character.isWhitespace(value)
        || value == ','
        || value == ';'
        || value == '&'
        || value == '}'
        || value == ']';
  }

  private static boolean isAuthScheme(String input, int startInclusive, int endExclusive) {
    int length = endExclusive - startInclusive;
    return (length == 6 && input.regionMatches(true, startInclusive, "Bearer", 0, length))
        || (length == 5 && input.regionMatches(true, startInclusive, "Basic", 0, length))
        || (length == 6 && input.regionMatches(true, startInclusive, "Digest", 0, length));
  }

  private static boolean isSensitiveQueryParameterKey(String normalized) {
    return isSensitiveCredentialKey(normalized) || normalized.endsWith("key");
  }

  private static boolean isSensitiveCredentialKey(String normalized) {
    return SENSITIVE_FIELD_NAMES.contains(normalized)
        || normalized.endsWith("token")
        || normalized.endsWith("password")
        || normalized.endsWith("passwd")
        || normalized.endsWith("secret")
        || normalized.endsWith("credential")
        || normalized.endsWith("seed")
        || normalized.endsWith("recoveryphrase")
        || (normalized.contains("privatekey") && !normalized.endsWith("present"));
  }

  private static String normalizeFieldName(String fieldName) {
    return fieldName.replaceAll("[^A-Za-z0-9]", "").toLowerCase(java.util.Locale.ROOT);
  }

  /**
   * Redacted payload and the structural fields omitted during redaction.
   *
   * <p>The {@code value} component preserves the original JSON-compatible shape as closely as the
   * redaction rules allow. The {@code omittedFields} component records field names removed because
   * their keys matched sensitive categories such as tokens, raw bodies, local paths, command lines,
   * or private key material.
   *
   * @param value sanitized value tree safe for the operator support-bundle envelope
   * @param omittedFields copied field names that were removed during structural redaction
   */
  public record RedactionResult(Object value, List<String> omittedFields) {
    /** Creates an immutable redaction result. */
    public RedactionResult {
      omittedFields = List.copyOf(new ArrayList<>(omittedFields));
    }
  }
}
