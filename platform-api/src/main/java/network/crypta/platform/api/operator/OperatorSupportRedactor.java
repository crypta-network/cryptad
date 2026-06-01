package network.crypta.platform.api.operator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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
  private static final Pattern CONTENT_URI =
      Pattern.compile("(?i)\\b(?:crypta:)?(?:CHK|SSK|USK|KSK)@[^\\s\"'<>]+");
  private static final Pattern UNIX_ABSOLUTE_PATH =
      Pattern.compile(
          "(?<![A-Za-z0-9])/(?:home|root|work|tmp|var|etc|opt|Users|private|mnt|srv|run|build)/[^\\s\"'<>]*");
  private static final Pattern WINDOWS_ABSOLUTE_PATH = Pattern.compile("[A-Za-z]:\\\\[^\\s\"'<>]+");
  private static final Pattern SECRET_ASSIGNMENT =
      Pattern.compile(
          "(?i)\\b(token|password|formPassword|secret|private[-_ ]?key|seed|recovery[-_"
              + " ]?phrase)\\s*[:=]\\s*[^\\s,;]+");
  private static final Pattern SENSITIVE_QUERY =
      Pattern.compile("(?i)([?&](?:token|password|formPassword|secret|key)=)[^&#\\s]+");
  private static final Set<String> SENSITIVE_FIELD_NAMES =
      Set.of(
          "token",
          "apptoken",
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
   * URIs, local paths, secret assignments, and sensitive query parameters. The input object is not
   * mutated.
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
    String normalized = fieldName.replaceAll("[^A-Za-z0-9]", "").toLowerCase(java.util.Locale.ROOT);
    return SENSITIVE_FIELD_NAMES.contains(normalized);
  }

  private static String redactString(String input) {
    String redacted = Objects.requireNonNull(input, "input");
    redacted = CONTENT_URI.matcher(redacted).replaceAll("<redacted-content-uri>");
    redacted = UNIX_ABSOLUTE_PATH.matcher(redacted).replaceAll("<redacted-path>");
    redacted = WINDOWS_ABSOLUTE_PATH.matcher(redacted).replaceAll("<redacted-path>");
    redacted = SECRET_ASSIGNMENT.matcher(redacted).replaceAll("$1=<redacted>");
    redacted = SENSITIVE_QUERY.matcher(redacted).replaceAll("$1<redacted>");
    return redacted;
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
