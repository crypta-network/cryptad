package network.crypta.platform.api.operator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
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
  private static final String REDACTED_APP_DATA_BACKUP = "<redacted-app-data-backup>";
  private static final String REDACTED_PATH = "<redacted-path>";
  private static final String REDACTED_PRIVATE_KEY = "<redacted-private-key>";
  private static final String FILE_URI_PREFIX = "file:";
  private static final String APP_DATA_BACKUP_KIND = "crypta-app-data-backup";
  private static final String PEM_BEGIN_PREFIX = "-----BEGIN ";
  private static final String PEM_END_PREFIX = "-----END ";
  private static final String PEM_LINE_SUFFIX = "-----";
  private static final String SIGNATURE_FIELD_NAME = "signature";
  private static final Set<String> SAFE_RAW_APP_DATA_BOOLEAN_METADATA_FIELDS =
      Set.of(
          "rawappdataavailable",
          "rawappdataconfigured",
          "rawappdataenabled",
          "rawappdataexcluded",
          "rawappdataexcludedfromevidence",
          "rawappdatavaluesexcluded",
          "rawappdatapresent",
          "rawappdataredacted",
          "rawappdatarequired");
  private static final Set<String> PATH_LABEL_FIELD_NAMES =
      Set.of(
          "path",
          "dir",
          "directory",
          "file",
          "filepath",
          "localpath",
          "sourcepath",
          "stageddir",
          "stagedpath",
          "stagedbundlepath",
          "scratchpath",
          "rollbackpath");
  private static final Pattern CONTENT_URI =
      Pattern.compile("(?i)\\b(?:crypta:)?(?:CHK|SSK|USK|KSK)@[^\\s\"'<>]+");
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
          "authorizationheader",
          "proxyauthorization",
          "proxyauthorizationheader",
          "cookie",
          "setcookie",
          "token",
          "apptoken",
          "cryptadapptoken",
          "xcryptaappsession",
          "xcryptaformpassword",
          "sessiontoken",
          "browsersession",
          "browsersessiontoken",
          "plantoken",
          "formpassword",
          "password",
          "secret",
          "cisecret",
          "cisecrets",
          "cisecretvalue",
          "secretvalue",
          "identitymaterial",
          "vaultidentitymaterial",
          "privatekey",
          "privateuri",
          "privateinserturi",
          "seed",
          "recoveryphrase",
          "requestbody",
          "rawrequestbody",
          "rawbody",
          "rawfetchedcontent",
          "rawcontent",
          "rawdocument",
          "rawprofiledocument",
          "profiledocumentbody",
          "rawfeedsnapshot",
          "feedsnapshotbody",
          "rawtruststatement",
          "rawtruststatementbody",
          "rawtruststatementsignature",
          "rawsocialmessage",
          "socialmessagebody",
          "rawsocialoutbox",
          "socialoutboxbody",
          "canonicalsignaturepayload",
          "canonicalsignaturepayloadbytes",
          "appserviceinvocationrequestbody",
          "appserviceinvocationresponsebody",
          "appserviceinvocationbody",
          "invocationrequestbody",
          "invocationresponsebody",
          "subjecturi",
          "rawsubjecturi",
          "body",
          "plaintextbody",
          "plaintext",
          "plaintextexport",
          "backup",
          "backupbundle",
          "backuppayload",
          "backuppayloadbase64",
          "appdatabackup",
          "appdatabackupbundle",
          "appdatabackuppayload",
          "restorepayloadbase64",
          "rawappdata",
          "rawappdatavalue",
          "recordvalue",
          "payloadbase64",
          "valuebase64",
          "rawappdatarecordkey",
          "commandline",
          "command",
          "path",
          "sourcepath",
          "stageddir",
          "stagedpath",
          "stagedbundlepath",
          "scratchpath",
          "rollbackpath",
          "directory",
          "dir",
          "file");
  private static final List<String> SENSITIVE_SIGNATURE_SUFFIXES =
      List.of(
          "",
          "base64",
          "value",
          "valuebase64",
          "payload",
          "payloadbase64",
          "document",
          "documentbase64");
  private static final List<String> PATTERNS_CHECKED =
      List.of(
          "crypta_or_freenet_content_uri",
          "private_insert_uri",
          "public_content_uri",
          "raw_profile_document",
          "raw_feed_snapshot",
          "raw_trust_statement",
          "raw_social_message",
          "raw_social_outbox",
          "canonical_signature_payload",
          "raw_signature_material",
          "app_service_invocation_body",
          "vault_identity_material",
          "seed_or_recovery_phrase",
          "pem_private_key_block",
          "file_uri_absolute_path",
          "unix_absolute_path",
          "windows_absolute_path",
          "windows_unc_path",
          "authorization_or_cookie_header",
          "secret_assignment",
          "sensitive_query_parameter",
          "app_data_backup_payload",
          "raw_app_data_record_value",
          "nested_archive_or_base64_backup_payload",
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
   * URIs, PEM private-key blocks, local paths, credential headers, secret assignments, and
   * sensitive query parameters. The input object is not mutated.
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
      if (isBackupPayloadMap(map)) {
        omittedFields.add("appDataBackup");
        return REDACTED_APP_DATA_BACKUP;
      }
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
      if (isSensitiveFieldName(key, entry.getValue())) {
        omittedFields.add(key);
        continue;
      }
      redacted.put(key, redactValue(entry.getValue(), omittedFields));
    }
    return redacted;
  }

  private static boolean isBackupPayloadMap(Map<?, ?> map) {
    Object kind = map.get("kind");
    if (kind instanceof String text && APP_DATA_BACKUP_KIND.equalsIgnoreCase(text)) {
      return true;
    }
    if (map.containsKey("backupVersion") && map.containsKey("apps")) {
      return true;
    }
    for (Object key : map.keySet()) {
      String normalized = normalizeFieldName(String.valueOf(key));
      if (normalized.contains("appdatabackup")
          || normalized.equals("backupbundle")
          || normalized.equals("backuppayload")
          || normalized.equals("backuppayloadbase64")
          || normalized.equals("restorepayloadbase64")) {
        return true;
      }
    }
    return false;
  }

  private static boolean isSensitiveFieldName(String fieldName, Object value) {
    String normalized = normalizeFieldName(fieldName);
    return isSensitiveCredentialKey(normalized, value);
  }

  private static String redactString(String input) {
    String redacted = Objects.requireNonNull(input, "input");
    if (redacted.toLowerCase(Locale.ROOT).contains(APP_DATA_BACKUP_KIND)) {
      return REDACTED_APP_DATA_BACKUP;
    }
    redacted = redactPrivateKeyBlocks(redacted);
    redacted = CONTENT_URI.matcher(redacted).replaceAll("<redacted-content-uri>");
    redacted = redactAbsolutePaths(redacted);
    redacted = AUTHORIZATION_OR_COOKIE_HEADER.matcher(redacted).replaceAll("$1" + REDACTED);
    redacted = redactAssignments(redacted);
    redacted = redactQueryParameters(redacted);
    return redacted;
  }

  private static String redactPrivateKeyBlocks(String input) {
    StringBuilder redacted = null;
    int appendFrom = 0;
    int searchFrom = 0;
    int beginStart = indexOfIgnoreCase(input, PEM_BEGIN_PREFIX, searchFrom);
    while (beginStart >= 0) {
      String keyType = privateKeyType(input, beginStart);
      if (keyType == null) {
        searchFrom = beginStart + PEM_BEGIN_PREFIX.length();
      } else {
        int blockEnd = privateKeyBlockEnd(input, beginStart, keyType);
        if (redacted == null) {
          redacted = new StringBuilder(input.length());
        }
        redacted.append(input, appendFrom, beginStart);
        redacted.append(REDACTED_PRIVATE_KEY);
        appendFrom = blockEnd;
        searchFrom = blockEnd;
      }
      beginStart = indexOfIgnoreCase(input, PEM_BEGIN_PREFIX, searchFrom);
    }
    if (redacted == null) {
      return input;
    }
    return redacted.append(input, appendFrom, input.length()).toString();
  }

  private static String privateKeyType(String input, int beginStart) {
    int typeStart = beginStart + PEM_BEGIN_PREFIX.length();
    int lineEnd = lineEnd(input, typeStart);
    int markerEnd = input.indexOf(PEM_LINE_SUFFIX, typeStart);
    if (markerEnd < 0 || markerEnd > lineEnd) {
      return null;
    }
    String keyType = input.substring(typeStart, markerEnd);
    return isPrivateKeyPemType(keyType) ? keyType : null;
  }

  private static boolean isPrivateKeyPemType(String keyType) {
    String normalized = keyType.toUpperCase(Locale.ROOT);
    if (!normalized.endsWith("PRIVATE KEY")) {
      return false;
    }
    for (int index = 0; index < normalized.length(); index++) {
      char current = normalized.charAt(index);
      if (!(current == ' ' || Character.isDigit(current) || (current >= 'A' && current <= 'Z'))) {
        return false;
      }
    }
    return true;
  }

  private static int privateKeyBlockEnd(String input, int beginStart, String keyType) {
    int bodyStart = lineEnd(input, beginStart) + 1;
    String endMarker = PEM_END_PREFIX + keyType + PEM_LINE_SUFFIX;
    int endStart = indexOfIgnoreCase(input, endMarker, bodyStart);
    if (endStart >= 0) {
      return endStart + endMarker.length();
    }
    int nextPemBegin = indexOfIgnoreCase(input, "\n" + PEM_BEGIN_PREFIX, bodyStart);
    if (nextPemBegin < 0) {
      return input.length();
    }
    return nextPemBegin > 0 && input.charAt(nextPemBegin - 1) == '\r'
        ? nextPemBegin - 1
        : nextPemBegin;
  }

  private static int lineEnd(String input, int start) {
    int index = start;
    while (index < input.length()) {
      char current = input.charAt(index);
      if (current == '\r' || current == '\n') {
        break;
      }
      index++;
    }
    return index;
  }

  private static int indexOfIgnoreCase(String input, String needle, int fromIndex) {
    int lastStart = input.length() - needle.length();
    for (int index = Math.max(0, fromIndex); index <= lastStart; index++) {
      if (input.regionMatches(true, index, needle, 0, needle.length())) {
        return index;
      }
    }
    return -1;
  }

  private static String redactAbsolutePaths(String input) {
    StringBuilder redacted = null;
    int appendFrom = 0;
    int index = 0;
    while (index < input.length()) {
      int pathEnd = absolutePathEnd(input, index);
      if (pathEnd <= index) {
        index++;
        continue;
      }
      if (redacted == null) {
        redacted = new StringBuilder(input.length());
      }
      redacted.append(input, appendFrom, index);
      redacted.append(REDACTED_PATH);
      appendFrom = pathEnd;
      index = pathEnd;
    }
    if (redacted == null) {
      return input;
    }
    return redacted.append(input, appendFrom, input.length()).toString();
  }

  private static int absolutePathEnd(String input, int index) {
    if (!isPathStartBoundary(input, index)) {
      return -1;
    }
    if (startsWithFileUriPrefix(input, index)) {
      int pathStart = index + FILE_URI_PREFIX.length();
      int pathEnd = pathTokenEnd(input, pathStart);
      return pathEnd > pathStart ? pathEnd : -1;
    }
    if (startsWithWindowsDrivePath(input, index) || startsWithUncPath(input, index)) {
      return pathTokenEnd(input, index);
    }
    if (startsWithUnixPath(input, index)) {
      return pathTokenEnd(input, index);
    }
    return -1;
  }

  private static boolean startsWithUnixPath(String input, int index) {
    return input.charAt(index) == '/'
        && index + 1 < input.length()
        && isPathTokenCharacter(input.charAt(index + 1))
        && !isSafeRoutePath(input, index);
  }

  private static boolean startsWithWindowsDrivePath(String input, int index) {
    return index + 2 < input.length()
        && Character.isLetter(input.charAt(index))
        && input.charAt(index + 1) == ':'
        && isPathSeparator(input.charAt(index + 2));
  }

  private static boolean startsWithUncPath(String input, int index) {
    if (index + 3 >= input.length()
        || input.charAt(index) != '\\'
        || input.charAt(index + 1) != '\\') {
      return false;
    }
    int tokenEnd = pathTokenEnd(input, index);
    return input.indexOf('\\', index + 2) > 0 && input.indexOf('\\', index + 2) < tokenEnd;
  }

  private static int pathTokenEnd(String input, int start) {
    int quotedEnd = quotedPathTokenEnd(input, start);
    if (quotedEnd > start) {
      return quotedEnd;
    }
    int index = start;
    while (index < input.length()) {
      char current = input.charAt(index);
      if (isPathTokenCharacter(current)) {
        index++;
      } else if (isHorizontalWhitespace(current) && isPathWhitespaceContinuation(input, index)) {
        index = skipHorizontalWhitespace(input, index);
      } else {
        break;
      }
    }
    return index;
  }

  private static int quotedPathTokenEnd(String input, int start) {
    if (start == 0 || !isQuote(input.charAt(start - 1))) {
      return -1;
    }
    char quote = input.charAt(start - 1);
    int index = start;
    while (index < input.length()) {
      char current = input.charAt(index);
      if (current == quote) {
        return index;
      }
      if (current == '\r' || current == '\n') {
        return -1;
      }
      index++;
    }
    return -1;
  }

  private static boolean isPathWhitespaceContinuation(String input, int whitespaceIndex) {
    int next = skipHorizontalWhitespace(input, whitespaceIndex);
    return next > whitespaceIndex
        && next < input.length()
        && isPathTokenCharacter(input.charAt(next))
        && (pathTokenSegmentContainsSeparator(input, next)
            || pathTokenSegmentLooksLikeFilename(input, next));
  }

  private static boolean pathTokenSegmentContainsSeparator(String input, int start) {
    int index = start;
    while (index < input.length() && isPathTokenCharacter(input.charAt(index))) {
      if (isPathSeparator(input.charAt(index))) {
        return true;
      }
      index++;
    }
    return false;
  }

  private static boolean pathTokenSegmentLooksLikeFilename(String input, int start) {
    int end = pathTokenSegmentEnd(input, start);
    int dot = input.lastIndexOf('.', end - 1);
    return dot > start && dot + 1 < end;
  }

  private static int pathTokenSegmentEnd(String input, int start) {
    int index = start;
    while (index < input.length() && isPathTokenCharacter(input.charAt(index))) {
      index++;
    }
    return index;
  }

  private static boolean isPathTokenCharacter(char value) {
    return !Character.isWhitespace(value)
        && value != ']'
        && value != ')'
        && value != '}'
        && value != ','
        && value != ';'
        && value != '"'
        && value != '\''
        && value != '<'
        && value != '>';
  }

  private static boolean isPathStartBoundary(String input, int index) {
    if (index == 0) {
      return true;
    }
    char previous = input.charAt(index - 1);
    if (previous == ':') {
      return hasPathLabelBeforeColon(input, index - 1);
    }
    return !(Character.isLetterOrDigit(previous)
        || previous == '_'
        || previous == '/'
        || previous == '.'
        || previous == '-');
  }

  private static boolean hasPathLabelBeforeColon(String input, int colonIndex) {
    int labelStart = colonIndex;
    while (labelStart > 0 && isPathLabelCharacter(input.charAt(labelStart - 1))) {
      labelStart--;
    }
    return labelStart < colonIndex
        && isPathLabelName(normalizeFieldName(input.substring(labelStart, colonIndex)));
  }

  private static boolean isPathLabelName(String normalized) {
    return PATH_LABEL_FIELD_NAMES.contains(normalized)
        || normalized.endsWith("path")
        || normalized.endsWith("dir")
        || normalized.endsWith("directory");
  }

  private static boolean isPathLabelCharacter(char value) {
    return Character.isLetterOrDigit(value) || value == '_' || value == '-' || value == '.';
  }

  private static boolean isSafeRoutePath(String input, int index) {
    return startsWithRoutePrefix(input, index, "/api/v1")
        || startsWithRoutePrefix(input, index, "/apps")
        || startsWithRoutePrefix(input, index, "/app/node")
        || startsWithRoutePrefix(input, index, "/.well-known")
        || startsWithRoutePrefix(input, index, "/platform/contract");
  }

  private static boolean startsWithRoutePrefix(String input, int index, String prefix) {
    if (!input.startsWith(prefix, index)) {
      return false;
    }
    int afterPrefix = index + prefix.length();
    return afterPrefix == input.length() || !isRouteIdentifierChar(input.charAt(afterPrefix));
  }

  private static boolean isRouteIdentifierChar(char value) {
    return Character.isLetterOrDigit(value) || value == '_' || value == '-';
  }

  private static boolean startsWithFileUriPrefix(String input, int index) {
    return index + FILE_URI_PREFIX.length() <= input.length()
        && input.regionMatches(true, index, FILE_URI_PREFIX, 0, FILE_URI_PREFIX.length());
  }

  private static boolean isPathSeparator(char value) {
    return value == '/' || value == '\\';
  }

  private static boolean isHorizontalWhitespace(char value) {
    return value == ' ' || value == '\t';
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
      if (!isHorizontalWhitespace(current)) {
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
    return isSensitiveCredentialKey(normalized);
  }

  private static boolean isSensitiveCredentialKey(String normalized) {
    return isSensitiveCredentialKey(normalized, null);
  }

  private static boolean isSensitiveCredentialKey(String normalized, Object value) {
    return SENSITIVE_FIELD_NAMES.contains(normalized)
        || isSensitiveRawAppDataKey(normalized, value)
        || normalized.endsWith("key")
        || isSensitiveSignatureKey(normalized)
        || normalized.endsWith("token")
        || normalized.endsWith("password")
        || normalized.endsWith("passwd")
        || normalized.endsWith("secret")
        || normalized.endsWith("credential")
        || isSensitiveSeedOrMnemonicKey(normalized)
        || (normalized.contains("privatekey") && !normalized.endsWith("present"));
  }

  private static boolean isSensitiveRawAppDataKey(String normalized, Object value) {
    if (!normalized.contains("rawappdata")) {
      return false;
    }
    return !(value instanceof Boolean
        && SAFE_RAW_APP_DATA_BOOLEAN_METADATA_FIELDS.contains(normalized));
  }

  private static boolean isSensitiveSeedOrMnemonicKey(String normalized) {
    return normalized.endsWith("seed")
        || normalized.contains("seedphrase")
        || normalized.contains("recoveryphrase")
        || normalized.contains("mnemonic");
  }

  private static boolean isSensitiveSignatureKey(String normalized) {
    int signatureIndex = normalized.lastIndexOf(SIGNATURE_FIELD_NAME);
    if (signatureIndex < 0) {
      return false;
    }
    String suffix = normalized.substring(signatureIndex + SIGNATURE_FIELD_NAME.length());
    return SENSITIVE_SIGNATURE_SUFFIXES.contains(suffix);
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
