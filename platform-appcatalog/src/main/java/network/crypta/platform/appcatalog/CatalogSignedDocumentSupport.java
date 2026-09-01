package network.crypta.platform.appcatalog;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Provides closed-format validation for signed catalog discovery documents.
 *
 * <p>Discovery descriptors and endorsements share strict bounds for identifiers, text, arrays,
 * timestamps, JSON depth, public URIs, digests, and Ed25519 signatures. This utility centralizes
 * those rules so runtime parsing and canonical serialization reject the same malformed or private
 * inputs. HTTPS literals must be globally routable; local paths, credentials, fragments, and
 * private network addresses fail closed.
 *
 * <p>The helper is stateless and thread-safe. It creates fresh byte arrays and immutable
 * collections where applicable, uses UTF-8 and lowercase SHA-256 consistently, and maps validation
 * failures to bounded catalog error codes without retaining raw document content.
 */
final class CatalogSignedDocumentSupport {
  /** Closed signature algorithm accepted by discovery documents. */
  static final String ED25519 = "Ed25519";

  /** Stable error code for invalid discovery descriptors. */
  static final String INVALID_DESCRIPTOR = "invalid_catalog_discovery_descriptor";

  /** Stable error code for invalid catalog endorsements. */
  static final String INVALID_ENDORSEMENT = "invalid_catalog_endorsement";

  /** Stable error code for invalid discovery signatures. */
  static final String INVALID_SIGNATURE = "invalid_catalog_discovery_signature";

  /** Maximum accepted encoded document size in bytes. */
  static final int MAX_DOCUMENT_BYTES = 64 * 1024;

  /** Maximum character count for a bounded identifier. */
  static final int MAX_ID_CHARS = 128;

  /** Maximum character count for a display name. */
  static final int MAX_NAME_CHARS = 128;

  /** Maximum character count for a display summary. */
  static final int MAX_SUMMARY_CHARS = 512;

  /** Maximum character count for endorsement reason text. */
  static final int MAX_REASON_CHARS = 256;

  /** Maximum character count for a public URI. */
  static final int MAX_URI_CHARS = 2048;

  /** Maximum number of public source hints in a descriptor. */
  static final int MAX_SOURCE_HINTS = 4;

  /** Maximum number of advertised catalog channels. */
  static final int MAX_CHANNELS = 8;

  /** Maximum number of direct endorsement labels. */
  static final int MAX_LABELS = 8;

  /** Maximum structural nesting depth accepted from JSON input. */
  static final int MAX_JSON_DEPTH = 12;

  /** Maximum permitted lifetime of one signed discovery document. */
  static final Duration MAX_VALIDITY = Duration.ofDays(90);

  /** Maximum permitted future clock skew for an issued-at timestamp. */
  static final Duration MAX_FUTURE_SKEW = Duration.ofMinutes(5);

  /** Qualified field name used for descriptor source-hint failures. */
  private static final String SOURCE_HINTS_FIELD = "subject.sourceHints";

  /** Common suffix used for bounded URI syntax failures. */
  private static final String INVALID_URI_SUFFIX = " is not a valid URI";

  /** Closed grammar for discovery document identifiers. */
  private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

  /** Closed lowercase hexadecimal SHA-256 grammar. */
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

  /** Prevents construction of this stateless validation utility. */
  private CatalogSignedDocumentSupport() {}

  /**
   * Validates one bounded discovery identifier.
   *
   * @param value identifier text to validate
   * @param fieldName qualified field name for failures
   * @param errorCode stable document error code
   * @return normalized identifier matching the closed grammar
   */
  static String requireId(String value, String fieldName, String errorCode) {
    String normalized = requireBoundedLine(value, fieldName, MAX_ID_CHARS, errorCode);
    if (!ID.matcher(normalized).matches()) {
      throw invalid(errorCode, fieldName + " has invalid syntax");
    }
    return normalized;
  }

  /**
   * Normalizes one catalog identifier with catalog wire-format rules.
   *
   * @param value catalog identifier text
   * @param errorCode stable document error code
   * @return normalized path-safe catalog identifier
   */
  static String requireCatalogId(String value, String errorCode) {
    try {
      return AppCatalog.normalizeCatalogId(value);
    } catch (AppCatalogException _) {
      throw invalid(errorCode, "subject.catalogId is invalid");
    }
  }

  /**
   * Requires a non-null bounded single-line text value.
   *
   * @param value text to validate
   * @param fieldName qualified field name for failures
   * @param maxChars maximum permitted character count
   * @param errorCode stable document error code
   * @return validated single-line text
   */
  static String requireBoundedLine(String value, String fieldName, int maxChars, String errorCode) {
    if (value == null) {
      throw invalid(errorCode, fieldName + " is required");
    }
    return AppCatalogSidecars.requireBoundedSingleLine(value, fieldName, errorCode, maxChars);
  }

  /**
   * Requires a lowercase hexadecimal SHA-256 value.
   *
   * @param value digest text to validate
   * @param fieldName qualified field name for failures
   * @param errorCode stable document error code
   * @return validated lowercase digest
   */
  static String requireSha256(String value, String fieldName, String errorCode) {
    String normalized = requireBoundedLine(value, fieldName, 64, errorCode);
    if (!SHA256.matcher(normalized).matches()) {
      throw invalid(errorCode, fieldName + " must be lowercase SHA-256 hex");
    }
    return normalized;
  }

  /**
   * Validates an optional lowercase SHA-256 value.
   *
   * @param value optional digest text
   * @param fieldName qualified field name for failures
   * @param errorCode stable document error code
   * @return empty value or validated lowercase digest
   */
  static Optional<String> optionalSha256(String value, String fieldName, String errorCode) {
    return Optional.ofNullable(value).map(item -> requireSha256(item, fieldName, errorCode));
  }

  /**
   * Validates a bounded nonempty list of unique single-line strings.
   *
   * @param values input strings to validate
   * @param fieldName qualified field name for failures
   * @param maxItems maximum permitted item count
   * @param maxChars maximum characters per item
   * @param errorCode stable document error code
   * @return immutable validated strings in input order
   */
  static List<String> requireUniqueLines(
      List<String> values, String fieldName, int maxItems, int maxChars, String errorCode) {
    Objects.requireNonNull(values, fieldName);
    if (values.isEmpty() || values.size() > maxItems) {
      throw invalid(errorCode, fieldName + " has an invalid item count");
    }
    List<String> normalized = new ArrayList<>(values.size());
    Set<String> seen = new HashSet<>();
    for (String value : values) {
      String item = requireBoundedLine(value, fieldName, maxChars, errorCode);
      if (!seen.add(item)) {
        throw invalid(errorCode, fieldName + " contains a duplicate value");
      }
      normalized.add(item);
    }
    return List.copyOf(normalized);
  }

  /**
   * Validates the optional bounded direct-endorsement labels.
   *
   * @param values endorsement label strings
   * @return immutable validated labels in input order
   */
  static List<String> requireEndorsementLabels(List<String> values) {
    Objects.requireNonNull(values, "evidence.labels");
    if (values.size() > MAX_LABELS) {
      throw invalid(INVALID_ENDORSEMENT, "evidence.labels has an invalid item count");
    }
    if (values.isEmpty()) {
      return List.of();
    }
    return requireUniqueLines(values, "evidence.labels", MAX_LABELS, 64, INVALID_ENDORSEMENT);
  }

  /**
   * Validates bounded unique public catalog source hints.
   *
   * @param values source hint URIs to validate
   * @return immutable normalized public source hints
   */
  static List<URI> requireSourceHints(List<URI> values) {
    Objects.requireNonNull(values, "sourceHints");
    if (values.isEmpty() || values.size() > MAX_SOURCE_HINTS) {
      throw invalid(INVALID_DESCRIPTOR, SOURCE_HINTS_FIELD + " has an invalid item count");
    }
    List<URI> normalized = new ArrayList<>(values.size());
    Set<String> seen = new HashSet<>();
    for (URI value : values) {
      URI hint = requirePublicCatalogSourceHint(value);
      if (!seen.add(hint.toString())) {
        throw invalid(INVALID_DESCRIPTOR, SOURCE_HINTS_FIELD + " contains a duplicate value");
      }
      normalized.add(hint);
    }
    return List.copyOf(normalized);
  }

  /**
   * Validates an optional public descriptor evidence reference.
   *
   * @param value optional reference URI
   * @param fieldName qualified field name for failures
   * @return empty value or normalized public reference
   */
  static Optional<URI> optionalPublicReference(URI value, String fieldName) {
    return Optional.ofNullable(value)
        .map(item -> requirePublicDescriptorReference(item, fieldName));
  }

  /**
   * Validates one HTTPS or read-only Crypta catalog source hint.
   *
   * @param value source hint URI
   * @return normalized public catalog source hint
   */
  private static URI requirePublicCatalogSourceHint(URI value) {
    URI normalized = requireBasicPublicUri(value, SOURCE_HINTS_FIELD);
    if ("https".equalsIgnoreCase(normalized.getScheme())) {
      return requirePublicHttps(normalized, SOURCE_HINTS_FIELD);
    }
    if ("crypta".equalsIgnoreCase(normalized.getScheme())) {
      if (AppSubmissionRedactionScanner.containsPrivateInsertUriMaterial(normalized.toString())) {
        throw invalid(
            INVALID_DESCRIPTOR, SOURCE_HINTS_FIELD + " must not contain private insert material");
      }
      try {
        return CryptaCatalogUri.parse(normalized.toString()).toUri();
      } catch (AppCatalogException _) {
        throw invalid(
            INVALID_DESCRIPTOR, SOURCE_HINTS_FIELD + " contains an invalid crypta catalog URI");
      }
    }
    throw invalid(INVALID_DESCRIPTOR, SOURCE_HINTS_FIELD + " must use https or crypta");
  }

  /**
   * Validates one HTTPS or public Crypta evidence reference.
   *
   * @param value evidence reference URI
   * @param fieldName qualified field name for failures
   * @return normalized public evidence reference
   */
  private static URI requirePublicDescriptorReference(URI value, String fieldName) {
    URI normalized = requireBasicPublicUri(value, fieldName);
    if ("https".equalsIgnoreCase(normalized.getScheme())) {
      return requirePublicHttps(normalized, fieldName);
    }
    if ("crypta".equalsIgnoreCase(normalized.getScheme())) {
      String text = normalized.toString();
      if (AppSubmissionRedactionScanner.containsPrivateInsertUriMaterial(text)) {
        throw invalid(INVALID_DESCRIPTOR, fieldName + " must not contain private insert material");
      }
      String body = text.substring("crypta:".length());
      if (!(body.startsWith("CHK@") || body.startsWith("SSK@") || body.startsWith("USK@"))) {
        throw invalid(INVALID_DESCRIPTOR, fieldName + " contains an unsupported crypta key");
      }
      return normalized;
    }
    throw invalid(INVALID_DESCRIPTOR, fieldName + " must use https or crypta");
  }

  /**
   * Applies shared absolute, size, credential, and fragment URI constraints.
   *
   * @param value URI to normalize and validate
   * @param fieldName qualified field name for failures
   * @return normalized bounded absolute URI
   */
  private static URI requireBasicPublicUri(URI value, String fieldName) {
    URI normalized = Objects.requireNonNull(value, fieldName).normalize();
    String text = normalized.toString();
    if (text.length() > MAX_URI_CHARS || !normalized.isAbsolute()) {
      throw invalid(INVALID_DESCRIPTOR, fieldName + " must be a bounded absolute URI");
    }
    if (normalized.getUserInfo() != null || normalized.getFragment() != null) {
      throw invalid(INVALID_DESCRIPTOR, fieldName + " must not contain credentials or a fragment");
    }
    return normalized;
  }

  /**
   * Requires a hierarchical public HTTPS URI without query data.
   *
   * @param uri normalized HTTPS URI to inspect
   * @param fieldName qualified field name for failures
   * @return validated public HTTPS URI
   */
  private static URI requirePublicHttps(URI uri, String fieldName) {
    if (uri.isOpaque()
        || uri.getHost() == null
        || uri.getHost().isBlank()
        || uri.getQuery() != null
        || !isPublicHost(uri.getHost())) {
      throw invalid(
          INVALID_DESCRIPTOR, fieldName + " must be a public HTTPS URI without query credentials");
    }
    return uri;
  }

  /**
   * Reports whether a hostname or address literal is suitable for public discovery.
   *
   * @param rawHost URI host text
   * @return {@code true} for a public DNS name or globally routable literal
   */
  private static boolean isPublicHost(String rawHost) {
    String host = rawHost.toLowerCase(Locale.ROOT);
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.substring(1, host.length() - 1);
    }
    if (host.endsWith(".")) {
      host = host.substring(0, host.length() - 1);
    }
    if (host.equals("localhost")
        || host.endsWith(".localhost")
        || host.endsWith(".local")
        || host.endsWith(".internal")) {
      return false;
    }
    try {
      return isGlobalUnicastLiteral(InetAddress.ofLiteral(host));
    } catch (IllegalArgumentException _) {
      return !looksLikeMalformedAddressLiteral(host);
    }
  }

  /**
   * Reports whether a parsed address literal is globally routable unicast.
   *
   * @param address parsed IPv4 or IPv6 literal
   * @return {@code true} when the address is permitted for public discovery
   */
  private static boolean isGlobalUnicastLiteral(InetAddress address) {
    if (address.isAnyLocalAddress()
        || address.isLoopbackAddress()
        || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()
        || address.isMulticastAddress()) {
      return false;
    }
    byte[] bytes = address.getAddress();
    return address instanceof Inet4Address ? isGlobalIpv4(bytes) : isGlobalIpv6(bytes);
  }

  /**
   * Applies closed public-address exclusions to an IPv4 address.
   *
   * @param bytes four-byte IPv4 address
   * @return {@code true} when the address is globally routable
   */
  private static boolean isGlobalIpv4(byte[] bytes) {
    int first = Byte.toUnsignedInt(bytes[0]);
    int second = Byte.toUnsignedInt(bytes[1]);
    int third = Byte.toUnsignedInt(bytes[2]);
    return first != 0
        && first != 10
        && !(first == 100 && second >= 64 && second <= 127)
        && first != 127
        && !(first == 169 && second == 254)
        && !(first == 172 && second >= 16 && second <= 31)
        && !(first == 192 && second == 0 && (third == 0 || third == 2))
        && !(first == 192 && second == 168)
        && !(first == 198 && (second == 18 || second == 19))
        && !(first == 198 && second == 51 && third == 100)
        && !(first == 203 && second == 0 && third == 113)
        && first < 224;
  }

  /**
   * Applies closed public-address exclusions to an IPv6 address.
   *
   * @param bytes sixteen-byte IPv6 address
   * @return {@code true} when the address is globally routable
   */
  private static boolean isGlobalIpv6(byte[] bytes) {
    int first = Byte.toUnsignedInt(bytes[0]);
    int second = Byte.toUnsignedInt(bytes[1]);
    int third = Byte.toUnsignedInt(bytes[2]);
    int fourth = Byte.toUnsignedInt(bytes[3]);
    boolean globalUnicast = (first & 0xe0) == 0x20;
    boolean ietfSpecial = first == 0x20 && second == 0x01 && (third & 0xfe) == 0;
    boolean documentation = first == 0x20 && second == 0x01 && third == 0x0d && fourth == 0xb8;
    boolean sixToFour = first == 0x20 && second == 0x02;
    boolean documentationV2 = first == 0x3f && second == 0xff && (third & 0xf0) == 0;
    return globalUnicast && !ietfSpecial && !documentation && !sixToFour && !documentationV2;
  }

  /**
   * Detects numeric or colon-bearing hosts that failed literal parsing.
   *
   * @param host normalized host text
   * @return {@code true} when the text resembles a malformed address literal
   */
  private static boolean looksLikeMalformedAddressLiteral(String host) {
    if (host.indexOf(':') >= 0) {
      return true;
    }
    for (int index = 0; index < host.length(); index++) {
      char value = host.charAt(index);
      if (value != '.' && !Character.isDigit(value)) {
        return false;
      }
    }
    return !host.isEmpty();
  }

  /**
   * Validates ordering and maximum duration of a signed-document interval.
   *
   * @param issuedAt signed issue instant
   * @param expiresAt signed exclusive expiration instant
   * @param errorCode stable document error code
   */
  static void requireValidity(Instant issuedAt, Instant expiresAt, String errorCode) {
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    if (!issuedAt.isBefore(expiresAt)) {
      throw invalid(errorCode, "validity.issuedAt must precede validity.expiresAt");
    }
    Duration validity = Duration.between(issuedAt, expiresAt);
    if (validity.compareTo(MAX_VALIDITY) > 0) {
      throw invalid(errorCode, "signed document validity exceeds 90 days");
    }
  }

  /**
   * Requires a descriptor interval to be current at a local instant.
   *
   * @param issuedAt signed issue instant
   * @param expiresAt signed exclusive expiration instant
   * @param now local verification instant
   */
  static void requireCurrent(Instant issuedAt, Instant expiresAt, Instant now) {
    Objects.requireNonNull(now, "now");
    if (issuedAt.isAfter(now.plus(MAX_FUTURE_SKEW))) {
      throw invalid(INVALID_DESCRIPTOR, "signed document is not yet fresh");
    }
    if (!expiresAt.isAfter(now)) {
      throw invalid(INVALID_DESCRIPTOR, "signed document has expired");
    }
  }

  /**
   * Bounds and copies raw signed-document bytes before parsing.
   *
   * @param bytes caller-supplied document bytes
   * @param description bounded document description for failures
   * @param errorCode stable document error code
   * @return fresh bounded byte array
   */
  static byte[] parseBytes(byte[] bytes, String description, String errorCode) {
    Objects.requireNonNull(bytes, "bytes");
    if (bytes.length == 0 || bytes.length > MAX_DOCUMENT_BYTES) {
      throw invalid(errorCode, description + " has an invalid byte length");
    }
    return bytes.clone();
  }

  /**
   * Parses bounded strict UTF-8 bytes as one JSON object.
   *
   * @param bytes caller-supplied document bytes
   * @param description bounded document description for failures
   * @param errorCode stable document error code
   * @return parsed JSON-compatible object map
   */
  static Map<String, Object> parseObject(byte[] bytes, String description, String errorCode) {
    byte[] bounded = parseBytes(bytes, description, errorCode);
    String json;
    try {
      json =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bounded))
              .toString();
    } catch (CharacterCodingException _) {
      throw invalid(errorCode, description + " must be valid UTF-8");
    }
    requireJsonDepth(json, description, errorCode);
    try {
      return AppSubmissionJson.parseObject(json, description);
    } catch (AppCatalogException _) {
      throw invalid(errorCode, description + " is not valid closed JSON");
    }
  }

  /**
   * Enforces the maximum structural JSON nesting depth outside strings.
   *
   * @param json decoded JSON text
   * @param description bounded document description for failures
   * @param errorCode stable document error code
   */
  private static void requireJsonDepth(String json, String description, String errorCode) {
    int depth = 0;
    boolean quoted = false;
    boolean escaped = false;
    for (int index = 0; index < json.length(); index++) {
      char character = json.charAt(index);
      if (quoted) {
        if (escaped) {
          escaped = false;
        } else if (character == '\\') {
          escaped = true;
        } else if (character == '"') {
          quoted = false;
        }
      } else if (character == '"') {
        quoted = true;
      } else {
        depth = adjustJsonDepth(depth, character, description, errorCode);
      }
    }
  }

  /**
   * Applies one structural JSON delimiter to the current nesting depth.
   *
   * @param depth current structural nesting depth
   * @param character decoded JSON character outside a string
   * @param description bounded document description for failures
   * @param errorCode stable document error code
   * @return adjusted structural nesting depth
   */
  private static int adjustJsonDepth(
      int depth, char character, String description, String errorCode) {
    if (character == '{' || character == '[') {
      int nestedDepth = depth + 1;
      if (nestedDepth > MAX_JSON_DEPTH) {
        throw invalid(errorCode, description + " exceeds the JSON nesting limit");
      }
      return nestedDepth;
    }
    if (character == '}' || character == ']') {
      int enclosingDepth = depth - 1;
      if (enclosingDepth < 0) {
        throw invalid(errorCode, description + " has invalid JSON nesting");
      }
      return enclosingDepth;
    }
    return depth;
  }

  /**
   * Requires an object to contain all required fields and no unknown fields.
   *
   * @param object parsed JSON-compatible object
   * @param required required field names
   * @param optional optional field names
   * @param fieldName qualified object name for failures
   * @param errorCode stable document error code
   */
  static void requireClosedObject(
      Map<String, Object> object,
      Set<String> required,
      Set<String> optional,
      String fieldName,
      String errorCode) {
    Set<String> allowed = new HashSet<>(required);
    allowed.addAll(optional);
    for (String key : object.keySet()) {
      if (!allowed.contains(key)) {
        throw invalid(errorCode, fieldName + " contains unknown field: " + key);
      }
    }
    for (String key : required) {
      if (!object.containsKey(key)) {
        throw invalid(errorCode, fieldName + " is missing field: " + key);
      }
    }
  }

  /**
   * Requires one nested JSON object field.
   *
   * @param object containing parsed object
   * @param key exact field key
   * @param fieldName qualified field name for failures
   * @param errorCode stable document error code
   * @return nested JSON-compatible object map
   */
  @SuppressWarnings("unchecked")
  static Map<String, Object> requireObject(
      Map<String, Object> object, String key, String fieldName, String errorCode) {
    Object value = object.get(key);
    if (value instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    throw invalid(errorCode, fieldName + " must be an object");
  }

  /**
   * Requires the supported signed-document schema version.
   *
   * @param object parsed root document object
   * @param errorCode stable document error code
   * @return supported schema version value
   */
  static int requireVersion(Map<String, Object> object, String errorCode) {
    Object value = object.get("schemaVersion");
    if (value instanceof Long number && number == 1L) {
      return 1;
    }
    throw invalid(errorCode, "schemaVersion must equal 1");
  }

  /**
   * Requires one JSON string field.
   *
   * @param object containing parsed object
   * @param key exact field key
   * @param fieldName qualified field name for failures
   * @param errorCode stable document error code
   * @return raw string field value
   */
  static String requireString(
      Map<String, Object> object, String key, String fieldName, String errorCode) {
    Object value = object.get(key);
    if (value instanceof String text) {
      return text;
    }
    throw invalid(errorCode, fieldName + " must be a string");
  }

  /**
   * Reads one optional JSON string field.
   *
   * @param object containing parsed object
   * @param key exact field key
   * @param fieldName qualified field name for failures
   * @param errorCode stable document error code
   * @return empty value or raw string field value
   */
  static Optional<String> optionalString(
      Map<String, Object> object, String key, String fieldName, String errorCode) {
    Object value = object.get(key);
    if (value == null) {
      return Optional.empty();
    }
    if (value instanceof String text) {
      return Optional.of(text);
    }
    throw invalid(errorCode, fieldName + " must be a string");
  }

  /**
   * Requires one JSON array containing only strings.
   *
   * @param object containing parsed object
   * @param key exact field key
   * @param fieldName qualified field name for failures
   * @param errorCode stable document error code
   * @return immutable string values in input order
   */
  static List<String> requireStrings(
      Map<String, Object> object, String key, String fieldName, String errorCode) {
    Object value = object.get(key);
    if (!(value instanceof List<?> list)) {
      throw invalid(errorCode, fieldName + " must be an array");
    }
    List<String> values = new ArrayList<>(list.size());
    for (Object item : list) {
      if (!(item instanceof String text)) {
        throw invalid(errorCode, fieldName + " must contain only strings");
      }
      values.add(text);
    }
    return List.copyOf(values);
  }

  /**
   * Parses one optional descriptor URI field.
   *
   * @param object containing parsed object
   * @param key exact field key
   * @param fieldName qualified field name for failures
   * @return empty value or parsed URI
   */
  static Optional<URI> optionalUri(Map<String, Object> object, String key, String fieldName) {
    return optionalString(object, key, fieldName, INVALID_DESCRIPTOR)
        .map(
            text -> {
              try {
                return new URI(text);
              } catch (URISyntaxException _) {
                throw invalid(INVALID_DESCRIPTOR, fieldName + INVALID_URI_SUFFIX);
              }
            });
  }

  /**
   * Parses source-hint text as a syntactically valid URI.
   *
   * @param value source-hint URI text
   * @return parsed URI for subsequent public-source validation
   */
  static URI requireSourceHintUriText(String value) {
    try {
      return new URI(value);
    } catch (URISyntaxException _) {
      throw invalid(INVALID_DESCRIPTOR, SOURCE_HINTS_FIELD + INVALID_URI_SUFFIX);
    }
  }

  /**
   * Parses one required ISO-8601 instant field.
   *
   * @param object containing parsed object
   * @param key exact field key
   * @param fieldName qualified field name for failures
   * @param errorCode stable document error code
   * @return parsed canonical instant
   */
  static Instant requireInstant(
      Map<String, Object> object, String key, String fieldName, String errorCode) {
    try {
      return Instant.parse(requireString(object, key, fieldName, errorCode));
    } catch (DateTimeParseException _) {
      throw invalid(errorCode, fieldName + " must be an ISO-8601 instant");
    }
  }

  /**
   * Requires the closed Ed25519 signature algorithm identifier.
   *
   * @param value declared algorithm text
   * @param errorCode stable document error code
   * @return validated {@code Ed25519} identifier
   */
  static String requireAlgorithm(String value, String errorCode) {
    String algorithm = requireBoundedLine(value, "signature.algorithm", 32, errorCode);
    if (!ED25519.equals(algorithm)) {
      throw invalid(errorCode, "signature.algorithm must be Ed25519");
    }
    return algorithm;
  }

  /**
   * Validates bounded Base64 encoding of a 64-byte Ed25519 signature.
   *
   * @param value declared Base64 signature text
   * @param errorCode stable document error code
   * @return validated Base64 signature text
   */
  static String requireSignatureBase64(String value, String errorCode) {
    String normalized = requireBoundedLine(value, "signature.valueBase64", 256, errorCode);
    try {
      byte[] signature = Base64.getDecoder().decode(normalized);
      if (signature.length != 64) {
        throw invalid(errorCode, "signature.valueBase64 must contain a 64-byte signature");
      }
      return normalized;
    } catch (IllegalArgumentException _) {
      throw invalid(errorCode, "signature.valueBase64 is invalid base64");
    }
  }

  /**
   * Computes lowercase SHA-256 over exact bytes.
   *
   * @param bytes exact digest subject bytes
   * @return lowercase hexadecimal SHA-256 digest
   */
  static String sha256(byte[] bytes) {
    return HexFormat.of().formatHex(AppCatalogSidecars.newArtifactSha256Digest().digest(bytes));
  }

  /**
   * Computes the canonical fingerprint of an encoded public key.
   *
   * @param key public key with canonical encoded form
   * @return lowercase SHA-256 fingerprint of encoded key bytes
   */
  static String publicKeyFingerprint(PublicKey key) {
    byte[] encoded = Objects.requireNonNull(key, "key").getEncoded();
    if (encoded == null || encoded.length == 0) {
      throw invalid(INVALID_SIGNATURE, "issuer public key has no canonical encoding");
    }
    return sha256(encoded);
  }

  /**
   * Compares a declared self-digest with canonical content in constant time.
   *
   * @param declared declared lowercase content digest
   * @param content canonical signed-document content bytes
   * @param errorCode stable document error code
   */
  static void requireSelfDigest(String declared, byte[] content, String errorCode) {
    byte[] actual = sha256(content).getBytes(StandardCharsets.US_ASCII);
    byte[] expected = declared.getBytes(StandardCharsets.US_ASCII);
    if (!MessageDigest.isEqual(expected, actual)) {
      throw invalid(errorCode, "selfDigestSha256 does not match canonical content");
    }
  }

  /**
   * Verifies a detached signature over exact canonical payload bytes.
   *
   * @param key locally trusted issuer public key
   * @param algorithm validated signature algorithm identifier
   * @param valueBase64 validated Base64 signature value
   * @param payload exact canonical signature payload
   */
  static void verifySignature(PublicKey key, String algorithm, String valueBase64, byte[] payload) {
    try {
      Signature verifier = Signature.getInstance(algorithm);
      verifier.initVerify(key);
      verifier.update(payload);
      if (!verifier.verify(Base64.getDecoder().decode(valueBase64))) {
        throw invalid(INVALID_SIGNATURE, "signature does not match canonical payload");
      }
    } catch (GeneralSecurityException exception) {
      throw new AppCatalogException(
          INVALID_SIGNATURE, "failed to verify signed discovery document", exception);
    }
  }

  /**
   * Serializes a deterministic JSON-compatible map as UTF-8 bytes.
   *
   * @param value insertion-ordered JSON-compatible value
   * @return fresh canonical UTF-8 JSON bytes
   */
  static byte[] jsonBytes(Map<String, Object> value) {
    return AppSubmissionJson.write(value).getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Creates a bounded catalog-domain validation failure.
   *
   * @param errorCode stable machine-readable error code
   * @param message bounded validation explanation
   * @return catalog exception carrying the supplied bounded failure
   */
  static AppCatalogException invalid(String errorCode, String message) {
    return new AppCatalogException(errorCode, message);
  }
}
