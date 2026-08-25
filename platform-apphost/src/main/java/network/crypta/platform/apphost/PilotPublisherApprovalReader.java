package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Reads an authenticated pilot publisher-approval artifact into its bounded runtime projection.
 *
 * <p>This class is the file and schema boundary between protected certification evidence and
 * AppHost configuration. It rejects symbolic links, non-regular files, empty or oversized input,
 * malformed UTF-8, duplicate JSON keys, unknown fields, and an incomplete operation set. Before
 * parsing, it compares the SHA-256 digest of the exact retained bytes with a value supplied by an
 * independently authenticated execution binding.
 *
 * <p>The reader does not download artifacts, modify trusted-key registries, or establish approval
 * provenance by itself. The caller must authenticate the expected digest and protected producer.
 * The returned {@link PilotPublisherVerificationPolicy.Approval} contains only the public runtime
 * projection needed to enforce the pilot ID, node ID, publisher, registry roots, validity window,
 * and permitted bundle-signature subjects. Private signing material is neither accepted nor
 * returned.
 */
public final class PilotPublisherApprovalReader {
  private static final int MAX_APPROVAL_BYTES = 256 * 1024;
  private static final Set<String> REQUIRED_FIELDS =
      Set.of(
          "schemaVersion",
          "kind",
          "pilotId",
          "appId",
          "provenance",
          "publisherKeyId",
          "publisherFingerprint",
          "sourceRepositoryIdentity",
          "handoffDigest",
          "pilotNodeId",
          "nodeAttestationFingerprint",
          "normalStableRegistryDigest",
          "catalogRegistryDigest",
          "pilotRegistryDigest",
          "permittedSubjects",
          "allowedOperations",
          "validFrom",
          "validUntil",
          "revoked",
          "cleanupRequired",
          "approvalAuthorityKeyId",
          "receiptDigest",
          "signatureBase64");
  private static final Set<String> SUBJECT_FIELDS =
      Set.of("version", "bundleDigest", "bundleSignatureDigest");
  private static final Set<String> REQUIRED_OPERATIONS =
      Set.of("install", "update", "caution-update", "rollback", "cleanup");
  private static final String WRONG_OPERATION_SET_MESSAGE =
      "pilot publisher approval has the wrong operation set";

  private PilotPublisherApprovalReader() {}

  /**
   * Reads a closed approval after authenticating its exact raw file digest.
   *
   * <p>The expected digest must come from the already-authenticated execution binding, not from the
   * approval itself. This reader intentionally does not accept a caller-authored reduced JSON
   * projection: it requires the complete schema-v1 receipt shape before selecting the public fields
   * needed by AppHost. The method reads at most 256 KiB, does not follow symbolic links, and
   * accepts only strict UTF-8 JSON with the exact required field set. It performs no remote access
   * and does not install the resulting approval into a runtime.
   *
   * @param approvalFile exact signed approval receipt retained by the protected evidence boundary
   * @param expectedDigest independently authenticated SHA-256 of the exact approval bytes
   * @return validated public approval projection suitable for constructing the pilot policy
   * @throws IOException if the file or approval is unsafe, malformed, incomplete, or substituted
   * @throws NullPointerException if {@code approvalFile} is {@code null}
   */
  public static PilotPublisherVerificationPolicy.Approval read(
      Path approvalFile, String expectedDigest) throws IOException {
    Path file = requireRegularFile(approvalFile);
    byte[] bytes = readBounded(file);
    if (!digest(bytes).equals(expectedDigest)) {
      throw new AppHostConfigurationException(
          "pilot publisher approval digest differs from authenticated execution evidence");
    }
    Map<String, Object> approval = parseObject(decodeUtf8(bytes));
    requireExactFields(approval, REQUIRED_FIELDS, "pilot publisher approval");
    if (!Long.valueOf(1L).equals(approval.get("schemaVersion"))) {
      throw invalid("pilot publisher approval has an unsupported schema version");
    }
    if (!"stable-1.0-pilot-publisher-key-approval".equals(approval.get("kind"))) {
      throw invalid("pilot publisher approval has the wrong kind");
    }
    if (!Boolean.TRUE.equals(approval.get("cleanupRequired"))) {
      throw invalid("pilot publisher approval must require cleanup");
    }
    requireClosedOperations(approval.get("allowedOperations"));
    return new PilotPublisherVerificationPolicy.Approval(
        string(approval, "pilotId"),
        string(approval, "pilotNodeId"),
        string(approval, "appId"),
        string(approval, "publisherKeyId"),
        string(approval, "publisherFingerprint"),
        string(approval, "normalStableRegistryDigest"),
        string(approval, "catalogRegistryDigest"),
        string(approval, "pilotRegistryDigest"),
        instant(approval, "validFrom"),
        instant(approval, "validUntil"),
        revoked(approval),
        subjects(approval.get("permittedSubjects")));
  }

  private static Path requireRegularFile(Path input) throws IOException {
    Path lexical = Objects.requireNonNull(input, "approvalFile").toAbsolutePath().normalize();
    Path current = lexical.getRoot();
    for (Path component : lexical) {
      current = current == null ? component : current.resolve(component);
      if (Files.isSymbolicLink(current)) {
        throw invalid("pilot publisher approval must not use symbolic links");
      }
    }
    if (!Files.isRegularFile(lexical, LinkOption.NOFOLLOW_LINKS)) {
      throw invalid("pilot publisher approval must be a regular non-symlink file");
    }
    return lexical;
  }

  private static byte[] readBounded(Path file) throws IOException {
    long size = Files.size(file);
    if (size <= 0L || size > MAX_APPROVAL_BYTES) {
      throw invalid("pilot publisher approval size is outside the supported bound");
    }
    byte[] bytes = Files.readAllBytes(file);
    if (bytes.length != size) {
      throw invalid("pilot publisher approval changed while it was read");
    }
    return bytes;
  }

  private static String decodeUtf8(byte[] bytes) throws AppHostConfigurationException {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString();
    } catch (CharacterCodingException exception) {
      throw new AppHostConfigurationException(
          "pilot publisher approval is not valid UTF-8", exception);
    }
  }

  private static List<PilotPublisherVerificationPolicy.Subject> subjects(Object value)
      throws AppHostConfigurationException {
    if (!(value instanceof List<?> values) || values.size() != 3) {
      throw invalid("pilot publisher approval must contain exactly three permitted subjects");
    }
    List<PilotPublisherVerificationPolicy.Subject> subjects = new ArrayList<>(values.size());
    for (Object element : values) {
      Map<String, Object> subject = object(element, "pilot publisher subject");
      requireExactFields(subject, SUBJECT_FIELDS, "pilot publisher subject");
      string(subject, "bundleDigest");
      subjects.add(
          new PilotPublisherVerificationPolicy.Subject(
              string(subject, "version"), string(subject, "bundleSignatureDigest")));
    }
    return List.copyOf(subjects);
  }

  private static void requireClosedOperations(Object value) throws AppHostConfigurationException {
    if (!(value instanceof List<?> values) || values.size() != REQUIRED_OPERATIONS.size()) {
      throw invalid(WRONG_OPERATION_SET_MESSAGE);
    }
    Set<String> actual = new java.util.HashSet<>();
    for (Object operation : values) {
      if (!(operation instanceof String text) || !actual.add(text)) {
        throw invalid(WRONG_OPERATION_SET_MESSAGE);
      }
    }
    if (!actual.equals(REQUIRED_OPERATIONS)) {
      throw invalid(WRONG_OPERATION_SET_MESSAGE);
    }
  }

  private static String string(Map<String, Object> object, String field)
      throws AppHostConfigurationException {
    Object value = object.get(field);
    if (value instanceof String text) {
      return text;
    }
    throw invalid("pilot publisher approval field is not a string: " + field);
  }

  private static boolean revoked(Map<String, Object> object) throws AppHostConfigurationException {
    Object value = object.get("revoked");
    if (value instanceof Boolean bool) {
      return bool;
    }
    throw invalid("pilot publisher approval field is not a boolean: revoked");
  }

  private static Instant instant(Map<String, Object> object, String field)
      throws AppHostConfigurationException {
    try {
      return Instant.parse(string(object, field));
    } catch (DateTimeParseException exception) {
      throw new AppHostConfigurationException(
          "pilot publisher approval has an invalid timestamp: " + field, exception);
    }
  }

  private static void requireExactFields(
      Map<String, Object> object, Set<String> fields, String description)
      throws AppHostConfigurationException {
    if (!object.keySet().equals(fields)) {
      throw invalid(description + " has missing or unsupported fields");
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(Object value, String description)
      throws AppHostConfigurationException {
    if (value instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    throw invalid(description + " must be a JSON object");
  }

  private static Map<String, Object> parseObject(String json) throws AppHostConfigurationException {
    Parser parser = new Parser(json);
    Object value = parser.parseValue();
    parser.skipWhitespace();
    if (!parser.finished()) {
      throw invalid("pilot publisher approval contains trailing JSON data");
    }
    return object(value, "pilot publisher approval");
  }

  private static String digest(byte[] bytes) {
    try {
      return "sha256:"
          + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static AppHostConfigurationException invalid(String message) {
    return new AppHostConfigurationException(message);
  }

  private static final class Parser {
    private final String json;
    private int index;

    private Parser(String json) {
      this.json = Objects.requireNonNull(json, "json");
    }

    private Object parseValue() throws AppHostConfigurationException {
      skipWhitespace();
      if (finished()) {
        throw invalid("pilot publisher approval JSON is empty");
      }
      char next = json.charAt(index);
      return switch (next) {
        case '{' -> parseObjectValue();
        case '[' -> parseArray();
        case '"' -> parseString();
        case 't' -> parseLiteral("true", Boolean.TRUE);
        case 'f' -> parseLiteral("false", Boolean.FALSE);
        case 'n' -> parseLiteral("null", null);
        default -> {
          if (next == '-' || Character.isDigit(next)) {
            yield parseInteger();
          }
          throw invalid("pilot publisher approval contains invalid JSON");
        }
      };
    }

    private Map<String, Object> parseObjectValue() throws AppHostConfigurationException {
      index++;
      Map<String, Object> result = new LinkedHashMap<>();
      skipWhitespace();
      if (consume('}')) {
        return result;
      }
      while (true) {
        skipWhitespace();
        if (finished() || json.charAt(index) != '"') {
          throw invalid("pilot publisher approval object key must be a string");
        }
        String key = parseString();
        if (result.containsKey(key)) {
          throw invalid("pilot publisher approval contains a duplicate JSON key");
        }
        skipWhitespace();
        require(':');
        result.put(key, parseValue());
        skipWhitespace();
        if (consume('}')) {
          return result;
        }
        require(',');
      }
    }

    private List<Object> parseArray() throws AppHostConfigurationException {
      index++;
      List<Object> values = new ArrayList<>();
      skipWhitespace();
      if (consume(']')) {
        return List.of();
      }
      while (true) {
        values.add(parseValue());
        skipWhitespace();
        if (consume(']')) {
          return List.copyOf(values);
        }
        require(',');
      }
    }

    private String parseString() throws AppHostConfigurationException {
      require('"');
      StringBuilder value = new StringBuilder();
      while (!finished()) {
        char next = json.charAt(index++);
        if (next == '"') {
          return value.toString();
        }
        if (next != '\\') {
          if (next < 0x20) {
            throw invalid("pilot publisher approval contains a control character");
          }
          value.append(next);
          continue;
        }
        if (finished()) {
          throw invalid("pilot publisher approval contains an invalid escape");
        }
        char escape = json.charAt(index++);
        switch (escape) {
          case '"', '\\', '/' -> value.append(escape);
          case 'b' -> value.append('\b');
          case 'f' -> value.append('\f');
          case 'n' -> value.append('\n');
          case 'r' -> value.append('\r');
          case 't' -> value.append('\t');
          case 'u' -> value.append(parseUnicode());
          default -> throw invalid("pilot publisher approval contains an invalid escape");
        }
      }
      throw invalid("pilot publisher approval contains an unterminated string");
    }

    private char parseUnicode() throws AppHostConfigurationException {
      if (index + 4 > json.length()) {
        throw invalid("pilot publisher approval contains an invalid unicode escape");
      }
      String digits = json.substring(index, index + 4);
      index += 4;
      try {
        return (char) Integer.parseInt(digits, 16);
      } catch (NumberFormatException exception) {
        throw new AppHostConfigurationException(
            "pilot publisher approval contains an invalid unicode escape", exception);
      }
    }

    private Object parseLiteral(String literal, Object value) throws AppHostConfigurationException {
      if (!json.startsWith(literal, index)) {
        throw invalid("pilot publisher approval contains an invalid literal");
      }
      index += literal.length();
      return value;
    }

    private Long parseInteger() throws AppHostConfigurationException {
      int start = index;
      if (json.charAt(index) == '-') {
        index++;
      }
      if (finished() || !Character.isDigit(json.charAt(index))) {
        throw invalid("pilot publisher approval contains an invalid number");
      }
      while (!finished() && Character.isDigit(json.charAt(index))) {
        index++;
      }
      if (!finished()
          && (json.charAt(index) == '.'
              || json.charAt(index) == 'e'
              || json.charAt(index) == 'E')) {
        throw invalid("pilot publisher approval accepts integer numbers only");
      }
      try {
        return Long.parseLong(json.substring(start, index));
      } catch (NumberFormatException exception) {
        throw new AppHostConfigurationException(
            "pilot publisher approval contains an out-of-range number", exception);
      }
    }

    private void skipWhitespace() {
      while (!finished()) {
        char next = json.charAt(index);
        if (next != ' ' && next != '\n' && next != '\r' && next != '\t') {
          return;
        }
        index++;
      }
    }

    private boolean finished() {
      return index >= json.length();
    }

    private boolean consume(char expected) {
      if (!finished() && json.charAt(index) == expected) {
        index++;
        return true;
      }
      return false;
    }

    private void require(char expected) throws AppHostConfigurationException {
      if (finished() || json.charAt(index) != expected) {
        throw invalid("pilot publisher approval JSON is malformed");
      }
      index++;
    }
  }
}
