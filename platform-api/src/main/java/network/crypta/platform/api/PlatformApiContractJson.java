package network.crypta.platform.api;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * JSON encoder and decoder for Platform API compatibility contract snapshots.
 *
 * <p>The encoder produces only deterministic JDK map/list/scalar shapes accepted by the existing
 * Platform API JSON writer. The decoder is intentionally small and dependency-free; it reads the
 * same contract envelope used by {@code GET /api/v1/platform/contract} and by the developer CLI's
 * offline snapshot command.
 *
 * <p>This class is not a general JSON framework. It knows only the contract snapshot schema and the
 * JSON primitives that schema uses. That narrow scope keeps offline developer tooling and release
 * certification free of extra schema-generation dependencies while still allowing snapshots to
 * round-trip in tests. Field order follows the public contract order so checked-in fixtures,
 * release evidence, and catalog review reports remain stable across runs.
 *
 * <p>The emitted JSON is metadata only. It includes route templates, action labels, capability
 * names, and stability annotations, but it never serializes request bodies, query strings,
 * filesystem paths, process command lines, app tokens, browser-session tokens, passwords, or
 * private key material.
 */
public final class PlatformApiContractJson {
  private static final String FIELD_ACTION_LABEL = "actionLabel";
  private static final String FIELD_API_VERSION = "apiVersion";
  private static final String FIELD_APP_BROWSER_PRINCIPALS_ALLOWED = "appBrowserPrincipalsAllowed";
  private static final String FIELD_APP_PROCESS_PRINCIPALS_ALLOWED = "appProcessPrincipalsAllowed";
  private static final String FIELD_CAPABILITIES = "capabilities";
  private static final String FIELD_CONTRACT = "contract";
  private static final String FIELD_CONTRACT_VERSION = "contractVersion";
  private static final String FIELD_DEPRECATED_SINCE_CONTRACT_VERSION =
      "deprecatedSinceContractVersion";
  private static final String FIELD_DEPRECATION = "deprecation";
  private static final String FIELD_DESCRIPTION = "description";
  private static final String FIELD_ENDPOINTS = "endpoints";
  private static final String FIELD_GENERATED_BY = "generatedBy";
  private static final String FIELD_HOST_OPERATOR_BYPASS_ALLOWED = "hostOperatorBypassAllowed";
  private static final String FIELD_METHOD = "method";
  private static final String FIELD_NAME = "name";
  private static final String FIELD_NOTE = "note";
  private static final String FIELD_REMOVAL_CONTRACT_VERSION = "removalContractVersion";
  private static final String FIELD_REQUIRED_CAPABILITIES = "requiredCapabilities";
  private static final String FIELD_ROUTE_FAMILY = "routeFamily";
  private static final String FIELD_ROUTE_TEMPLATE = "routeTemplate";
  private static final String FIELD_SINCE_CONTRACT_VERSION = "sinceContractVersion";
  private static final String FIELD_STABILITY = "stability";
  private static final String FIELD_STABILITY_POLICY = "stabilityPolicy";

  private PlatformApiContractJson() {}

  /**
   * Builds the public endpoint response envelope.
   *
   * <p>The envelope mirrors the HTTP response body for {@code GET /api/v1/platform/contract}. It is
   * also the shape written by the developer CLI snapshot command, which means consumers can compare
   * endpoint output and offline artifacts without another wrapping step.
   *
   * @param contract contract to encode into the public response envelope
   * @return deterministic JSON-compatible envelope map with a {@code contract} field
   */
  public static Map<String, Object> envelope(PlatformApiContract contract) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put(FIELD_CONTRACT, toJsonValue(contract));
    return envelope;
  }

  /**
   * Serializes a contract snapshot envelope.
   *
   * <p>The method delegates to the Platform API JSON writer after building the same map shape
   * returned by {@link #envelope(PlatformApiContract)}. It is the preferred entry point for
   * snapshot files because it preserves the canonical response envelope.
   *
   * @param contract contract to encode into canonical snapshot JSON
   * @return deterministic JSON text suitable for offline compatibility verification
   */
  public static String writeEnvelope(PlatformApiContract contract) {
    return PlatformApiJsonWriter.write(envelope(contract));
  }

  /**
   * Converts one contract to a JSON-compatible object.
   *
   * <p>The returned object is the nested {@code contract} value, not the outer endpoint envelope.
   * It is useful when composing larger evidence documents, such as release-certification reports,
   * that already provide their own top-level object.
   *
   * @param contract contract to encode into the nested contract object
   * @return deterministic JSON-compatible map containing only public compatibility metadata
   */
  public static Map<String, Object> toJsonValue(PlatformApiContract contract) {
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, FIELD_CONTRACT);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put(FIELD_API_VERSION, checkedContract.apiVersion());
    json.put(FIELD_CONTRACT_VERSION, checkedContract.contractVersion());
    json.put(FIELD_GENERATED_BY, checkedContract.generatedBy());
    json.put(FIELD_STABILITY_POLICY, checkedContract.stabilityPolicy());
    json.put(
        FIELD_CAPABILITIES,
        checkedContract.capabilities().stream()
            .map(PlatformApiContractJson::capabilityJson)
            .toList());
    json.put(
        FIELD_ENDPOINTS,
        checkedContract.endpoints().stream().map(PlatformApiContractJson::endpointJson).toList());
    return json;
  }

  /**
   * Parses a contract snapshot produced by this class.
   *
   * <p>Both the public envelope shape and the raw nested {@code contract} object are accepted so
   * tests and local tooling can reuse this parser without adding wrapper code. The parser validates
   * field types before constructing the model, and the model constructor then checks descriptor
   * invariants such as positive contract versions and endpoint capability references.
   *
   * <p>Only the subset of JSON used by contract snapshots is accepted. Numbers must be integers,
   * objects preserve insertion order, and malformed text reports the approximate JSON offset to
   * make CLI diagnostics actionable.
   *
   * @param json JSON text containing a Platform API contract
   * @return parsed immutable contract model
   * @throws IllegalArgumentException if the JSON text or contract fields are malformed
   */
  public static PlatformApiContract parse(String json) {
    Object root = new Parser(Objects.requireNonNull(json, "json")).parse();
    Map<String, Object> rootObject = asObject(root, "contract root");
    //noinspection Java8MapApi
    Object contractObject =
        rootObject.containsKey(FIELD_CONTRACT) ? rootObject.get(FIELD_CONTRACT) : rootObject;
    Map<String, Object> contract = asObject(contractObject, FIELD_CONTRACT);
    return new PlatformApiContract(
        string(contract, FIELD_API_VERSION),
        integer(contract, FIELD_CONTRACT_VERSION),
        string(contract, FIELD_GENERATED_BY),
        string(contract, FIELD_STABILITY_POLICY),
        parseCapabilities(contract.get(FIELD_CAPABILITIES)),
        parseEndpoints(contract.get(FIELD_ENDPOINTS)));
  }

  private static Map<String, Object> capabilityJson(PlatformApiCapabilityDescriptor descriptor) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put(FIELD_NAME, descriptor.name());
    json.put(FIELD_STABILITY, descriptor.stability().jsonValue());
    json.put(FIELD_SINCE_CONTRACT_VERSION, descriptor.sinceContractVersion());
    json.put(FIELD_DEPRECATION, deprecationJson(descriptor.deprecation()));
    json.put(FIELD_DESCRIPTION, descriptor.description());
    return json;
  }

  private static Map<String, Object> endpointJson(PlatformApiEndpointDescriptor descriptor) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(12);
    json.put(FIELD_ROUTE_FAMILY, descriptor.routeFamily());
    json.put(FIELD_METHOD, descriptor.method());
    json.put(FIELD_ROUTE_TEMPLATE, descriptor.routeTemplate());
    json.put(FIELD_ACTION_LABEL, descriptor.actionLabel());
    json.put(FIELD_REQUIRED_CAPABILITIES, descriptor.requiredCapabilities());
    json.put(FIELD_HOST_OPERATOR_BYPASS_ALLOWED, descriptor.hostOperatorBypassAllowed());
    json.put(FIELD_APP_PROCESS_PRINCIPALS_ALLOWED, descriptor.appProcessAllowed());
    json.put(FIELD_APP_BROWSER_PRINCIPALS_ALLOWED, descriptor.appBrowserAllowed());
    json.put(FIELD_STABILITY, descriptor.stability().jsonValue());
    json.put(FIELD_SINCE_CONTRACT_VERSION, descriptor.sinceContractVersion());
    json.put(FIELD_DEPRECATION, deprecationJson(descriptor.deprecation()));
    json.put(FIELD_DESCRIPTION, descriptor.description());
    return json;
  }

  private static Object deprecationJson(PlatformApiDeprecation deprecation) {
    if (deprecation == null) {
      return null;
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(FIELD_DEPRECATED_SINCE_CONTRACT_VERSION, deprecation.deprecatedSinceContractVersion());
    json.put(FIELD_REMOVAL_CONTRACT_VERSION, deprecation.removalContractVersion());
    json.put(FIELD_NOTE, deprecation.note());
    return json;
  }

  private static List<PlatformApiCapabilityDescriptor> parseCapabilities(Object value) {
    List<Object> items = asArray(value, FIELD_CAPABILITIES);
    List<PlatformApiCapabilityDescriptor> descriptors = new ArrayList<>(items.size());
    for (Object item : items) {
      Map<String, Object> json = asObject(item, "capability");
      descriptors.add(
          new PlatformApiCapabilityDescriptor(
              string(json, FIELD_NAME),
              PlatformApiStabilityLevel.parse(string(json, FIELD_STABILITY)),
              integer(json, FIELD_SINCE_CONTRACT_VERSION),
              parseDeprecation(json.get(FIELD_DEPRECATION)),
              string(json, FIELD_DESCRIPTION)));
    }
    return List.copyOf(descriptors);
  }

  private static List<PlatformApiEndpointDescriptor> parseEndpoints(Object value) {
    List<Object> items = asArray(value, FIELD_ENDPOINTS);
    List<PlatformApiEndpointDescriptor> descriptors = new ArrayList<>(items.size());
    for (Object item : items) {
      Map<String, Object> json = asObject(item, "endpoint");
      descriptors.add(
          new PlatformApiEndpointDescriptor(
              string(json, FIELD_ROUTE_FAMILY),
              string(json, FIELD_METHOD),
              string(json, FIELD_ROUTE_TEMPLATE),
              string(json, FIELD_ACTION_LABEL),
              requiredCapabilities(json.get(FIELD_REQUIRED_CAPABILITIES)),
              bool(json, FIELD_HOST_OPERATOR_BYPASS_ALLOWED),
              bool(json, FIELD_APP_PROCESS_PRINCIPALS_ALLOWED),
              bool(json, FIELD_APP_BROWSER_PRINCIPALS_ALLOWED),
              PlatformApiStabilityLevel.parse(string(json, FIELD_STABILITY)),
              integer(json, FIELD_SINCE_CONTRACT_VERSION),
              parseDeprecation(json.get(FIELD_DEPRECATION)),
              string(json, FIELD_DESCRIPTION)));
    }
    return List.copyOf(descriptors);
  }

  private static PlatformApiDeprecation parseDeprecation(Object value) {
    if (value == null) {
      return null;
    }
    Map<String, Object> json = asObject(value, FIELD_DEPRECATION);
    return new PlatformApiDeprecation(
        optionalInteger(json, FIELD_DEPRECATED_SINCE_CONTRACT_VERSION),
        optionalInteger(json, FIELD_REMOVAL_CONTRACT_VERSION),
        optionalString(json, FIELD_NOTE));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> asObject(Object value, String fieldName) {
    if (value instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    throw new IllegalArgumentException(fieldName + " must be a JSON object");
  }

  @SuppressWarnings("unchecked")
  private static List<Object> asArray(Object value, String fieldName) {
    if (value instanceof List<?> list) {
      return (List<Object>) list;
    }
    throw new IllegalArgumentException(fieldName + " must be a JSON array");
  }

  private static String string(Map<String, Object> json, String fieldName) {
    String value = optionalString(json, fieldName);
    if (value == null) {
      throw new IllegalArgumentException(fieldName + " must be a string");
    }
    return value;
  }

  private static String optionalString(Map<String, Object> json, String fieldName) {
    Object value = json.get(fieldName);
    if (value == null) {
      return null;
    }
    if (value instanceof String text) {
      return text;
    }
    throw new IllegalArgumentException(fieldName + " must be a string");
  }

  private static int integer(Map<String, Object> json, String fieldName) {
    Integer value = optionalInteger(json, fieldName);
    if (value == null) {
      throw new IllegalArgumentException(fieldName + " must be an integer");
    }
    return value;
  }

  private static Integer optionalInteger(Map<String, Object> json, String fieldName) {
    Object value = json.get(fieldName);
    return switch (value) {
      case null -> null;
      case Integer integer -> integer;
      case Long longValue when longValue >= Integer.MIN_VALUE && longValue <= Integer.MAX_VALUE ->
          longValue.intValue();
      default -> throw new IllegalArgumentException(fieldName + " must be an integer");
    };
  }

  private static boolean bool(Map<String, Object> json, String fieldName) {
    Object value = json.get(fieldName);
    if (value instanceof Boolean booleanValue) {
      return booleanValue;
    }
    throw new IllegalArgumentException(fieldName + " must be a boolean");
  }

  private static List<String> requiredCapabilities(Object value) {
    List<Object> items = asArray(value, FIELD_REQUIRED_CAPABILITIES);
    List<String> strings = new ArrayList<>(items.size());
    for (Object item : items) {
      if (item instanceof String text) {
        strings.add(text);
      } else {
        throw new IllegalArgumentException(
            FIELD_REQUIRED_CAPABILITIES + " must contain only strings");
      }
    }
    return List.copyOf(strings);
  }

  private static final class Parser {
    private final String text;
    private int index;

    private Parser(String text) {
      this.text = text;
    }

    private Object parse() {
      Object value = parseValue();
      skipWhitespace();
      if (index != text.length()) {
        throw error("unexpected trailing JSON content");
      }
      return value;
    }

    private Object parseValue() {
      skipWhitespace();
      if (index >= text.length()) {
        throw error("unexpected end of JSON");
      }
      return switch (text.charAt(index)) {
        case '{' -> parseObject();
        case '[' -> parseArray();
        case '"' -> parseString();
        case 't' -> parseLiteral("true", Boolean.TRUE);
        case 'f' -> parseLiteral("false", Boolean.FALSE);
        case 'n' -> parseLiteral("null", null);
        default -> parseNumber();
      };
    }

    private Map<String, Object> parseObject() {
      expect('{');
      LinkedHashMap<String, Object> object = new LinkedHashMap<>();
      skipWhitespace();
      if (consume('}')) {
        return object;
      }
      do {
        skipWhitespace();
        String key = parseString();
        skipWhitespace();
        expect(':');
        object.put(key, parseValue());
        skipWhitespace();
      } while (consume(','));
      expect('}');
      return object;
    }

    private List<Object> parseArray() {
      expect('[');
      List<Object> values = new ArrayList<>();
      skipWhitespace();
      if (consume(']')) {
        return values;
      }
      do {
        values.add(parseValue());
        skipWhitespace();
      } while (consume(','));
      expect(']');
      return values;
    }

    private String parseString() {
      expect('"');
      StringBuilder builder = new StringBuilder();
      while (index < text.length()) {
        char ch = text.charAt(index++);
        if (ch == '"') {
          return builder.toString();
        }
        if (ch == '\\') {
          builder.append(parseEscape());
        } else {
          if (ch < 0x20) {
            throw error("unescaped control character in JSON string");
          }
          builder.append(ch);
        }
      }
      throw error("unterminated JSON string");
    }

    private char parseEscape() {
      if (index >= text.length()) {
        throw error("unterminated JSON escape");
      }
      char escaped = text.charAt(index++);
      return switch (escaped) {
        case '"' -> '"';
        case '\\' -> '\\';
        case '/' -> '/';
        case 'b' -> '\b';
        case 'f' -> '\f';
        case 'n' -> '\n';
        case 'r' -> '\r';
        case 't' -> '\t';
        case 'u' -> parseUnicodeEscape();
        default -> throw error("invalid JSON escape");
      };
    }

    private char parseUnicodeEscape() {
      if (index + 4 > text.length()) {
        throw error("truncated JSON unicode escape");
      }
      int value = 0;
      for (int offset = 0; offset < 4; offset++) {
        int digit = Character.digit(text.charAt(index++), 16);
        if (digit < 0) {
          throw error("invalid JSON unicode escape");
        }
        value = (value << 4) + digit;
      }
      return (char) value;
    }

    private Object parseLiteral(String literal, Object value) {
      if (!text.startsWith(literal, index)) {
        throw error("invalid JSON literal");
      }
      index += literal.length();
      return value;
    }

    private Number parseNumber() {
      int start = index;
      if (text.charAt(index) == '-') {
        index++;
      }
      if (index >= text.length() || !Character.isDigit(text.charAt(index))) {
        throw error("invalid JSON value");
      }
      while (index < text.length() && Character.isDigit(text.charAt(index))) {
        index++;
      }
      if (index < text.length()
          && (text.charAt(index) == '.'
              || text.charAt(index) == 'e'
              || text.charAt(index) == 'E')) {
        throw error("Platform API contract numbers must be integers");
      }
      String value = text.substring(start, index);
      try {
        long parsed = Long.parseLong(value);
        if (parsed >= Integer.MIN_VALUE && parsed <= Integer.MAX_VALUE) {
          return (int) parsed;
        }
        return parsed;
      } catch (NumberFormatException exception) {
        throw new IllegalArgumentException(
            "invalid JSON integer at JSON offset " + index, exception);
      }
    }

    private void skipWhitespace() {
      while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
        index++;
      }
    }

    private boolean consume(char expected) {
      if (index < text.length() && text.charAt(index) == expected) {
        index++;
        return true;
      }
      return false;
    }

    private void expect(char expected) {
      if (!consume(expected)) {
        throw error("expected '" + expected + "'");
      }
    }

    private IllegalArgumentException error(String message) {
      return new IllegalArgumentException(message + " at JSON offset " + index);
    }
  }
}
