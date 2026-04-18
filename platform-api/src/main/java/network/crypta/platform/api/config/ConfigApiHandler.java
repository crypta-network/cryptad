package network.crypta.platform.api.config;

import java.net.MalformedURLException;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.keys.FreenetURI;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.json.PlatformApiFieldSetJson;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.support.Fields;
import network.crypta.support.TimeUtil;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.URLEncoder;

/**
 * Configuration endpoint family for Platform API v1.
 *
 * <p>The handler keeps reads and writes deliberately small. Configuration export defaults to the
 * current effective values, while mutation support is limited to dotted-name override application
 * plus explicit persistence through the existing runtime config port.
 */
public final class ConfigApiHandler {
  /** Conservative default export scope used when callers omit the {@code sections} query. */
  private static final EnumSet<ConfigSection> DEFAULT_SECTIONS = EnumSet.of(ConfigSection.CURRENT);

  private static final EnumSet<ConfigSection> VERIFICATION_SECTIONS =
      EnumSet.of(ConfigSection.CURRENT, ConfigSection.DATA_TYPES);

  private static final String FIELD_OPERATION = "operation";
  private static final String FIELD_OVERRIDE_COUNT = "overrideCount";
  private static final String TYPE_BOOLEAN = "boolean";
  private static final String TYPE_NUMBER = "number";
  private static final String TYPE_STRING_ARRAY = "stringArray";
  private static final String UPDATE_URI_OPTION = "node.updater.URI";
  private static final String REVOCATION_URI_OPTION = "node.updater.revocationURI";
  private static final String LEGACY_UPDATE_URI_DOC_NAME = "jar";
  private static final String REVOCATION_URI_DOC_NAME = "revoked";
  private static final String UPDATE_URI_DOC_NAME = "info";

  /** Detached runtime port that exports configuration snapshots for the API layer. */
  private final ConfigPort configPort;

  /**
   * Creates a configuration API handler backed by the supplied runtime port.
   *
   * @param configPort detached runtime config port
   */
  public ConfigApiHandler(ConfigPort configPort) {
    this.configPort = Objects.requireNonNull(configPort, "configPort");
  }

  /**
   * Exports the requested configuration sections.
   *
   * @param queryParameters decoded query parameters for the current request
   * @return JSON-compatible configuration snapshot keyed by section name
   */
  public Map<String, Object> exportConfig(Map<String, List<String>> queryParameters) {
    Set<ConfigSection> requestedSections =
        PlatformApiParameters.readCommaSeparatedEnums(
            queryParameters, "sections", ConfigSection.class, DEFAULT_SECTIONS);
    ConfigSnapshot snapshot = configPort.export(requestedSections);

    LinkedHashMap<String, Object> sections =
        LinkedHashMap.newLinkedHashMap(snapshot.sections().size());
    snapshot
        .sections()
        .forEach(
            (section, fieldSet) ->
                sections.put(section.name(), PlatformApiFieldSetJson.toJson(fieldSet)));
    return sections;
  }

  /**
   * Applies one or more dotted-name configuration overrides.
   *
   * <p>The Platform API keeps this mutation deliberately narrow. Every supplied parameter name is
   * treated as one dotted config key and must carry exactly one value. The runtime port preserves
   * the legacy behavior for unknown or invalid options, while this handler enforces only the
   * transport-neutral shape of the request.
   *
   * @param queryParameters decoded request parameters containing dotted config overrides
   * @return JSON-compatible mutation summary
   */
  public Map<String, Object> applyOverrides(Map<String, List<String>> queryParameters) {
    Objects.requireNonNull(queryParameters, "queryParameters");
    Map<String, String> overrides = toSingleValueOverrides(queryParameters);
    if (overrides.isEmpty()) {
      throw invalidQuery("At least one config override parameter is required.");
    }

    ConfigSnapshot beforeSnapshot = configPort.export(VERIFICATION_SECTIONS);
    configPort.applyOverrides(overrides);
    ConfigSnapshot afterSnapshot = configPort.export(VERIFICATION_SECTIONS);

    Map<String, String> rejectedOverrides =
        collectRejectedOverrides(beforeSnapshot, overrides, afterSnapshot);
    if (!rejectedOverrides.isEmpty()) {
      revertAcceptedOverrides(beforeSnapshot, afterSnapshot, overrides, rejectedOverrides.keySet());
      throw new PlatformApiException(
          400,
          "config_override_rejected",
          "Rejected config overrides: " + String.join(", ", rejectedOverrides.keySet()));
    }

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
    response.put(FIELD_OPERATION, "apply_overrides");
    response.put(FIELD_OVERRIDE_COUNT, overrides.size());
    return response;
  }

  /**
   * Persists the current configuration state through the runtime's existing storage path.
   *
   * @return JSON-compatible mutation summary
   */
  public Map<String, Object> persist() {
    configPort.persist();

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(1);
    response.put(FIELD_OPERATION, "persist");
    return response;
  }

  private static Map<String, String> toSingleValueOverrides(
      Map<String, List<String>> queryParameters) {
    LinkedHashMap<String, String> overrides =
        LinkedHashMap.newLinkedHashMap(queryParameters.size());
    for (Map.Entry<String, List<String>> entry : queryParameters.entrySet()) {
      String name = entry.getKey();
      if (name == null || name.isBlank()) {
        throw invalidQuery("Config override parameter names must not be blank.");
      }

      List<String> values = entry.getValue();
      if (values == null || values.isEmpty()) {
        throw invalidQuery("Config override parameter '" + name + "' must have one value.");
      }
      if (values.size() > 1) {
        throw invalidQuery("Config override parameter '" + name + "' must not be repeated.");
      }
      overrides.put(name, values.getFirst());
    }
    return overrides;
  }

  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }

  private void revertAcceptedOverrides(
      ConfigSnapshot beforeSnapshot,
      ConfigSnapshot afterSnapshot,
      Map<String, String> requestedOverrides,
      Set<String> rejectedOverrideNames) {
    LinkedHashMap<String, String> revertOverrides =
        LinkedHashMap.newLinkedHashMap(requestedOverrides.size());
    for (Map.Entry<String, String> entry : requestedOverrides.entrySet()) {
      String name = entry.getKey();
      if (rejectedOverrideNames.contains(name)) {
        continue;
      }
      String beforeValue = readCurrentValue(beforeSnapshot, name);
      String afterValue = readCurrentValue(afterSnapshot, name);
      if (beforeValue != null && !Objects.equals(beforeValue, afterValue)) {
        revertOverrides.put(name, beforeValue);
      }
    }
    if (!revertOverrides.isEmpty()) {
      configPort.applyOverrides(revertOverrides);
    }
  }

  private static Map<String, String> collectRejectedOverrides(
      ConfigSnapshot beforeSnapshot,
      Map<String, String> requestedOverrides,
      ConfigSnapshot afterSnapshot) {
    LinkedHashMap<String, String> rejectedOverrides =
        LinkedHashMap.newLinkedHashMap(requestedOverrides.size());
    for (Map.Entry<String, String> entry : requestedOverrides.entrySet()) {
      String beforeValue = readCurrentValue(beforeSnapshot, entry.getKey());
      String resultingValue = readCurrentValue(afterSnapshot, entry.getKey());
      String dataType = readDataType(afterSnapshot, entry.getKey());
      if (!valuesSemanticallyMatch(
          entry.getKey(), beforeValue, entry.getValue(), resultingValue, dataType)) {
        rejectedOverrides.put(entry.getKey(), entry.getValue());
      }
    }
    return rejectedOverrides;
  }

  private static String readDataType(ConfigSnapshot snapshot, String dottedName) {
    Objects.requireNonNull(snapshot, "snapshot");
    ConfigFieldSet dataTypes = snapshot.sections().get(ConfigSection.DATA_TYPES);
    if (dataTypes == null || dottedName == null || dottedName.isBlank()) {
      return null;
    }
    return readFieldValue(dataTypes, dottedName);
  }

  private static boolean valuesSemanticallyMatch(
      String dottedName,
      String beforeValue,
      String requestedValue,
      String resultingValue,
      String dataType) {
    if (Objects.equals(requestedValue, resultingValue)) {
      return true;
    }
    if (requestedValue == null || resultingValue == null || dataType == null) {
      return false;
    }
    try {
      return switch (dataType) {
        case TYPE_BOOLEAN -> parseBooleanValue(requestedValue) == parseBooleanValue(resultingValue);
        case TYPE_NUMBER -> numericValuesSemanticallyMatch(requestedValue, resultingValue);
        case TYPE_STRING_ARRAY ->
            stringArrayValuesSemanticallyMatch(requestedValue, resultingValue);
        default ->
            canonicalizedStringValuesSemanticallyMatch(dottedName, requestedValue, resultingValue)
                || (beforeValue != null && !Objects.equals(beforeValue, resultingValue));
      };
    } catch (RuntimeException _) {
      return false;
    }
  }

  private static boolean canonicalizedStringValuesSemanticallyMatch(
      String dottedName, String requestedValue, String resultingValue) {
    String canonicalRequested = canonicalizeKnownStringValue(dottedName, requestedValue);
    return canonicalRequested != null && Objects.equals(canonicalRequested, resultingValue);
  }

  private static String canonicalizeKnownStringValue(String dottedName, String requestedValue) {
    if (UPDATE_URI_OPTION.equals(dottedName)) {
      return canonicalizeUpdateUriValue(requestedValue);
    }
    if (REVOCATION_URI_OPTION.equals(dottedName)) {
      return canonicalizeRevocationUriValue(requestedValue);
    }
    return null;
  }

  private static String canonicalizeUpdateUriValue(String requestedValue) {
    try {
      FreenetURI parsed = new FreenetURI(requestedValue.trim());
      if (parsed.isUSK()
          && !parsed.hasMetaStrings()
          && (UPDATE_URI_DOC_NAME.equals(parsed.getDocName())
              || LEGACY_UPDATE_URI_DOC_NAME.equals(parsed.getDocName()))) {
        return extractPublicKeyMaterial(parsed);
      }
    } catch (MalformedURLException | RuntimeException _) {
      // Fall through to "unknown normalization".
    }
    return null;
  }

  private static String canonicalizeRevocationUriValue(String requestedValue) {
    try {
      FreenetURI parsed = new FreenetURI(requestedValue.trim());
      if (parsed.isSSK()
          && !parsed.hasMetaStrings()
          && REVOCATION_URI_DOC_NAME.equals(parsed.getDocName())) {
        return extractPublicKeyMaterial(parsed);
      }
    } catch (MalformedURLException | RuntimeException _) {
      // Fall through to "unknown normalization".
    }
    return null;
  }

  private static String extractPublicKeyMaterial(FreenetURI uri) {
    String uriString = uri.toString(false, false);
    if (uriString == null) {
      return "";
    }
    int prefixEnd = uriString.indexOf('@');
    if (prefixEnd < 0 || prefixEnd + 1 >= uriString.length()) {
      return uriString;
    }
    int pathStart = uriString.indexOf('/', prefixEnd + 1);
    if (pathStart < 0) {
      return uriString.substring(prefixEnd + 1);
    }
    return uriString.substring(prefixEnd + 1, pathStart);
  }

  private static boolean parseBooleanValue(String value) {
    return Fields.stringToBool(value);
  }

  private static long parseNumericValue(String value) {
    return Fields.parseLong(trimPerSecondSuffix(value));
  }

  private static boolean numericValuesSemanticallyMatch(
      String requestedValue, String resultingValue) {
    long resultingNumeric = parseNumericValue(resultingValue);
    return matchesAnyRequestedNumericInterpretation(requestedValue, resultingNumeric);
  }

  private static boolean stringArrayValuesSemanticallyMatch(
      String requestedValue, String resultingValue) {
    try {
      return Objects.equals(canonicalizeStringArrayValue(requestedValue), resultingValue);
    } catch (URLEncodedFormatException _) {
      return false;
    }
  }

  private static String canonicalizeStringArrayValue(String value)
      throws URLEncodedFormatException {
    if (value.isEmpty()) {
      return "";
    }

    List<String> tokens = splitStringArrayTokens(value);
    StringBuilder canonical = new StringBuilder(value.length());
    for (int i = 0; i < tokens.size(); i++) {
      if (i > 0) {
        canonical.append(';');
      }
      canonical.append(canonicalizeStringArrayToken(tokens.get(i)));
    }
    return canonical.toString();
  }

  private static List<String> splitStringArrayTokens(String value) {
    java.util.ArrayList<String> tokens = new java.util.ArrayList<>();
    int segmentStart = 0;
    while (segmentStart <= value.length()) {
      int delimiter = value.indexOf(';', segmentStart);
      if (delimiter < 0) {
        tokens.add(value.substring(segmentStart));
        return tokens;
      }
      tokens.add(value.substring(segmentStart, delimiter));
      segmentStart = delimiter + 1;
    }
    return tokens;
  }

  private static String canonicalizeStringArrayToken(String token)
      throws URLEncodedFormatException {
    if (":".equals(token)) {
      return ":";
    }
    String decoded = URLDecoder.decode(token, true);
    return decoded.isEmpty() ? ":" : URLEncoder.encode(decoded, false);
  }

  private static boolean matchesAnyRequestedNumericInterpretation(
      String requestedValue, long resultingNumeric) {
    try {
      if (parseNumericValue(requestedValue) == resultingNumeric) {
        return true;
      }
    } catch (RuntimeException _) {
      // Try duration semantics next.
    }
    return TimeUtil.toMillis(requestedValue) == resultingNumeric;
  }

  private static String trimPerSecondSuffix(String value) {
    String trimmed = value.trim();
    String lower = trimmed.toLowerCase(java.util.Locale.ROOT);
    for (String suffix : new String[] {"/s", "/sec", "/second", "ps"}) {
      if (lower.endsWith(suffix)) {
        return trimmed.substring(0, trimmed.length() - suffix.length());
      }
    }
    return trimmed;
  }

  private static String readCurrentValue(ConfigSnapshot snapshot, String dottedName) {
    Objects.requireNonNull(snapshot, "snapshot");
    ConfigFieldSet current = snapshot.sections().get(ConfigSection.CURRENT);
    if (current == null || dottedName == null || dottedName.isBlank()) {
      return null;
    }
    return readFieldValue(current, dottedName);
  }

  private static String readFieldValue(ConfigFieldSet fieldSet, String dottedName) {
    ConfigFieldSet current = fieldSet;
    int segmentStart = 0;
    while (segmentStart < dottedName.length()) {
      int nextDot = dottedName.indexOf('.', segmentStart);
      int segmentEnd = nextDot >= 0 ? nextDot : dottedName.length();
      String segment = dottedName.substring(segmentStart, segmentEnd);
      if (current.directSubsets().containsKey(segment)) {
        current = current.directSubsets().get(segment);
        segmentStart = segmentEnd + 1;
        continue;
      }

      String remainingPath = dottedName.substring(segmentStart);
      if (current.directValues().containsKey(remainingPath)) {
        return current.directValues().get(remainingPath);
      }
      return null;
    }
    return null;
  }
}
