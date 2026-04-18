package network.crypta.platform.api.config;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ConfigApiHandlerTest {
  private static final String CANONICAL_UPDATE_URI =
      "uQnFwn0aEFSAZihnSDduEHUd3GUmGg68ATn5R95MKJo,"
          + "mcNiZqosfZ1F~PkZY8v1TuDKsY6noda-hGRXvu7uUFc,AQACAAE";
  private static final String FULL_UPDATE_URI = "USK@" + CANONICAL_UPDATE_URI + "/info/1234";

  @Test
  void applyOverrides_whenOverridesProvided_expectDelegatesAndReturnsSummary() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    configPort.currentValues.put("updater.enabled", "true");
    configPort.currentValues.put("updater.autoupdate", "false");
    configPort.dataTypes.put("updater.enabled", "boolean");
    configPort.dataTypes.put("updater.autoupdate", "boolean");
    ConfigApiHandler handler = new ConfigApiHandler(configPort);

    Map<String, Object> response =
        handler.applyOverrides(
            orderedParameters(
                Map.entry("node.updater.enabled", List.of("false")),
                Map.entry("node.updater.autoupdate", List.of("true"))));

    assertEquals(
        Map.of("node.updater.enabled", "false", "node.updater.autoupdate", "true"),
        configPort.lastOverrides);
    assertEquals("apply_overrides", response.get("operation"));
    assertEquals(2, response.get("overrideCount"));
  }

  @Test
  void applyOverrides_whenCanonicalBooleanProvided_expectAccepted() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    configPort.currentValues.put("updater.enabled", "false");
    configPort.dataTypes.put("updater.enabled", "boolean");
    ConfigApiHandler handler = new ConfigApiHandler(configPort);

    Map<String, Object> response =
        handler.applyOverrides(
            orderedParameters(Map.entry("node.updater.enabled", List.of("YES"))));

    assertEquals("true", configPort.currentValues.get("updater.enabled"));
    assertEquals("apply_overrides", response.get("operation"));
    assertEquals(1, response.get("overrideCount"));
  }

  @Test
  void applyOverrides_whenCanonicalNumberProvided_expectAccepted() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    configPort.currentValues.put("inputBandwidthLimit", "15360");
    configPort.dataTypes.put("inputBandwidthLimit", "number");
    ConfigApiHandler handler = new ConfigApiHandler(configPort);

    Map<String, Object> response =
        handler.applyOverrides(
            orderedParameters(Map.entry("node.inputBandwidthLimit", List.of("15K"))));

    assertEquals("15360", configPort.currentValues.get("inputBandwidthLimit"));
    assertEquals("apply_overrides", response.get("operation"));
    assertEquals(1, response.get("overrideCount"));
  }

  @Test
  void applyOverrides_whenStringArrayProvidedAsDecodedValue_expectAccepted() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    configPort.currentValues.put("downloadAllowedDirs", "");
    configPort.dataTypes.put("downloadAllowedDirs", "stringArray");
    ConfigApiHandler handler = new ConfigApiHandler(configPort);

    Map<String, Object> response =
        handler.applyOverrides(
            orderedParameters(
                Map.entry("node.downloadAllowedDirs", List.of("/home/alice/My Files"))));

    assertEquals(
        network.crypta.support.URLEncoder.encode("/home/alice/My Files", false),
        configPort.currentValues.get("downloadAllowedDirs"));
    assertEquals("apply_overrides", response.get("operation"));
    assertEquals(1, response.get("overrideCount"));
  }

  @Test
  void applyOverrides_whenStringOverrideIsNormalized_expectAccepted() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    configPort.currentValues.put("updater.URI", "USK@old-key");
    configPort.dataTypes.put("updater.URI", "string");
    ConfigApiHandler handler = new ConfigApiHandler(configPort);

    Map<String, Object> response =
        handler.applyOverrides(
            orderedParameters(Map.entry("node.updater.URI", List.of(FULL_UPDATE_URI))));

    assertEquals(CANONICAL_UPDATE_URI, configPort.currentValues.get("updater.URI"));
    assertEquals("apply_overrides", response.get("operation"));
    assertEquals(1, response.get("overrideCount"));
  }

  @Test
  void applyOverrides_whenNormalizedStringOverrideIsIdempotent_expectAccepted() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    configPort.currentValues.put("updater.URI", CANONICAL_UPDATE_URI);
    configPort.dataTypes.put("updater.URI", "string");
    ConfigApiHandler handler = new ConfigApiHandler(configPort);

    Map<String, Object> response =
        handler.applyOverrides(
            orderedParameters(Map.entry("node.updater.URI", List.of(FULL_UPDATE_URI))));

    assertEquals(CANONICAL_UPDATE_URI, configPort.currentValues.get("updater.URI"));
    assertEquals("apply_overrides", response.get("operation"));
    assertEquals(1, response.get("overrideCount"));
  }

  @Test
  void applyOverrides_whenOverrideRejected_expectConflictAndRollbackAcceptedChanges() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    configPort.currentValues.put("updater.enabled", "true");
    configPort.currentValues.put("updater.autoupdate", "false");
    configPort.dataTypes.put("updater.enabled", "boolean");
    configPort.dataTypes.put("updater.autoupdate", "boolean");
    configPort.rejectNames.add("node.updater.autoupdate");
    ConfigApiHandler handler = new ConfigApiHandler(configPort);
    Map<String, List<String>> queryParameters =
        orderedParameters(
            Map.entry("node.updater.enabled", List.of("false")),
            Map.entry("node.updater.autoupdate", List.of("true")));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.applyOverrides(queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("config_override_rejected", exception.errorCode());
    assertEquals("true", configPort.currentValues.get("updater.enabled"));
    assertEquals("false", configPort.currentValues.get("updater.autoupdate"));
    assertEquals(
        List.of(
            Map.of("node.updater.enabled", "false", "node.updater.autoupdate", "true"),
            Map.of("node.updater.enabled", "true")),
        configPort.applyCalls);
  }

  @Test
  void applyOverrides_whenTypedOverrideMalformed_expectRejectedWithoutInternalError() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    configPort.currentValues.put("updater.enabled", "true");
    configPort.dataTypes.put("updater.enabled", "boolean");
    ConfigApiHandler handler = new ConfigApiHandler(configPort);
    Map<String, List<String>> queryParameters =
        orderedParameters(Map.entry("node.updater.enabled", List.of("maybe")));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.applyOverrides(queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("config_override_rejected", exception.errorCode());
    assertEquals("true", configPort.currentValues.get("updater.enabled"));
  }

  @Test
  void applyOverrides_whenNoParametersProvided_expectInvalidQueryException() {
    ConfigApiHandler handler = new ConfigApiHandler(new RecordingConfigPort());
    Map<String, List<String>> queryParameters = Map.of();

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.applyOverrides(queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
  }

  @Test
  void applyOverrides_whenParameterRepeated_expectInvalidQueryException() {
    ConfigApiHandler handler = new ConfigApiHandler(new RecordingConfigPort());
    Map<String, List<String>> queryParameters =
        Map.of("node.updater.enabled", List.of("true", "false"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.applyOverrides(queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
  }

  @Test
  void persist_whenCalled_expectDelegatesAndReturnsSummary() {
    RecordingConfigPort configPort = new RecordingConfigPort();
    ConfigApiHandler handler = new ConfigApiHandler(configPort);

    Map<String, Object> response = handler.persist();

    assertEquals(1, configPort.persistCalls);
    assertEquals("persist", response.get("operation"));
  }

  @SafeVarargs
  private static Map<String, List<String>> orderedParameters(
      Map.Entry<String, List<String>>... entries) {
    LinkedHashMap<String, List<String>> parameters = LinkedHashMap.newLinkedHashMap(entries.length);
    for (Map.Entry<String, List<String>> entry : entries) {
      parameters.put(entry.getKey(), entry.getValue());
    }
    return parameters;
  }

  private static final class RecordingConfigPort implements ConfigPort {
    private Map<String, String> lastOverrides = Map.of();
    private final LinkedHashMap<String, String> currentValues = LinkedHashMap.newLinkedHashMap(4);
    private final LinkedHashMap<String, String> dataTypes = LinkedHashMap.newLinkedHashMap(4);
    private final java.util.Set<String> rejectNames = new java.util.LinkedHashSet<>();
    private final java.util.List<Map<String, String>> applyCalls = new java.util.ArrayList<>();
    private int persistCalls;

    @Override
    public ConfigSnapshot export(Set<ConfigSection> sections) {
      LinkedHashMap<ConfigSection, ConfigFieldSet> exported =
          LinkedHashMap.newLinkedHashMap(sections.size());
      if (sections.contains(ConfigSection.CURRENT)) {
        exported.put(
            ConfigSection.CURRENT,
            new ConfigFieldSet(
                Map.of(),
                Map.of("node", new ConfigFieldSet(new LinkedHashMap<>(currentValues), Map.of()))));
      }
      if (sections.contains(ConfigSection.DATA_TYPES)) {
        exported.put(
            ConfigSection.DATA_TYPES,
            new ConfigFieldSet(
                Map.of(),
                Map.of("node", new ConfigFieldSet(new LinkedHashMap<>(dataTypes), Map.of()))));
      }
      return new ConfigSnapshot(exported);
    }

    @Override
    public void applyOverrides(Map<String, String> overrides) {
      applyCalls.add(Map.copyOf(overrides));
      lastOverrides = Map.copyOf(overrides);
      overrides.forEach(
          (name, value) -> {
            if (!rejectNames.contains(name)) {
              String nestedName =
                  name.startsWith("node.") ? name.substring("node.".length()) : name;
              try {
                currentValues.put(nestedName, canonicalizeValue(nestedName, value));
              } catch (RuntimeException _) {
                // Mirror LegacyConfigPort: invalid values are ignored instead of bubbling out.
              }
            }
          });
    }

    @Override
    public void persist() {
      persistCalls++;
    }

    private String canonicalizeValue(String nestedName, String value) {
      String dataType = dataTypes.get(nestedName);
      if ("updater.URI".equals(nestedName)) {
        return CANONICAL_UPDATE_URI;
      }
      if ("boolean".equals(dataType)) {
        return network.crypta.support.Fields.boolToString(
            network.crypta.support.Fields.stringToBool(value));
      }
      if ("number".equals(dataType)) {
        return Long.toString(network.crypta.support.Fields.parseLong(value));
      }
      if ("stringArray".equals(dataType)) {
        return canonicalizeStringArrayValue(value);
      }
      return value;
    }

    private String canonicalizeStringArrayValue(String value) {
      if (value.isEmpty()) {
        return "";
      }

      java.util.List<String> tokens = splitStringArrayTokens(value);
      StringBuilder canonical = new StringBuilder(value.length());
      for (int i = 0; i < tokens.size(); i++) {
        if (i > 0) {
          canonical.append(';');
        }
        canonical.append(canonicalizeStringArrayToken(tokens.get(i)));
      }
      return canonical.toString();
    }

    private java.util.List<String> splitStringArrayTokens(String value) {
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

    private String canonicalizeStringArrayToken(String token) {
      if (":".equals(token)) {
        return ":";
      }
      try {
        String decoded = network.crypta.support.URLDecoder.decode(token, true);
        return decoded.isEmpty() ? ":" : network.crypta.support.URLEncoder.encode(decoded, false);
      } catch (network.crypta.support.URLEncodedFormatException e) {
        throw new IllegalArgumentException(e);
      }
    }
  }
}
