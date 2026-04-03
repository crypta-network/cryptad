package network.crypta.platform.api.config;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.json.PlatformApiFieldSetJson;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;

/**
 * Read-only configuration endpoint family for Platform API v1.
 *
 * <p>The initial API keeps configuration export conservative: when callers omit the {@code
 * sections} query parameter, the handler exports only {@link ConfigSection#CURRENT}, which exposes
 * effective values without broadening the surface to descriptions, metadata, or write-oriented
 * flows.
 */
public final class ConfigApiHandler {
  /** Conservative default export scope used when callers omit the {@code sections} query. */
  private static final EnumSet<ConfigSection> DEFAULT_SECTIONS = EnumSet.of(ConfigSection.CURRENT);

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
}
