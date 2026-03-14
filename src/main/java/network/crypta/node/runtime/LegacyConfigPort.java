package network.crypta.node.runtime;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapts the daemon's legacy configuration subsystem to the runtime SPI's {@link ConfigPort}.
 *
 * <p>This package-private bridge keeps knowledge of {@link PersistentConfig}, {@link SubConfig},
 * {@link Option}, and {@link SimpleFieldSet} inside the daemon root module while exposing only
 * SPI-local DTOs to higher layers. FCP handlers and other management-facing code can therefore use
 * the runtime aggregate without traversing daemon configuration internals directly.
 *
 * <p>The adapter preserves the current daemon behavior instead of redesigning it. Export requests
 * delegate to the existing field-set export logic and are then mapped into immutable SPI values.
 * Override application still ignores unknown dotted names, skips unchanged values, logs invalid
 * values, and continues processing subsequent options. Persistence remains delegated to {@link
 * NodeClientCore#storeConfig()}.
 */
final class LegacyConfigPort implements ConfigPort {
  /** Logger for legacy configuration export and override application failures. */
  private static final Logger LOG = LoggerFactory.getLogger(LegacyConfigPort.class);

  /** Owning daemon node that still exposes the legacy configuration subsystem. */
  private final Node node;

  /** Client-core entry point that persists the daemon configuration to durable storage. */
  private final NodeClientCore core;

  /**
   * Creates a legacy-backed config port for the current daemon runtime.
   *
   * @param node daemon node that exposes the legacy configuration registry
   * @param core client-core entry point used for persistence
   */
  LegacyConfigPort(Node node, NodeClientCore core) {
    this.node = Objects.requireNonNull(node);
    this.core = Objects.requireNonNull(core);
  }

  @Override
  public ConfigSnapshot export(Set<ConfigSection> sections) {
    Objects.requireNonNull(sections, "sections");
    if (sections.isEmpty()) {
      return ConfigSnapshot.empty();
    }

    PersistentConfig config = node.getConfig();
    EnumMap<ConfigSection, ConfigFieldSet> exported = new EnumMap<>(ConfigSection.class);
    for (ConfigSection section : sections) {
      ConfigFieldSet fieldSet =
          toConfigFieldSet(config.exportFieldSet(requestType(section), includeDefaults(section)));
      if (!fieldSet.isEmpty()) {
        exported.put(section, fieldSet);
      }
    }
    return new ConfigSnapshot(exported);
  }

  @Override
  public void applyOverrides(Map<String, String> overrides) {
    Objects.requireNonNull(overrides, "overrides");
    if (overrides.isEmpty()) {
      return;
    }

    Config config = node.getConfig();
    for (SubConfig subConfig : config.getConfigs()) {
      String prefix = subConfig.getPrefix();
      for (Option<?> option : subConfig.getOptions()) {
        updateOption(prefix, option, overrides);
      }
    }
  }

  @Override
  public void persist() {
    core.storeConfig();
  }

  /**
   * Maps an SPI section request to the legacy daemon export type.
   *
   * @param section logical section requested through the runtime SPI
   * @return matching legacy request type for the daemon config exporter
   */
  private static Config.RequestType requestType(ConfigSection section) {
    return switch (section) {
      case CURRENT -> Config.RequestType.CURRENT_SETTINGS;
      case DEFAULTS -> Config.RequestType.DEFAULT_SETTINGS;
      case SORT_ORDER -> Config.RequestType.SORT_ORDER;
      case EXPERT_FLAG -> Config.RequestType.EXPERT_FLAG;
      case FORCE_WRITE_FLAG -> Config.RequestType.FORCE_WRITE_FLAG;
      case SHORT_DESCRIPTION -> Config.RequestType.SHORT_DESCRIPTION;
      case LONG_DESCRIPTION -> Config.RequestType.LONG_DESCRIPTION;
      case DATA_TYPES -> Config.RequestType.DATA_TYPE;
    };
  }

  /**
   * Returns whether the legacy exporter should include default values for the requested section.
   *
   * @param section logical section requested through the runtime SPI
   * @return {@code true} when the legacy exporter should merge defaults into the response
   */
  private static boolean includeDefaults(ConfigSection section) {
    return section == ConfigSection.CURRENT;
  }

  /**
   * Applies one override value to a legacy option when the dotted name matches.
   *
   * @param prefix legacy sub-config prefix used to build the dotted option name
   * @param option legacy option candidate that may receive the override
   * @param overrides textual overrides keyed by dotted option name
   */
  private void updateOption(String prefix, Option<?> option, Map<String, String> overrides) {
    String configName = option.getName();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Setting {}.{}", prefix, configName);
    }
    String value = overrides.get(prefix + '.' + configName);
    if (value == null || option.getValueString().equals(value)) {
      return;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Setting {}.{} to {}", prefix, configName, value);
    }
    try {
      option.setValue(value);
    } catch (Exception e) {
      // Bad values silently fail from an FCP perspective, but the FCP client can tell if a change
      // took by comparing ConfigData messages before and after.
      LOG.error("Caught {}", e, e);
    }
  }

  /**
   * Recursively maps a legacy {@link SimpleFieldSet} tree into an SPI-local field-set tree.
   *
   * @param fieldSet legacy field-set node to convert
   * @return immutable SPI field-set node with empty descendants removed
   */
  private static ConfigFieldSet toConfigFieldSet(SimpleFieldSet fieldSet) {
    if (fieldSet.isEmpty()) {
      return ConfigFieldSet.empty();
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(fieldSet.directKeyValues());
    LinkedHashMap<String, ConfigFieldSet> directSubsets = new LinkedHashMap<>();
    for (Map.Entry<String, SimpleFieldSet> entry : fieldSet.directSubsets().entrySet()) {
      ConfigFieldSet subset = toConfigFieldSet(entry.getValue());
      if (!subset.isEmpty()) {
        directSubsets.put(entry.getKey(), subset);
      }
    }
    return new ConfigFieldSet(directValues, directSubsets);
  }
}
