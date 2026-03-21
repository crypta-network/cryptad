package network.crypta.config;

import java.util.LinkedHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Central registry and utility for node configuration.
 *
 * <p>This class manages {@link SubConfig} instances keyed by their unique {@code prefix}. It
 * provides registration, lookup, and basic validation helpers. The registry preserves insertion
 * order and is safe for concurrent access via {@code synchronized} blocks on {@code this}.
 *
 * <p>Persistence of settings is environment-specific; see {@link #store()} for details.
 */
public class Config {
  private static final Logger LOG = LoggerFactory.getLogger(Config.class);

  /**
   * Kinds of metadata or values that may be requested for a configuration option. The constants are
   * primarily used by user-facing configuration tools to query attributes of an option.
   */
  public enum RequestType {
    /** Request the current, effective value. */
    CURRENT_SETTINGS,
    /** Request the default value (prior to user overrides). */
    DEFAULT_SETTINGS,
    /** Request the preferred sort order among sibling options. */
    SORT_ORDER,
    /** Request whether the option is marked as expert-only. */
    EXPERT_FLAG,
    /** Request whether writes for this option require explicit user confirmation. */
    FORCE_WRITE_FLAG,
    /** Request the short, human-readable description. */
    SHORT_DESCRIPTION,
    /** Request the long, human-readable description. */
    LONG_DESCRIPTION,
    /** Request the data type (see {@link Option.DataType}). */
    DATA_TYPE
  }

  /**
   * Registry of sub-configurations keyed by prefix. Insertion order is preserved. Access is guarded
   * by synchronization on {@code this}.
   */
  protected final LinkedHashMap<String, SubConfig> configsByPrefix;

  /** Creates an empty configuration registry. No {@link SubConfig} instances are registered. */
  public Config() {
    configsByPrefix = new LinkedHashMap<>();
  }

  /**
   * Registers a {@link SubConfig} with this registry.
   *
   * <p>This method is thread-safe. Registration keys on {@link SubConfig#prefix}; attempting to
   * register another sub-config with the same prefix fails.
   *
   * @param sc the sub-configuration to add
   * @throws IllegalArgumentException if a sub-config with the same {@code prefix} is already
   *     registered
   */
  public void register(SubConfig sc) {
    synchronized (this) {
      if (configsByPrefix.containsKey(sc.prefix))
        throw new IllegalArgumentException("Already registered " + sc.prefix + ": " + sc);
      configsByPrefix.put(sc.prefix, sc);
    }
  }

  /**
   * Persists configuration to durable storage.
   *
   * <p>No-op in this implementation. Persistence is handled by surrounding infrastructure or
   * higher-level components.
   */
  public void store() {
    // Intentionally no-op: persistence is delegated to higher-level components.
    // This registry does not own an on-disk format in this context.
  }

  /**
   * Verifies that all registered sub-configs reported completion of their initialization.
   *
   * <p>Logs an error for each {@link SubConfig} whose {@link SubConfig#hasFinishedInitialization()}
   * returns {@code false}. This method does not throw; it is intended for diagnostic purposes late
   * in startup.
   */
  public void finishedInit() {
    SubConfig[] configs;
    synchronized (this) {
      // Note: Consider caching the array if this method is hot; profile before adding state.
      configs = configsByPrefix.values().toArray(new SubConfig[0]);
    }
    for (SubConfig config : configs) {
      if (!config.hasFinishedInitialization())
        LOG.error("Not finished initialization: {}", config.prefix);
    }
  }

  /**
   * Callback invoked when an {@link Option} is registered on a {@link SubConfig}.
   *
   * <p>No-op by default. Hooks may use this to observe registrations for metrics or validation.
   *
   * @param config the owning sub-config
   * @param o the option being registered
   */
  public void onRegister(SubConfig config, Option<?> o) {
    // Extension hook: override in subclasses to observe or validate registrations.
    // Default is no-op to avoid side effects during option wiring.
  }

  /**
   * Returns a snapshot of all registered sub-configs in insertion order.
   *
   * <p>The returned array is a copy and is not backed by the internal map, so callers may iterate
   * without synchronization.
   *
   * @return array of registered {@link SubConfig} in insertion order; never {@code null}
   */
  public synchronized SubConfig[] getConfigs() {
    return configsByPrefix.values().toArray(new SubConfig[0]);
  }

  /**
   * Looks up a sub-config by its prefix.
   *
   * @param subConfig the {@code prefix} key used during registration
   * @return the matching {@link SubConfig}, or {@code null} if none is registered
   */
  public synchronized SubConfig get(String subConfig) {
    return configsByPrefix.get(subConfig);
  }

  /**
   * Creates a new {@link SubConfig} instance associated with this registry.
   *
   * <p>The returned instance is not added to the registry. Call {@link #register(SubConfig)} to
   * make it available for lookups.
   *
   * @param subConfig the {@code prefix} of the new sub-config
   * @return a new sub-config bound to this {@link Config}
   */
  public SubConfig createSubConfig(String subConfig) {
    return new SubConfig(subConfig, this);
  }

  /**
   * Returns an {@link Option} of type {@code Long} for a given key on the supplied sub-config.
   *
   * <p>Convenience method that validates the option's declared {@link Option.DataType} is {@link
   * Option.DataType#NUMBER} and narrows the return type.
   *
   * @param subConfig the source sub-config
   * @param key the option key
   * @return the numeric option
   * @throws ClassCastException if the option exists but is not of a numeric type
   */
  @SuppressWarnings("unchecked")
  public static Option<Long> longOption(SubConfig subConfig, String key) {
    Option<?> opt = subConfig.getOption(key);
    if (opt.getDataType() != Option.DataType.NUMBER) {
      throw new ClassCastException("Option '" + key + "' is not numeric: " + opt.getDataType());
    }
    return (Option<Long>) opt;
  }
}
