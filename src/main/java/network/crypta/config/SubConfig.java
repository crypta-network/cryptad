package network.crypta.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.ShortCallback;
import network.crypta.support.api.StringArrCallback;
import network.crypta.support.api.StringCallback;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A configuration subsection owned by a {@link Config}.
 *
 * <p>Each {@code SubConfig} groups a set of typed {@link Option} values under a prefix (e.g.,
 * {@code node.} or {@code plugins.}). Options are registered once and may later be read, written,
 * exported, or removed. Access to the internal map is synchronized on {@code this} to make
 * registration and queries safe when called from multiple threads.
 *
 * <p>Instances are identity-based for equality; two different objects are never equal even if they
 * have the same prefix. Ordering is lexicographic by prefix via {@link #compareTo(SubConfig)}.
 */
public class SubConfig implements Comparable<SubConfig> {
  private static final Logger LOG = LoggerFactory.getLogger(SubConfig.class);

  private final LinkedHashMap<String, Option<?>> map;
  public final Config config;
  final String prefix;
  private boolean hasInitialized;

  // No static initialization required.

  /**
   * Creates a sub-configuration bound to a {@link Config} and a string prefix.
   *
   * <p>Callers should prefer {@link Config#createSubConfig(String)} to ensure consistent
   * registration and lifecycle handling.
   *
   * @param prefix Subtree prefix used when exporting and looking up keys.
   * @param config Owning configuration which tracks and persists this subsection.
   */
  SubConfig(String prefix, Config config) {
    this.config = config;
    this.prefix = prefix;
    map = new LinkedHashMap<>();
    hasInitialized = false;
    config.register(this);
  }

  /**
   * Returns a snapshot array of all registered options.
   *
   * <p>The returned array contains heterogeneous {@link Option} instances. It is safe to iterate
   * without additional synchronization. Callers must not assume a specific element type.
   *
   * @return all options currently registered in registration order.
   */
  @SuppressWarnings(
      "java:S1452") // Intentional: heterogeneous Option<T> set; wildcard expresses read-only,
  // type-agnostic view
  public synchronized Option<?>[] getOptions() {
    return map.values().toArray(new Option<?>[0]);
  }

  /**
   * Returns the option registered under {@code option} or {@code null} when absent.
   *
   * @param option Option name without the {@link #prefix}.
   * @return the matching {@link Option} instance, or {@code null}.
   */
  @SuppressWarnings(
      "java:S1452") // Intentional: Option<T> varies per key; callers use type-agnostic API
  public synchronized Option<?> getOption(String option) {
    return map.get(option);
  }

  /**
   * Registers an already-constructed {@link Option} with this subsection.
   *
   * <p>Names must be unique within the subsection and must not contain {@link
   * SimpleFieldSet#MULTI_LEVEL_CHAR}.
   *
   * @param o Option to register.
   * @throws IllegalArgumentException if the name is a duplicate or contains the multi-level
   *     separator character.
   */
  public void register(Option<?> o) {
    synchronized (this) {
      if (o.name.indexOf(SimpleFieldSet.MULTI_LEVEL_CHAR) != -1)
        throw new IllegalArgumentException(
            "Option names must not contain " + SimpleFieldSet.MULTI_LEVEL_CHAR);
      if (map.containsKey(o.name))
        throw new IllegalArgumentException("Already registered: " + o.name + " on " + this);
      map.put(o.name, o);
    }
    config.onRegister(this, o);
  }

  /**
   * Registers an {@code int}-valued option.
   *
   * @param optionName Name of the option (no prefix).
   * @param defaultValue Default value used until changed.
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback invoked on value changes; {@code NullIntCallback} when {@code null}.
   * @param isSize When {@code true}, treat as a size (bytes) for units handling.
   */
  public void register(
      String optionName, int defaultValue, Option.Meta meta, IntCallback cb, boolean isSize) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) cb = new NullIntCallback();
    register(
        new IntOption(
            this,
            optionName,
            defaultValue,
            normalizedMeta,
            cb,
            isSize ? Dimension.SIZE : Dimension.NOT));
  }

  /**
   * Registers a {@code long}-valued option.
   *
   * @param optionName Name of the option (no prefix).
   * @param defaultValue Default value used until changed.
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback invoked on value changes; {@code NullLongCallback} when {@code null}.
   * @param isSize When {@code true}, treat as a size (bytes) for units handling.
   */
  public void register(
      String optionName, long defaultValue, Option.Meta meta, LongCallback cb, boolean isSize) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) cb = new NullLongCallback();
    register(new LongOption(this, optionName, defaultValue, normalizedMeta, cb, isSize));
  }

  /**
   * Registers a bandwidth option.
   *
   * @see BandwidthOption
   */
  public void register(String optionName, int defaultValue, Option.Meta meta, IntCallback cb) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) cb = new NullIntCallback();
    register(new BandwidthOption(this, optionName, defaultValue, normalizedMeta, cb));
  }

  /**
   * Registers an {@code int}-valued option with the default provided as a string.
   *
   * @param optionName Name of the option (no prefix).
   * @param defaultValueString Default value as string (parsed to {@code int}).
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback invoked on value changes; {@code NullIntCallback} when {@code null}.
   * @param dimension Logical dimension for unit handling.
   */
  public void register(
      String optionName,
      String defaultValueString,
      Option.Meta meta,
      IntCallback cb,
      Dimension dimension) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) {
      cb = new NullIntCallback();
    }
    register(new IntOption(this, optionName, defaultValueString, normalizedMeta, cb, dimension));
  }

  /**
   * Registers a {@code long}-valued option with the default provided as a string.
   *
   * @param optionName Name of the option (no prefix).
   * @param defaultValueString Default value as string (parsed to {@code long}).
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback invoked on value changes; {@code NullLongCallback} when {@code null}.
   * @param isSize When {@code true}, treat as a size (bytes) for units handling.
   */
  public void register(
      String optionName,
      String defaultValueString,
      Option.Meta meta,
      LongCallback cb,
      boolean isSize) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) cb = new NullLongCallback();
    register(new LongOption(this, optionName, defaultValueString, normalizedMeta, cb, isSize));
  }

  /**
   * Registers a bandwidth option.
   *
   * @see BandwidthOption
   */
  public void register(
      String optionName, String defaultValueString, Option.Meta meta, IntCallback cb) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) cb = new NullIntCallback();
    register(new BandwidthOption(this, optionName, defaultValueString, normalizedMeta, cb));
  }

  /**
   * Registers a {@code boolean}-valued option.
   *
   * @param optionName Name of the option (no prefix).
   * @param defaultValue Default value used until changed.
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback invoked on value changes; {@code NullBooleanCallback} when {@code null}.
   */
  public void register(
      String optionName, boolean defaultValue, Option.Meta meta, BooleanCallback cb) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) cb = new NullBooleanCallback();
    register(new BooleanOption(this, optionName, defaultValue, normalizedMeta, cb));
  }

  /**
   * Registers a {@code String}-valued option.
   *
   * @param optionName Name of the option (no prefix).
   * @param defaultValue Default value used until changed.
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback invoked on value changes; {@code NullStringCallback} when {@code null}.
   */
  public void register(
      String optionName, String defaultValue, Option.Meta meta, StringCallback cb) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) cb = new NullStringCallback();
    register(
        new StringOption(
            this,
            optionName,
            defaultValue,
            normalizedMeta.sortOrder(),
            normalizedMeta.expert(),
            normalizedMeta.forceWrite(),
            normalizedMeta.shortDesc(),
            normalizedMeta.longDesc(),
            cb));
  }

  /**
   * Registers a {@code short}-valued option.
   *
   * @param optionName Name of the option (no prefix).
   * @param defaultValue Default value used until changed.
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback invoked on value changes; {@code NullShortCallback} when {@code null}.
   * @param isSize When {@code true}, treat as a size (bytes) for units handling.
   */
  public void register(
      String optionName, short defaultValue, Option.Meta meta, ShortCallback cb, boolean isSize) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    if (cb == null) cb = new NullShortCallback();
    register(new ShortOption(this, optionName, defaultValue, normalizedMeta, cb, isSize));
  }

  /**
   * Registers a {@code String[]} option.
   *
   * @param optionName Name of the option (no prefix).
   * @param defaultValue Default value used until changed.
   * @param meta Presentation, description, and ordering metadata.
   * @param cb Callback invoked on value changes; may be {@code null}.
   */
  public void register(
      String optionName, String[] defaultValue, Option.Meta meta, StringArrCallback cb) {
    Option.Meta normalizedMeta = normalizeMeta(meta);
    register(new StringArrOption(this, optionName, defaultValue, normalizedMeta, cb));
  }

  private static Option.Meta normalizeMeta(Option.Meta meta) {
    return meta == null ? new Option.Meta(0, false, false, null, null) : meta;
  }

  /**
   * Registers an option that cannot be used.
   *
   * <p>It is not listed, it is not exported, it is not persisted, it doesn’t have a value. You
   * cannot change the value. It only exists so that Fred doesn’t log an error message if this
   * particular option is used in a config file.
   *
   * @param optionName The name of the option to ignore
   * @see PersistentConfig#finishedInit()
   */
  public void registerIgnoredOption(String optionName) {
    config.onRegister(this, new IgnoredOption(optionName));
  }

  /**
   * Returns the current value of an {@code int} option.
   *
   * <p>When the option is unknown (e.g., registered as ignored), a sentinel {@code -1} is returned
   * to avoid breaking legacy callers.
   *
   * @param optionName Name of the option (no prefix).
   * @return the value, or {@code -1} when missing/ignored.
   */
  public int getInt(String optionName) {
    IntOption o;
    synchronized (this) {
      o = (IntOption) map.get(optionName);
    }
    // Fallback for ignored options to keep historical behavior for plugins.
    return o == null ? -1 : o.getValue();
  }

  /**
   * Returns the current value of a {@code long} option.
   *
   * <p>When the option is unknown (e.g., registered as ignored), a sentinel {@code -1L} is returned
   * to avoid breaking legacy callers.
   *
   * @param optionName Name of the option (no prefix).
   * @return the value, or {@code -1L} when missing/ignored.
   */
  public long getLong(String optionName) {
    LongOption o;
    synchronized (this) {
      o = (LongOption) map.get(optionName);
    }
    // Fallback for ignored options to keep historical behavior for plugins.
    return o == null ? -1L : o.getValue();
  }

  /**
   * Returns the current value of a {@code boolean} option.
   *
   * <p>When the option is unknown (e.g., registered as ignored), {@code false} is returned.
   *
   * @param optionName Name of the option (no prefix).
   * @return the value, or {@code false} when missing/ignored.
   */
  public boolean getBoolean(String optionName) {
    BooleanOption o;
    synchronized (this) {
      o = (BooleanOption) map.get(optionName);
    }
    // Fallback for ignored options to keep historical behavior for plugins.
    return o != null && o.getValue();
  }

  /**
   * Returns the current value of a {@code String} option, trimmed of surrounding whitespace.
   *
   * <p>When the option is unknown (e.g., registered as ignored), an empty string is returned.
   *
   * @param optionName Name of the option (no prefix).
   * @return the trimmed value, or {@code ""} when missing/ignored.
   */
  public String getString(String optionName) {
    StringOption o;
    synchronized (this) {
      o = (StringOption) map.get(optionName);
    }
    // Fallback for ignored options to keep historical behavior for plugins.
    return o == null ? "" : o.getValue().trim();
  }

  /**
   * Returns the current value of a {@code String[]} option.
   *
   * <p>When the option is unknown (e.g., registered as ignored), an empty array is returned.
   *
   * @param optionName Name of the option (no prefix).
   * @return the array value, or an empty array when missing/ignored.
   */
  public String[] getStringArr(String optionName) {
    StringArrOption o;
    synchronized (this) {
      o = (StringArrOption) map.get(optionName);
    }
    // Fallback for ignored options to keep historical behavior for plugins.
    return o == null ? new String[] {} : o.getValue();
  }

  /**
   * Returns the current value of a {@code short} option.
   *
   * <p>When the option is unknown (e.g., registered as ignored), a sentinel {@code -1} is returned
   * to avoid breaking legacy callers.
   *
   * @param optionName Name of the option (no prefix).
   * @return the value, or {@code -1} when missing/ignored.
   */
  public short getShort(String optionName) {
    ShortOption o;
    synchronized (this) {
      o = (ShortOption) map.get(optionName);
    }
    // Fallback for ignored options to keep historical behavior for plugins.
    return o == null ? -1 : o.getValue();
  }

  /**
   * Removes and returns the option with the given name.
   *
   * @param optionName Name of the option (no prefix).
   * @return the removed {@link Option}, or {@code null} if no such option exists.
   */
  @SuppressWarnings(
      "java:S1452") // Intentional: heterogeneous Option<T> set; wildcard expresses read-only,
  // type-agnostic view
  public Option<?> removeOption(String optionName) {
    synchronized (this) {
      return map.remove(optionName);
    }
  }

  /**
   * Returns whether the owning object has finished initialization.
   *
   * <p>After initialization, option callbacks are considered authoritative and may be invoked on
   * user-initiated changes.
   *
   * @return {@code true} once {@link #finishedInitialization()} has been called.
   */
  public boolean hasFinishedInitialization() {
    return hasInitialized;
  }

  /**
   * Marks the subsection as initialized.
   *
   * <p>After this point, callbacks are authoritative for option values and are triggered when
   * options are changed by the user.
   */
  public void finishedInitialization() {
    hasInitialized = true;
    if (LOG.isDebugEnabled()) LOG.debug("Finished initialization on {} ({})", this, prefix);
  }

  /**
   * Applies values from a {@link SimpleFieldSet} to registered options.
   *
   * <p>Only keys present in {@code sfs} are processed; unrecognized keys are ignored. Invalid
   * values are logged and skipped. Values not present remain unchanged.
   *
   * @param sfs Field set providing string values keyed by option name.
   */
  public synchronized void setOptions(SimpleFieldSet sfs) {
    for (Entry<String, Option<?>> entry : map.entrySet()) {
      String key = entry.getKey();
      Option<?> o = entry.getValue();
      String val = sfs.get(key);
      if (val != null) {
        try {
          o.setValue(val);
        } catch (InvalidConfigValueException e) {
          String msg =
              "Invalid config value: "
                  + prefix
                  + SimpleFieldSet.MULTI_LEVEL_CHAR
                  + key
                  + " = "
                  + val
                  + " : error: "
                  + e;
          LOG.error(msg, e);
        } catch (NodeNeedRestartException e) {
          // Should not occur when applying initial values from a field set.
          String msg =
              "Impossible: "
                  + prefix
                  + SimpleFieldSet.MULTI_LEVEL_CHAR
                  + key
                  + " = "
                  + val
                  + " : error: "
                  + e;
          LOG.error(msg, e);
        }
      }
    }
  }

  /**
   * Exports this subsection as a field set with current values (excluding defaults by default).
   *
   * @return a {@link SimpleFieldSet} with {@link Config.RequestType#CURRENT_SETTINGS}.
   */
  public SimpleFieldSet exportFieldSet() {
    return exportFieldSet(false);
  }

  /**
   * Exports this subsection as a field set with current or default values.
   *
   * @param withDefaults When {@code true}, includes options that are still at their default values.
   * @return a {@link SimpleFieldSet} with {@link Config.RequestType#CURRENT_SETTINGS}.
   */
  public SimpleFieldSet exportFieldSet(boolean withDefaults) {
    return exportFieldSet(Config.RequestType.CURRENT_SETTINGS, withDefaults);
  }

  /**
   * Exports this subsection as a field set according to the requested view.
   *
   * <p>Depending on {@code configRequestType}, the field set contains values, defaults, sort order,
   * flags, descriptions, or data types. When exporting current settings, default-valued options are
   * skipped unless {@code withDefaults} is {@code true} and the option is not forced to be written.
   *
   * @param configRequestType Type of data to export.
   * @param withDefaults Whether to include default-valued options for current settings.
   * @return a new {@link SimpleFieldSet} containing the requested data.
   */
  public SimpleFieldSet exportFieldSet(Config.RequestType configRequestType, boolean withDefaults) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    // Snapshot entries into a typed List to avoid generic array casts.
    final List<Map.Entry<String, Option<?>>> entries;
    synchronized (this) {
      entries = new ArrayList<>(map.entrySet());
    }
    if (LOG.isDebugEnabled()) LOG.debug("Prefix={}", prefix);
    for (Map.Entry<String, Option<?>> entry : entries) {
      String key = entry.getKey();
      Option<?> o = entry.getValue();
      if (LOG.isDebugEnabled())
        LOG.debug("Key={} value={} default={}", key, o.getValueString(), o.isDefault());
      if (configRequestType == Config.RequestType.CURRENT_SETTINGS
          && (!withDefaults)
          && o.isDefault()
          && (!o.forceWrite)) {
        if (LOG.isDebugEnabled()) LOG.debug("Skipping {} - {}", key, o.isDefault());
        continue;
      }
      switch (configRequestType) {
        case CURRENT_SETTINGS:
          fs.putSingle(key, o.getValueString());
          break;
        case DEFAULT_SETTINGS:
          fs.putSingle(key, o.getDefault());
          break;
        case SORT_ORDER:
          fs.put(key, o.getSortOrder());
          break;
        case EXPERT_FLAG:
          fs.put(key, o.isExpert());
          break;
        case FORCE_WRITE_FLAG:
          fs.put(key, o.isForcedWrite());
          break;
        case SHORT_DESCRIPTION:
          fs.putSingle(key, o.getLocalisedShortDesc());
          break;
        case LONG_DESCRIPTION:
          fs.putSingle(key, o.getLocalisedLongDesc());
          break;
        case DATA_TYPE:
          fs.putSingle(key, o.getDataTypeStr());
          break;
        default:
          LOG.error("Unknown config request type value: {}", configRequestType);
          break;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Key={}.{} value={}", prefix, key, o.getValueString());
    }
    return fs;
  }

  /**
   * Force an option to be updated even if it hasn't changed.
   *
   * @param optionName Name of the option to refresh.
   * @throws InvalidConfigValueException if the current value is invalid for the option type.
   * @throws NodeNeedRestartException if the change requires a restart.
   */
  public void forceUpdate(String optionName)
      throws InvalidConfigValueException, NodeNeedRestartException {
    Option<?> o = map.get(optionName);
    o.forceUpdate();
  }

  /**
   * Sets the value of a string-parsed option.
   *
   * @param name Name of the option (no prefix).
   * @param value String representation to parse and apply.
   * @throws InvalidConfigValueException if {@code value} cannot be parsed for the target type.
   * @throws NodeNeedRestartException if the change requires a restart.
   */
  public void set(String name, String value)
      throws InvalidConfigValueException, NodeNeedRestartException {
    Option<?> o = map.get(name);
    o.setValue(value);
  }

  /**
   * Sets the value of a {@code boolean} option.
   *
   * @param name Name of the option (no prefix).
   * @param value New boolean value.
   * @throws InvalidConfigValueException if the update is rejected by the callback.
   * @throws NodeNeedRestartException if the change requires a restart.
   */
  public void set(String name, boolean value)
      throws InvalidConfigValueException, NodeNeedRestartException {
    BooleanOption o = (BooleanOption) map.get(name);
    o.set(value);
  }

  /**
   * If the option's value is equal to the provided old default, then set it to the new default.
   * Used to deal with changes to important options where this is not handled automatically because
   * the option's value is written to the .ini.
   *
   * @param name The name of the option.
   * @param value The value of the option.
   */
  @SuppressWarnings("unused")
  public void fixOldDefault(String name, String value) {
    Option<?> o = map.get(name);
    if (o.getValueString().equals(value)) o.setDefault();
  }

  /**
   * If the option's value matches the provided old default regex, then set it to the new default.
   * Used to deal with changes to important options where this is not handled automatically because
   * the option's value is written to the .ini.
   *
   * @param name The name of the option.
   * @param value The value of the option.
   */
  @SuppressWarnings("unused")
  public void fixOldDefaultRegex(String name, String value) {
    Option<?> o = map.get(name);
    if (o.getValueString().matches(value)) o.setDefault();
  }

  /**
   * Returns the prefix used by this subsection.
   *
   * @return the prefix string (never {@code null}).
   */
  public String getPrefix() {
    return prefix;
  }

  /**
   * Note: this class has a natural ordering that is inconsistent with equals. Two different
   * SubConfig instances are never considered equal, even if their prefixes are equal. This
   * preserves historical behavior and existing callers which rely on identity semantics.
   */
  @Override
  public boolean equals(Object obj) {
    return this == obj;
  }

  @Override
  public int hashCode() {
    return System.identityHashCode(this);
  }

  /**
   * Compares two subsections by their prefix for a total order.
   *
   * <p>Returns {@code 0} for identical instances to satisfy the {@link Comparable} contract; for
   * different instances the comparison delegates to {@link String#compareTo(String)} on prefixes.
   *
   * @param second Another subsection (non-null).
   * @return negative, zero, or positive per {@link String#compareTo(String)}.
   */
  @Override
  public int compareTo(@NotNull SubConfig second) {
    if (this == second) return 0; // equal elements must return 0 per Comparable contract
    // Delegate to lexicographic ordering of prefixes for total order
    return this.getPrefix().compareTo(second.getPrefix());
  }

  /**
   * Returns the raw, unparsed value from the persistent config file before initialization.
   *
   * <p>Only available while the owning {@link PersistentConfig} is still initializing; otherwise an
   * {@link IllegalStateException} is thrown.
   *
   * @param name Option name (no prefix).
   * @return the raw string value, or {@code null} if not present or when not a {@code
   *     PersistentConfig}.
   * @throws IllegalStateException if called after {@link PersistentConfig#finishedInit}.
   */
  public String getRawOption(String name) {
    if (config instanceof PersistentConfig pc) {
      if (pc.finishedInit)
        throw new IllegalStateException(
            "getRawOption("
                + name
                + ") on "
                + this
                + " but persistent config has been finishedInit() already!");
      SimpleFieldSet fs = pc.origConfigFileContents;
      if (fs == null) return null;
      return fs.get(prefix + SimpleFieldSet.MULTI_LEVEL_CHAR + name);
    } else return null;
  }

  private class IgnoredOption extends Option<Void> {

    /**
     * Sentinel option used for names that should be accepted but never read, written, or exported.
     *
     * <p>Prevents log noise when legacy or plugin configs reference removed settings.
     */
    public IgnoredOption(String optionName) {
      super(
          SubConfig.this,
          optionName,
          new ConfigCallback<>() {
            @Override
            public Void get() {
              return null;
            }

            @Override
            public void set(Void value) {
              // Intentionally no-op: the ignored option accepts no value updates.
            }
          },
          new Option.Meta(-1, false, false, null, null),
          null);
    }

    @Override
    protected Void parseString(String val) {
      return null;
    }

    @Override
    protected String toString(Void val) {
      return null;
    }
  }
}
