package network.crypta.config;

import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration registry that consumes an initial {@link SimpleFieldSet}.
 *
 * <p>This subclass of {@link Config} allows callers to provide a pre-parsed set of key/value pairs
 * (typically loaded from persistent storage). As individual {@link Option}s register themselves via
 * {@link #onRegister(SubConfig, Option)}, matching entries are consumed from the initial {@link
 * SimpleFieldSet} and used to set each option's initial value. After {@link #finishedInit()} is
 * invoked, any remaining keys are reported as unknown and the backing field set is cleared.
 *
 * <p>Thread-safety: access to internal state is synchronized on {@code this} where required. The
 * {@link #finishedInit} flag is {@code volatile} to ensure visibility across threads.
 */
public class PersistentConfig extends Config {
  private static final Logger LOG = LoggerFactory.getLogger(PersistentConfig.class);

  /**
   * Snapshot of options as read from persistent storage.
   *
   * <p>Keys are in the canonical dotted form {@code <prefix>.<option>} (see {@link
   * SimpleFieldSet#MULTI_LEVEL_CHAR}). Entries are removed as options register. Set to {@code null}
   * once {@link #finishedInit()} completes.
   */
  protected final AtomicReference<SimpleFieldSet> origConfigFileContents = new AtomicReference<>();

  /**
   * Indicates whether the configuration has completed initialization.
   *
   * <p>When {@code true}, further calls to {@link #onRegister(SubConfig, Option)} are invalid and
   * will throw {@link IllegalStateException}. Marked {@code volatile} for cross-thread visibility.
   */
  protected volatile boolean finishedInit;

  /**
   * Creates a configuration backed by an optional initial field set.
   *
   * @param initialContents the source of initial values; may be {@code null}
   */
  public PersistentConfig(SimpleFieldSet initialContents) {
    this.origConfigFileContents.set(initialContents);
  }

  /**
   * Marks initialization complete and reports any unknown options.
   *
   * <p>Logs an error for each unconsumed key in the original {@link SimpleFieldSet}, then clears
   * the reference. Also delegates to {@link Config#finishedInit()} to validate that all {@link
   * SubConfig} instances finished their own initialization.
   */
  @Override
  public synchronized void finishedInit() {
    finishedInit = true;
    SimpleFieldSet originalContents = origConfigFileContents.get();
    if (originalContents == null) return;
    Iterator<String> i = originalContents.keyIterator();
    while (i.hasNext()) {
      String key = i.next();
      if (LOG.isErrorEnabled()) {
        String value = originalContents.get(key);
        LOG.error("Unknown option: {} (value={})", key, value);
      }
    }
    origConfigFileContents.set(null);
    super.finishedInit();
  }

  /**
   * Exports the current settings to a field set.
   *
   * <p>Equivalent to {@link #exportFieldSet(boolean) exportFieldSet(false)}.
   *
   * @return a new {@link SimpleFieldSet} containing the current values only
   */
  public SimpleFieldSet exportFieldSet() {
    return exportFieldSet(false);
  }

  /**
   * Exports settings to a field set, optionally including defaults.
   *
   * <p>Equivalent to invoking {@link #exportFieldSet(Config.RequestType, boolean)} with {@link
   * Config.RequestType#CURRENT_SETTINGS}.
   *
   * @param withDefaults whether to include default values for all options
   * @return a new {@link SimpleFieldSet} keyed by {@link SubConfig} prefix
   */
  public SimpleFieldSet exportFieldSet(boolean withDefaults) {
    return exportFieldSet(Config.RequestType.CURRENT_SETTINGS, withDefaults);
  }

  /**
   * Exports option metadata or values for all registered sub-configs.
   *
   * <p>The resulting {@link SimpleFieldSet} contains one nested field set per {@link SubConfig},
   * keyed by the sub-config's {@code prefix}. The content of each nested set depends on {@code
   * configRequestType}; see {@link Config.RequestType} for supported attributes.
   *
   * @param configRequestType the kind of data to export (values, defaults, descriptions, etc.)
   * @param withDefaults when {@code true} and {@code configRequestType} requests values, include
   *     defaults for options that do not currently have an explicit value
   * @return a new {@link SimpleFieldSet} representing the export
   */
  public SimpleFieldSet exportFieldSet(Config.RequestType configRequestType, boolean withDefaults) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    SubConfig[] configs;
    synchronized (this) {
      // Consider caching the array if profiles show this call is a hotspot.
      configs = configsByPrefix.values().toArray(new SubConfig[0]);
    }
    for (SubConfig current : configs) {
      SimpleFieldSet scfs = current.exportFieldSet(configRequestType, withDefaults);
      fs.tput(current.prefix, scfs);
    }
    return fs;
  }

  /**
   * Consumes an initial value for a newly registered option from the original field set.
   *
   * <p>If a value exists under {@code <prefix>.<name>}, it is parsed and applied via {@link
   * Option#setInitialValue(String)}. Parse failures are logged at the error level, and the option
   * keeps its default. When called after {@link #finishedInit()}, this method throws.
   *
   * @param config the owning {@link SubConfig}
   * @param o the option being registered
   * @throws IllegalStateException if invoked after initialization is marked finished
   */
  @Override
  public void onRegister(SubConfig config, Option<?> o) {
    String val;
    String name;
    synchronized (this) {
      if (finishedInit)
        throw new IllegalStateException(
            "onRegister(" + config + ':' + o + ") called after finishedInit() !!");
      SimpleFieldSet originalContents = origConfigFileContents.get();
      if (originalContents == null) return;
      name = config.prefix + SimpleFieldSet.MULTI_LEVEL_CHAR + o.name;
      val = originalContents.get(name);
      originalContents.removeValue(name);
      if (val == null) return;
    }
    try {
      o.setInitialValue(val.trim());
    } catch (InvalidConfigValueException e) {
      LOG.error("Could not parse config option {}: {}", name, e, e);
    }
  }

  /**
   * Returns a defensive copy of the original field set as read by the config framework.
   *
   * @return a copy of the initial {@link SimpleFieldSet}, or {@code null} if initialization has
   *     finished or if no original contents were provided
   */
  public synchronized SimpleFieldSet getSimpleFieldSet() {
    SimpleFieldSet originalContents = origConfigFileContents.get();
    return (originalContents == null ? null : new SimpleFieldSet(originalContents));
  }
}
