package network.crypta.node;

import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Applies configuration and persistence wiring for {@link NodeStats}.
 *
 * <p>This helper owns the one-time setup that binds {@link SubConfig} options to {@link NodeStats}
 * fields, including default selection based on the detected memory limit and the wiring of
 * persistence for throttle-related metrics. Callers typically create one instance during node
 * startup, invoke {@link #configure(NodeStats, Node, int)}, and then retain the returned {@link
 * Result} so {@link NodeStats} can continue operating with the configured persister and the
 * boot-time throttle snapshot.
 *
 * <p>The class is intentionally stateful (it holds the {@link SubConfig}) but is not thread-safe;
 * it is designed for single-threaded initialization before the statistics system becomes visible.
 * Configuration is mutated as a side effect and should not be reconfigured after {@code
 * finishedInitialization()} has been called.
 *
 * <ul>
 *   <li>Registers stat-related options and their validation callbacks.
 *   <li>Chooses defaults based on resource limits and applies them to {@link NodeStats}.
 *   <li>Creates a persister and loads any existing throttle data.
 * </ul>
 *
 * @see NodeStats
 * @see ConfigurablePersister
 */
public final class NodeStatsConfig {
  /** Logger used for initialization-time configuration and throttle-file diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(NodeStatsConfig.class);

  /** Backing configuration for node statistics options; mutated during initialization. */
  private final SubConfig statsConfig;

  /**
   * Creates a configuration helper bound to the provided sub-configuration.
   *
   * <p>The instance retains the {@code statsConfig} reference and uses it to register options,
   * default values, and persistence wiring. The configuration is expected to be mutable during
   * construction and will be marked finished during {@link #configure(NodeStats, Node, int)}.
   *
   * @param statsConfig mutable sub-configuration for node stats; must be non-null
   */
  /**
   * Creates a configuration binder for node statistics.
   *
   * @param statsConfig subconfig containing statistics settings
   */
  public NodeStatsConfig(SubConfig statsConfig) {
    this.statsConfig = statsConfig;
  }

  /**
   * Registers node statistics options, applies defaults, and creates the persister.
   *
   * <p>This method is the main entry point for initialization. It registers configuration keys,
   * updates {@link NodeStats} with the selected values, and sets up the on-disk persister used for
   * throttle and running-average state. The call is not idempotent; it mutates {@code statsConfig}
   * and calls {@code finishedInitialization()} exactly once. If a throttle file exists, it is
   * loaded and returned to the caller for use during subsequent stat initialization.
   *
   * <p>Callers typically pass the current sort order for config UI layout and use the returned
   * value to continue registering additional options elsewhere.
   *
   * @param stats live statistics collector to receive configured values; must be non-null
   * @param node node instance providing runtime paths and ticker access; must be non-null
   * @param sortOrder starting order index for new configuration entries
   * @return configuration artifacts including the updated sort order and persister
   * @throws NodeInitException if persister setup fails or the throttle file is unusable
   */
  Result configure(NodeStats stats, Node node, int sortOrder) throws NodeInitException {
    int order = configureThreadLimit(stats, sortOrder);
    registerIgnoredOptions();
    order = configureBandwidthLiabilityOption(stats, order);
    order = configurePingTimes(stats, order);

    statsConfig.registerIgnoredOption("enableNewLoadManagementRT");
    statsConfig.registerIgnoredOption("enableNewLoadManagementBulk");

    ConfigurablePersister persister = createPersister(stats, order, node);
    SimpleFieldSet throttleFS = readThrottleFS(persister);

    statsConfig.finishedInitialization();
    return new Result(order, persister, throttleFS);
  }

  /**
   * Registers the {@code threadLimit} option and applies the initial value to {@code stats}.
   *
   * <p>The default value is chosen from the detected memory limit and logged at debug level. The
   * resulting configuration entry validates the limit and invokes {@link
   * NodeStats#updateThreadLimit} when the user changes the value.
   *
   * @param stats live statistics collector to receive the configured thread limit
   * @param sortOrder current sort order for registering the option
   * @return the next sort order after registering {@code threadLimit}
   */
  private int configureThreadLimit(NodeStats stats, int sortOrder) {
    int defaultThreadLimit;
    long memoryLimit = NodeStarter.getMemoryLimitMB();
    LOG.debug("Detected memory limit {} MB", memoryLimit);
    if (memoryLimit > 0 && memoryLimit < 100) {
      defaultThreadLimit = 200;
      LOG.debug("Severe memory pressure; set thread limit to 200. Crypta may not work well.");
    } else if (memoryLimit > 0 && memoryLimit < 128) {
      defaultThreadLimit = 300;
      LOG.debug(
          "Moderate memory pressure; set thread limit to 300. Increase the limit in wrapper.conf if"
              + " possible.");
    } else if (memoryLimit > 0 && memoryLimit < 192) {
      defaultThreadLimit = 400;
      LOG.debug("Set thread limit to 400 due to <=192 MB memory limit. More memory is better.");
    } else if (memoryLimit > 0 && memoryLimit < 512) {
      defaultThreadLimit = 500;
      LOG.debug("Set thread limit to 500 due to <=512 MB memory limit. More memory is better.");
    } else {
      defaultThreadLimit = 1000;
      LOG.debug("Set standard thread limit to 1000. Suitable for most nodes.");
    }
    statsConfig.register(
        "threadLimit",
        defaultThreadLimit,
        new Option.Meta(
            sortOrder++, true, true, "NodeStat.threadLimit", "NodeStat.threadLimitLong"),
        new IntCallback() {
          @Override
          public Integer get() {
            return stats.getThreadLimit();
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (stats.getThreadLimit() == val) return;
            if (val < 100) {
              throw new InvalidConfigValueException(
                  NodeL10n.getBase().getString("NodeStats.valueTooLow"));
            }
            stats.updateThreadLimit(val);
          }
        },
        false);
    stats.updateThreadLimit(statsConfig.getInt("threadLimit"));
    return sortOrder;
  }

  /**
   * Registers configuration keys that are intentionally ignored by the node.
   *
   * <p>These options remain in the configuration namespace for compatibility, but their values are
   * not consumed by the current implementation.
   */
  private void registerIgnoredOptions() {
    // Yes it could be in seconds instead of multiples of 0.12, but we don't want people to play
    // with it :)
    statsConfig.registerIgnoredOption("aggressiveGC");
    statsConfig.registerIgnoredOption("memoryChecker");
  }

  /**
   * Registers the bandwidth liability toggle and applies its initial value to {@code stats}.
   *
   * <p>This option influences how local versus remote bandwidth liability is treated. The method
   * registers a boolean configuration entry and immediately synchronizes the current value onto the
   * {@link NodeStats} instance.
   *
   * @param stats live statistics collector to receive the configured flag value
   * @param sortOrder current sort order for registering the option
   * @return the next sort order after registering the bandwidth liability option
   */
  private int configureBandwidthLiabilityOption(NodeStats stats, int sortOrder) {
    statsConfig.register(
        "ignoreLocalVsRemoteBandwidthLiability",
        false,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "NodeStat.ignoreLocalVsRemoteBandwidthLiability",
            "NodeStat.ignoreLocalVsRemoteBandwidthLiabilityLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return stats.getIgnoreLocalVsRemoteBandwidthLiability();
          }

          @Override
          public void set(Boolean val) {
            stats.setIgnoreLocalVsRemoteBandwidthLiability(val);
          }
        });
    stats.setIgnoreLocalVsRemoteBandwidthLiability(
        statsConfig.getBoolean("ignoreLocalVsRemoteBandwidthLiability"));
    return sortOrder;
  }

  /**
   * Registers ping-time configuration options and applies their initial values.
   *
   * <p>The method wires both {@code maxPingTime} and {@code subMaxPingTime} using long-valued
   * callbacks, then updates {@link NodeStats} with the persisted values from configuration.
   *
   * @param stats live statistics collector to receive ping time values
   * @param sortOrder current sort order for registering the options
   * @return the next sort order after registering ping-time options
   */
  private int configurePingTimes(NodeStats stats, int sortOrder) {
    statsConfig.register(
        "maxPingTime",
        NodeStats.DEFAULT_MAX_PING_TIME,
        new Option.Meta(
            sortOrder++, true, true, "NodeStat.maxPingTime", "NodeStat.maxPingTimeLong"),
        new LongCallback() {

          @Override
          public Long get() {
            return stats.getMaxPingTime();
          }

          @Override
          public void set(Long val) {
            stats.setMaxPingTime(val);
          }
        },
        false);
    stats.setMaxPingTime(statsConfig.getLong("maxPingTime"));

    statsConfig.register(
        "subMaxPingTime",
        NodeStats.DEFAULT_SUB_MAX_PING_TIME,
        new Option.Meta(
            sortOrder++, true, true, "NodeStat.subMaxPingTime", "NodeStat.subMaxPingTimeLong"),
        new LongCallback() {

          @Override
          public Long get() {
            return stats.getSubMaxPingTime();
          }

          @Override
          public void set(Long val) {
            stats.setSubMaxPingTime(val);
          }
        },
        false);
    stats.setSubMaxPingTime(statsConfig.getLong("subMaxPingTime"));
    return sortOrder;
  }

  /**
   * Builds the persister used for node throttle state and related statistics.
   *
   * <p>The persister is configured with the throttle file names and the runtime location derived
   * from {@code node}. The returned instance is used to read and write persisted statistics.
   *
   * @param stats live statistics collector associated with the persister
   * @param sortOrder current sort order for configuration entries
   * @param node node instance providing runtime paths and ticker access
   * @return a configured persister for node throttle data
   * @throws NodeInitException if the persister cannot be created for the run directory
   */
  private ConfigurablePersister createPersister(NodeStats stats, int sortOrder, Node node)
      throws NodeInitException {
    return new ConfigurablePersister(
        stats,
        statsConfig,
        "nodeThrottleFile",
        "node-throttle.dat",
        sortOrder,
        true,
        false,
        "NodeStat.statsPersister",
        "NodeStat.statsPersisterLong",
        node.network().ticker(),
        node.getRunDir());
  }

  /**
   * Reads the throttle field set from the supplied persister.
   *
   * <p>The result may be empty when no prior throttle data exists. The raw field set is logged at
   * debug level to aid diagnostics.
   *
   * @param persister persister instance that reads the throttle snapshot
   * @return the field set returned by the persister, possibly empty but never null
   */
  private SimpleFieldSet readThrottleFS(Persister persister) {
    SimpleFieldSet throttleFS = persister.read();
    if (LOG.isDebugEnabled()) LOG.debug("Read throttleFS: {}", throttleFS);
    return throttleFS;
  }

  /**
   * Aggregates configuration artifacts produced during node statistics initialization.
   *
   * <p>The record is an immutable carrier for values that must be handed back to callers after
   * configuration is complete. It includes the updated sort order, the configured persister, and
   * the initial throttle field set loaded from disk.
   *
   * @param sortOrder next sort order index for subsequent configuration entries
   * @param persister configured persister for throttle and running-average state
   * @param throttleFS field set loaded from the throttle file, possibly empty
   */
  record Result(int sortOrder, ConfigurablePersister persister, SimpleFieldSet throttleFS) {}
}
