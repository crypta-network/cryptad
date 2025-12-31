package network.crypta.node;

import network.crypta.config.InvalidConfigValueException;
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
 * <p>Extracted to keep configuration callbacks and localization dependencies out of the core
 * statistics collector.
 */
final class NodeStatsConfig {
  private static final Logger LOG = LoggerFactory.getLogger(NodeStatsConfig.class);

  private final SubConfig statsConfig;

  NodeStatsConfig(SubConfig statsConfig) {
    this.statsConfig = statsConfig;
  }

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
        sortOrder++,
        true,
        true,
        "NodeStat.threadLimit",
        "NodeStat.threadLimitLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return stats.getThreadLimit();
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (stats.getThreadLimit() == val) return;
            if (val < 100) throw new InvalidConfigValueException(l10n("valueTooLow"));
            stats.updateThreadLimit(val);
          }
        },
        false);
    stats.updateThreadLimit(statsConfig.getInt("threadLimit"));
    return sortOrder;
  }

  private void registerIgnoredOptions() {
    // Yes it could be in seconds instead of multiples of 0.12, but we don't want people to play
    // with it :)
    statsConfig.registerIgnoredOption("aggressiveGC");
    statsConfig.registerIgnoredOption("memoryChecker");
  }

  private int configureBandwidthLiabilityOption(NodeStats stats, int sortOrder) {
    statsConfig.register(
        "ignoreLocalVsRemoteBandwidthLiability",
        false,
        sortOrder++,
        true,
        false,
        "NodeStat.ignoreLocalVsRemoteBandwidthLiability",
        "NodeStat.ignoreLocalVsRemoteBandwidthLiabilityLong",
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

  private int configurePingTimes(NodeStats stats, int sortOrder) {
    statsConfig.register(
        "maxPingTime",
        NodeStats.DEFAULT_MAX_PING_TIME,
        sortOrder++,
        true,
        true,
        "NodeStat.maxPingTime",
        "NodeStat.maxPingTimeLong",
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
        sortOrder++,
        true,
        true,
        "NodeStat.subMaxPingTime",
        "NodeStat.subMaxPingTimeLong",
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
        node.getTicker(),
        node.getRunDir());
  }

  private SimpleFieldSet readThrottleFS(Persister persister) {
    SimpleFieldSet throttleFS = persister.read();
    if (LOG.isDebugEnabled()) LOG.debug("Read throttleFS: {}", throttleFS);
    return throttleFS;
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("NodeStats." + key);
  }

  static final class Result {
    final int sortOrder;
    final ConfigurablePersister persister;
    final SimpleFieldSet throttleFS;

    Result(int sortOrder, ConfigurablePersister persister, SimpleFieldSet throttleFS) {
      this.sortOrder = sortOrder;
      this.persister = persister;
      this.throttleFS = throttleFS;
    }
  }
}
