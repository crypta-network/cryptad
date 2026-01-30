package network.crypta.node;

import static java.util.concurrent.TimeUnit.DAYS;

import network.crypta.node.RequestTracker.WaitingForSlots;
import network.crypta.support.SimpleFieldSet;

/**
 * Builds volatile statistics snapshots for node and peer reporting.
 *
 * <p>This helper assembles a short-lived {@link SimpleFieldSet} by pulling current counters and
 * running averages from {@link NodeStats} and its collaborators. Callers use it when rendering UI
 * panels or exporting peer-visible snapshots; each invocation recomputes values using the current
 * wall clock time and does not cache or persist the result. The snapshot is best-effort: values are
 * read independently and may reflect slightly different instants, but no mutation occurs within
 * this exporter. Uptime-derived rates are normalized with a minimum of one second to avoid division
 * by zero, and empty recent windows fall back to zero-rate outputs.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Computing uptime, ping/delay, and network size estimate fields.
 *   <li>Counting peer connection states and routing backoff reasons.
 *   <li>Aggregating I/O, swap, datastore, and success-rate metrics.
 * </ul>
 *
 * @see NodeStats
 * @see SimpleFieldSet
 */
final class NodeStatsFieldSetExporter {

  /** Prevents instantiation; this class is a static helper for snapshots. */
  private NodeStatsFieldSetExporter() {}

  /**
   * Creates a new snapshot field set containing volatile runtime metrics.
   *
   * <p>The method reads counters and running averages from {@code stats} and its {@link Node},
   * {@link PeerManager}, and {@link RequestTracker} collaborators, computes derived rates and
   * percentages, and stores the results as string values in a short-lived {@link SimpleFieldSet}.
   * It uses {@link System#currentTimeMillis()} to calculate uptime and recent rates; uptime is
   * clamped to at least one second, recent I/O rates fall back to {@code 0.0} when the window is
   * empty, and payload percent is {@code -1} when total output is zero. The snapshot is not atomic
   * and may mix values from adjacent instants; callers should treat it as an approximate view.
   *
   * <pre>{@code
   * SimpleFieldSet snapshot =
   *     NodeStatsFieldSetExporter.exportVolatileFieldSet(node.getNodeStats());
   * }</pre>
   *
   * @param stats source statistics holder; must be non-null and fully initialized.
   * @return a new short-lived field set containing computed snapshot values.
   */
  static SimpleFieldSet exportVolatileFieldSet(NodeStats stats) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    long now = System.currentTimeMillis();
    fs.put("isUsingWrapper", stats.node.isUsingWrapper());
    putUptime(stats, fs, now);
    putPingAndDelays(stats, fs);
    long nodeUptimeSecondsLocal = Math.max(1, (now - stats.node.getStartupTime()) / 1000);
    putNetworkSizeEstimates(stats, fs, now);
    putRoutingMissDistances(stats, fs);

    fs.put("backedOffPercent", stats.backedOffPercent.currentValue());
    fs.put("pInstantReject", stats.pRejectIncomingInstantly());
    fs.put("unclaimedFIFOSize", stats.node.network().unclaimedFifoSize());
    fs.put(
        "RAMBucketPoolSize",
        stats.node.services().clientCore().getTempBucketFactory().getRamUsed());

    /* gather connection statistics */
    PeerNodeStatus[] peerNodeStatuses = stats.peers.statusBook().getPeerNodeStatuses(true);
    int numberOfSeedServers = 0;
    int numberOfSeedClients = 0;

    for (PeerNodeStatus peerNodeStatus : peerNodeStatuses) {
      if (peerNodeStatus.isSeedServer()) numberOfSeedServers++;
      if (peerNodeStatus.isSeedClient()) numberOfSeedClients++;
    }

    int numberOfConnected =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED);
    int numberOfRoutingBackedOff =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF);
    int numberOfTooNew =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW);
    int numberOfTooOld =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD);
    int numberOfDisconnected =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTED);
    int numberOfNeverConnected =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
    int numberOfDisabled =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED);
    int numberOfBursting =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING);
    int numberOfListening =
        PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING);
    int numberOfListenOnly =
        PeerNodeStatus.getPeerStatusCount(
            peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY);

    int numberOfSimpleConnected = numberOfConnected + numberOfRoutingBackedOff;
    int numberOfNotConnected =
        numberOfTooNew
            + numberOfTooOld
            + numberOfDisconnected
            + numberOfNeverConnected
            + numberOfDisabled
            + numberOfBursting
            + numberOfListening
            + numberOfListenOnly;

    fs.put("numberOfSeedServers", numberOfSeedServers);
    fs.put("numberOfSeedClients", numberOfSeedClients);
    fs.put("numberOfConnected", numberOfConnected);
    fs.put("numberOfRoutingBackedOff", numberOfRoutingBackedOff);
    fs.put("numberOfTooNew", numberOfTooNew);
    fs.put("numberOfTooOld", numberOfTooOld);
    fs.put("numberOfDisconnected", numberOfDisconnected);
    fs.put("numberOfNeverConnected", numberOfNeverConnected);
    fs.put("numberOfDisabled", numberOfDisabled);
    fs.put("numberOfBursting", numberOfBursting);
    fs.put("numberOfListening", numberOfListening);
    fs.put("numberOfListenOnly", numberOfListenOnly);

    fs.put("numberOfSimpleConnected", numberOfSimpleConnected);
    fs.put("numberOfNotConnected", numberOfNotConnected);

    fs.put(
        "numberOfTransferringRequestSenders",
        stats.node.routing().tracker().getNumTransferringRequestSenders());
    fs.put("numberOfARKFetchers", stats.node.network().numArkFetchers());
    fs.put(
        "bandwidthLiabilityUsageOutputBulk",
        stats.node.network().stats().getBandwidthLiabilityUsage());

    RequestTracker tracker = stats.node.routing().tracker();

    fs.put("numberOfLocalCHKInserts", tracker.getNumLocalCHKInserts());
    fs.put("numberOfRemoteCHKInserts", tracker.getNumRemoteCHKInserts());
    fs.put("numberOfLocalSSKInserts", tracker.getNumLocalSSKInserts());
    fs.put("numberOfRemoteSSKInserts", tracker.getNumRemoteSSKInserts());
    fs.put("numberOfLocalCHKRequests", tracker.getNumLocalCHKRequests());
    fs.put("numberOfRemoteCHKRequests", tracker.getNumRemoteCHKRequests());
    fs.put("numberOfLocalSSKRequests", tracker.getNumLocalSSKRequests());
    fs.put("numberOfRemoteSSKRequests", tracker.getNumRemoteSSKRequests());
    fs.put(
        "numberOfTransferringRequestHandlers",
        stats.node.routing().tracker().getNumTransferringRequestHandlers());
    fs.put("numberOfCHKOfferReplys", tracker.getNumCHKOfferReplies());
    fs.put("numberOfSSKOfferReplys", tracker.getNumSSKOfferReplies());

    double[] delayValues = stats.getNlmDelaySnapshot();
    fs.put("delayTimeLocalRT", delayValues[0]);
    fs.put("delayTimeRemoteRT", delayValues[1]);
    fs.put("delayTimeLocalBulk", delayValues[2]);
    fs.put("delayTimeRemoteBulk", delayValues[3]);
    long[] slotTimeouts = stats.getSlotTimeoutSnapshot();
    // timeoutFractions = fatalTimeouts/(fatalTimeouts+allocatedSlot)
    fs.put("fatalTimeoutsLocal", slotTimeouts[0]);
    fs.put("fatalTimeoutsRemote", slotTimeouts[1]);
    fs.put("allocatedSlotLocal", slotTimeouts[2]);
    fs.put("allocatedSlotRemote", slotTimeouts[3]);

    WaitingForSlots waitingSlots = tracker.countRequestsWaitingForSlots();
    fs.put("RequestsWaitingSlotsLocal", waitingSlots.local);
    fs.put("RequestsWaitingSlotsRemote", waitingSlots.remote);

    fs.put(
        "successfulLocalCHKFetchTimeBulk",
        stats.successfulLocalCHKFetchTimeAverageBulk.currentValue());
    fs.put(
        "successfulLocalCHKFetchTimeRT", stats.successfulLocalCHKFetchTimeAverageRT.currentValue());
    fs.put(
        "unsuccessfulLocalCHKFetchTimeBulk",
        stats.unsuccessfulLocalCHKFetchTimeAverageBulk.currentValue());
    fs.put(
        "unsuccessfulLocalCHKFetchTimeRT",
        stats.unsuccessfulLocalCHKFetchTimeAverageRT.currentValue());

    fs.put(
        "successfulLocalSSKFetchTimeBulk",
        stats.successfulLocalSSKFetchTimeAverageBulk.currentValue());
    fs.put(
        "successfulLocalSSKFetchTimeRT", stats.successfulLocalSSKFetchTimeAverageRT.currentValue());
    fs.put(
        "unsuccessfulLocalSSKFetchTimeBulk",
        stats.unsuccessfulLocalSSKFetchTimeAverageBulk.currentValue());
    fs.put(
        "unsuccessfulLocalSSKFetchTimeRT",
        stats.unsuccessfulLocalSSKFetchTimeAverageRT.currentValue());

    putTotalAndRecentIOMetrics(stats, fs, nodeUptimeSecondsLocal);

    putRoutingBackoffCounters(stats, fs);

    putSwapAndStoreMetrics(stats, fs, nodeUptimeSecondsLocal);

    Runtime rt = Runtime.getRuntime();
    float freeMemory = rt.freeMemory();
    float totalMemory = rt.totalMemory();
    float maxMemory = rt.maxMemory();

    long usedJavaMem = (long) (totalMemory - freeMemory);
    long allocatedJavaMem = (long) totalMemory;
    long maxJavaMem = (long) maxMemory;
    int availableCpus = rt.availableProcessors();

    fs.put("freeJavaMemory", (long) freeMemory);
    fs.put("usedJavaMemory", usedJavaMem);
    fs.put("allocatedJavaMemory", allocatedJavaMem);
    fs.put("maximumJavaMemory", maxJavaMem);
    fs.put("availableCPUs", availableCpus);
    fs.put("runningThreadCount", stats.getActiveThreadCount());

    fs.put("globalFetchPSuccess", stats.globalFetchPSuccess.currentValue());
    fs.put("globalFetchCount", stats.globalFetchPSuccess.countReports());
    fs.put("chkLocalFetchPSuccess", stats.chkLocalFetchPSuccess.currentValue());
    fs.put("chkLocalFetchCount", stats.chkLocalFetchPSuccess.countReports());
    fs.put("chkRemoteFetchPSuccess", stats.chkRemoteFetchPSuccess.currentValue());
    fs.put("chkRemoteFetchCount", stats.chkRemoteFetchPSuccess.countReports());
    fs.put("sskLocalFetchPSuccess", stats.sskLocalFetchPSuccess.currentValue());
    fs.put("sskLocalFetchCount", stats.sskLocalFetchPSuccess.countReports());
    fs.put("sskRemoteFetchPSuccess", stats.sskRemoteFetchPSuccess.currentValue());
    fs.put("sskRemoteFetchCount", stats.sskRemoteFetchPSuccess.countReports());
    fs.put("blockTransferPSuccessRT", stats.blockTransferPSuccessRT.currentValue());
    fs.put("blockTransferCountRT", stats.blockTransferPSuccessRT.countReports());
    fs.put("blockTransferPSuccessBulk", stats.blockTransferPSuccessBulk.currentValue());
    fs.put("blockTransferCountBulk", stats.blockTransferPSuccessBulk.countReports());
    fs.put("blockTransferFailTimeout", stats.blockTransferFailTimeout.currentValue());

    return fs;
  }

  /**
   * Adds startup time and uptime seconds to the field set.
   *
   * @param stats source statistics providing the node startup time.
   * @param fs destination field set receiving uptime-related keys.
   * @param now current time in milliseconds since the epoch.
   */
  private static void putUptime(NodeStats stats, SimpleFieldSet fs, long now) {
    long nodeUptimeSeconds;
    long startupTime = stats.node.getStartupTime();
    fs.put("startupTime", startupTime);
    nodeUptimeSeconds = (now - startupTime) / 1000;
    if (nodeUptimeSeconds == 0) nodeUptimeSeconds = 1; // prevent division by zero
    fs.put("uptimeSeconds", nodeUptimeSeconds);
  }

  /**
   * Adds ping and bandwidth delay metrics to the field set.
   *
   * @param stats source statistics providing ping and delay averages.
   * @param fs destination field set receiving ping and delay keys.
   */
  private static void putPingAndDelays(NodeStats stats, SimpleFieldSet fs) {
    fs.put("averagePingTime", stats.getNodeAveragePingTime());
    fs.put("bwlimitDelayTime", stats.getBwlimitDelayTime());
    fs.put("bwlimitDelayTimeRT", stats.getBwlimitDelayTimeRT());
    fs.put("bwlimitDelayTimeBulk", stats.getBwlimitDelayTimeBulk());
  }

  /**
   * Adds the most recent network size estimate fields to the field set.
   *
   * @param stats source statistics providing dark/opennet estimates.
   * @param fs destination field set receiving estimate keys.
   * @param now current time in milliseconds since the epoch.
   */
  private static void putNetworkSizeEstimates(NodeStats stats, SimpleFieldSet fs, long now) {
    fs.put("opennetSizeEstimateSession", stats.getOpennetSizeEstimate(-1));
    fs.put("networkSizeEstimateSession", stats.getDarknetSizeEstimate(-1));
    for (int t = 1; t < 7; t++) {
      int hour = t * 24;
      long limit = now - DAYS.toMillis(t);
      fs.put("opennetSizeEstimate" + hour + "hourRecent", stats.getOpennetSizeEstimate(limit));
      fs.put("networkSizeEstimate" + hour + "hourRecent", stats.getDarknetSizeEstimate(limit));
    }
  }

  /**
   * Adds routing miss distance averages to the field set.
   *
   * @param stats source statistics holding running averages.
   * @param fs destination field set receiving routing miss fields.
   */
  private static void putRoutingMissDistances(NodeStats stats, SimpleFieldSet fs) {
    fs.put("routingMissDistanceLocal", stats.routingMissDistanceLocal.currentValue());
    fs.put("routingMissDistanceRemote", stats.routingMissDistanceRemote.currentValue());
    fs.put("routingMissDistanceOverall", stats.routingMissDistanceOverall.currentValue());
    fs.put("routingMissDistanceBulk", stats.routingMissDistanceBulk.currentValue());
    fs.put("routingMissDistanceRT", stats.routingMissDistanceRT.currentValue());
  }

  /**
   * Adds total and recent I/O counters and rates to the field set.
   *
   * @param stats source statistics providing counters and recent deltas.
   * @param fs destination field set receiving I/O-related keys.
   * @param nodeUptimeSecondsLocal uptime seconds used to normalize totals.
   */
  private static void putTotalAndRecentIOMetrics(
      NodeStats stats, SimpleFieldSet fs, long nodeUptimeSecondsLocal) {
    long[] total = stats.node.network().collector().getTotalIO();
    long totalOutputRate = (total[0]) / nodeUptimeSecondsLocal;
    long totalInputRate = (total[1]) / nodeUptimeSecondsLocal;
    long totalPayloadOutput = stats.node.getTotalPayloadSent();
    long totalPayloadOutputRate = totalPayloadOutput / nodeUptimeSecondsLocal;
    int totalPayloadOutputPercent =
        (total[0] == 0) ? -1 : (int) (100 * totalPayloadOutput / total[0]);
    fs.put("totalOutputBytes", total[0]);
    fs.put("totalOutputRate", totalOutputRate);
    fs.put("totalPayloadOutputBytes", totalPayloadOutput);
    fs.put("totalPayloadOutputRate", totalPayloadOutputRate);
    fs.put("totalPayloadOutputPercent", totalPayloadOutputPercent);
    fs.put("totalInputBytes", total[1]);
    fs.put("totalInputRate", totalInputRate);

    long[] rate = stats.getNodeIOStats();
    long deltaMS = (rate[5] - rate[2]);
    double recentOutputRate = deltaMS == 0 ? 0 : (1000.0 * (rate[3] - rate[0]) / deltaMS);
    double recentInputRate = deltaMS == 0 ? 0 : (1000.0 * (rate[4] - rate[1]) / deltaMS);
    fs.put("recentOutputRate", recentOutputRate);
    fs.put("recentInputRate", recentInputRate);

    fs.put("ackOnlyBytes", stats.getNotificationOnlyPacketsSentBytes());
    fs.put("resentBytes", stats.getResendBytesSent());
    fs.put("updaterOutputBytes", stats.getUOMBytesSent());
    fs.put("announcePayloadBytes", stats.getAnnounceBytesPayloadSent());
    fs.put("announceSentBytes", stats.getAnnounceBytesSent());
  }

  /**
   * Adds routing backoff reason counters for real-time and bulk traffic.
   *
   * @param stats source statistics exposing backoff reason snapshots.
   * @param fs destination field set receiving reason count fields.
   */
  private static void putRoutingBackoffCounters(NodeStats stats, SimpleFieldSet fs) {
    String[] routingBackoffReasons = stats.peers.getPeerNodeRoutingBackoffReasons(true);
    for (String routingBackoffReason : routingBackoffReasons) {
      fs.put(
          "numberWithRoutingBackoffReasonsRT." + routingBackoffReason,
          stats.peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, true));
    }

    routingBackoffReasons = stats.peers.getPeerNodeRoutingBackoffReasons(false);
    for (String routingBackoffReason : routingBackoffReasons) {
      fs.put(
          "numberWithRoutingBackoffReasonsBulk." + routingBackoffReason,
          stats.peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, false));
    }
  }

  /**
   * Adds swap, location-change, and store/cache metrics to the field set.
   *
   * @param stats source statistics providing node swap and store counters.
   * @param fs destination field set receiving swap and store keys.
   * @param nodeUptimeSecondsLocal uptime seconds used to normalize rates.
   */
  private static void putSwapAndStoreMetrics(
      NodeStats stats, SimpleFieldSet fs, long nodeUptimeSecondsLocal) {
    double swaps = stats.node.network().swaps();
    double noSwaps = stats.node.network().noSwaps();
    double numberOfRemotePeerLocationsSeenInSwaps =
        stats.node.network().numberOfRemotePeerLocationsSeenInSwaps();
    fs.put("numberOfRemotePeerLocationsSeenInSwaps", numberOfRemotePeerLocationsSeenInSwaps);
    double avgConnectedPeersPerNode = 0.0;
    if ((numberOfRemotePeerLocationsSeenInSwaps > 0.0) && ((swaps > 0.0) || (noSwaps > 0.0))) {
      avgConnectedPeersPerNode = numberOfRemotePeerLocationsSeenInSwaps / (swaps + noSwaps);
    }
    fs.put("avgConnectedPeersPerNode", avgConnectedPeersPerNode);

    int startedSwaps = stats.node.network().startedSwaps();
    int swapsRejectedAlreadyLocked = stats.node.network().swapsRejectedAlreadyLocked();
    int swapsRejectedNowhereToGo = stats.node.network().swapsRejectedNowhereToGo();
    int swapsRejectedRateLimit = stats.node.network().swapsRejectedRateLimit();
    int swapsRejectedRecognizedID = stats.node.network().swapsRejectedRecognizedID();
    double locationChangePerSession = stats.node.network().locationChangeSession();
    double locationChangePerSwap = 0.0;
    double locationChangePerMinute = 0.0;
    double swapsPerMinute = 0.0;
    double noSwapsPerMinute = 0.0;
    double swapsPerNoSwaps = 0.0;
    if (swaps > 0) {
      locationChangePerSwap = locationChangePerSession / swaps;
    }
    if ((swaps > 0.0) && (nodeUptimeSecondsLocal >= 60)) {
      locationChangePerMinute = locationChangePerSession / (nodeUptimeSecondsLocal / 60.0);
    }
    if ((swaps > 0.0) && (nodeUptimeSecondsLocal >= 60)) {
      swapsPerMinute = swaps / (nodeUptimeSecondsLocal / 60.0);
    }
    if ((noSwaps > 0.0) && (nodeUptimeSecondsLocal >= 60)) {
      noSwapsPerMinute = noSwaps / (nodeUptimeSecondsLocal / 60.0);
    }
    if ((swaps > 0.0) && (noSwaps > 0.0)) {
      swapsPerNoSwaps = swaps / noSwaps;
    }
    fs.put("locationChangePerSession", locationChangePerSession);
    fs.put("locationChangePerSwap", locationChangePerSwap);
    fs.put("locationChangePerMinute", locationChangePerMinute);
    fs.put("swapsPerMinute", swapsPerMinute);
    fs.put("noSwapsPerMinute", noSwapsPerMinute);
    fs.put("swapsPerNoSwaps", swapsPerNoSwaps);
    fs.put("swaps", swaps);
    fs.put("noSwaps", noSwaps);
    fs.put("startedSwaps", startedSwaps);
    fs.put("swapsRejectedAlreadyLocked", swapsRejectedAlreadyLocked);
    fs.put("swapsRejectedNowhereToGo", swapsRejectedNowhereToGo);
    fs.put("swapsRejectedRateLimit", swapsRejectedRateLimit);
    fs.put("swapsRejectedRecognizedID", swapsRejectedRecognizedID);
    long fix32kb = 32L * 1024;
    long cachedKeys = stats.node.storage().getChkDatacache().keyCount();
    long cachedSize = cachedKeys * fix32kb;
    long storeKeys = stats.node.storage().getChkDatastore().keyCount();
    long storeSize = storeKeys * fix32kb;
    long overallKeys = cachedKeys + storeKeys;
    long overallSize = cachedSize + storeSize;

    long maxOverallKeys = stats.node.getMaxTotalKeys();
    long maxOverallSize = maxOverallKeys * fix32kb;

    double percentOverallKeysOfMax = (double) (overallKeys * 100) / (double) maxOverallKeys;

    long cachedStoreHits = stats.node.storage().getChkDatacache().hits();
    long cachedStoreMisses = stats.node.storage().getChkDatacache().misses();
    long cachedStoreWrites = stats.node.storage().getChkDatacache().writes();
    long cacheAccesses = cachedStoreHits + cachedStoreMisses;
    long cachedStoreFalsePositives = stats.node.storage().getChkDatacache().getBloomFalsePositive();
    double percentCachedStoreHitsOfAccesses =
        (double) (cachedStoreHits * 100) / (double) cacheAccesses;
    long storeHits = stats.node.storage().getChkDatastore().hits();
    long storeMisses = stats.node.storage().getChkDatastore().misses();
    long storeWrites = stats.node.storage().getChkDatastore().writes();
    long storeFalsePositives = stats.node.storage().getChkDatastore().getBloomFalsePositive();
    long storeAccesses = storeHits + storeMisses;
    double percentStoreHitsOfAccesses = (double) (storeHits * 100) / (double) storeAccesses;
    long overallAccesses = storeAccesses + cacheAccesses;
    double avgStoreAccessRate = (double) overallAccesses / (double) nodeUptimeSecondsLocal;

    fs.put("cachedKeys", cachedKeys);
    fs.put("cachedSize", cachedSize);
    fs.put("storeKeys", storeKeys);
    fs.put("storeSize", storeSize);
    fs.put("overallKeys", overallKeys);
    fs.put("overallSize", overallSize);
    fs.put("maxOverallKeys", maxOverallKeys);
    fs.put("maxOverallSize", maxOverallSize);
    fs.put("percentOverallKeysOfMax", percentOverallKeysOfMax);
    fs.put("cachedStoreHits", cachedStoreHits);
    fs.put("cachedStoreMisses", cachedStoreMisses);
    fs.put("cachedStoreWrites", cachedStoreWrites);
    fs.put("cacheAccesses", cacheAccesses);
    fs.put("cachedStoreFalsePositives", cachedStoreFalsePositives);
    fs.put("percentCachedStoreHitsOfAccesses", percentCachedStoreHitsOfAccesses);
    fs.put("storeHits", storeHits);
    fs.put("storeMisses", storeMisses);
    fs.put("storeAccesses", storeAccesses);
    fs.put("storeWrites", storeWrites);
    fs.put("storeFalsePositives", storeFalsePositives);
    fs.put("percentStoreHitsOfAccesses", percentStoreHitsOfAccesses);
    fs.put("overallAccesses", overallAccesses);
    fs.put("avgStoreAccessRate", avgStoreAccessRate);
  }
}
