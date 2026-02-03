package network.crypta.node.probe;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.io.comm.AsyncMessageFilterCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.node.Location;
import network.crypta.node.Node;
import network.crypta.node.OpennetManager;
import network.crypta.node.PeerNode;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.LongCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles starting, routing, and responding to probes corrected via the Metropolis–Hastings
 * algorithm.
 *
 * <p>This component provides a small, privacy-aware request/response mechanism that samples
 * characteristics of remote peers without exposing the initiating node. A probe is created with a
 * hops-to-live (HTL) value and a {@code Type}, then forwarded through the network using
 * Metropolis–Hastings correction to achieve a more uniform endpoint distribution. When forwarding
 * is not possible or HTL reaches zero, the current node may produce a local response if allowed by
 * configuration. Results cover operational metrics such as output bandwidth limit, uptime
 * percentages, datastore size, link-length statistics, location, build number, and selected
 * rejection statistics.
 *
 * <p>Typical usage is:
 *
 * <ol>
 *   <li>Construct a {@code Probe} with the running {@code Node} instance.
 *   <li>Call {@link #start(byte, long, Type, Listener)} with an appropriate HTL and a listener.
 *   <li>Await exactly one result or a terminal error callback on the listener.
 * </ol>
 *
 * <p>Concurrency and rate-limiting: incoming probes are accepted per peer using a short rolling
 * window; a background {@link java.util.Timer} releases slots after a minute. Local responses may
 * be delayed by a small randomized wait to obscure whether a reply was produced locally at HTL=1.
 * Thread-safety for acceptance is achieved with a synchronized map guarding per-peer counters.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>HTL decrements probabilistically at {@code HTL==1} to protect the responding node.
 *   <li>Forwarding attempts are bounded; timeouts scale with HTL.
 *   <li>Returned measurements incorporate small multiplicative noise to reduce identifiability.
 * </ul>
 *
 * @see <a href=
 *     "https://en.wikipedia.org/wiki/Metropolis%E2%80%93Hastings_algorithm">Metropolis–Hastings
 *     algorithm</a>
 */
public class Probe implements ByteCounter {
  private static final Logger LOG = LoggerFactory.getLogger(Probe.class);

  private static final String SOURCE_DISCONNECT =
      "Previous step in probe chain no longer connected.";

  private static final String IDENTIFIER_KEY = "identifier";

  /**
   * Maximum hops‑to‑live (HTL) value to which inbound and locally originated probe requests are
   * clamped.
   *
   * <p>Requests specifying an HTL greater than this limit are interpreted at this bound before any
   * routing occurs. This prevents excessively long walks and limits exposure while preserving
   * meaningful sampling depth on large networks.
   */
  public static final byte MAX_HTL = 70;

  /**
   * Maximum number of forwarding attempts before giving up and reporting a forwarding failure.
   *
   * <p>The routing loop bounds the number of candidate selections to avoid pathological retries
   * when the Metropolis–Hastings correction repeatedly rejects peers or when connectivity is
   * transient. When the cap is reached, the listener receives {@code CANNOT_FORWARD}.
   */
  public static final int MAX_SEND_ATTEMPTS = 50;

  /**
   * Probability that HTL decrements at {@code HTL==1} rather than forwarding.
   *
   * <p>This small chance protects the responding node by avoiding deterministic behavior at the
   * final hop while keeping the overall walk length distribution stable.
   */
  public static final float DECREMENT_PROBABILITY = 0.2f;

  /**
   * Per‑hop timeout contribution, in milliseconds, for {@code HTL > 1}.
   *
   * <p>The overall timeout budget scales approximately linearly with HTL, and this constant anchors
   * that scaling for hops above the last probabilistic step.
   */
  public static final long TIMEOUT_PER_HTL = SECONDS.toMillis(3);

  /**
   * Timeout component, in milliseconds, to account for the probabilistic decrement at {@code
   * HTL==1}.
   *
   * <p>Because the final hop does not always forward, its timing characteristics differ from the
   * simple per‑hop budget. This value expands the last‑hop allowance accordingly.
   */
  public static final long TIMEOUT_HTL1 = (long) (TIMEOUT_PER_HTL / DECREMENT_PROBABILITY);

  /**
   * Mean of the exponential jitter (milliseconds) applied to local responses at {@code HTL==1}.
   *
   * <p>The randomized delay obscures whether a reply was produced locally or after another hop. The
   * generated wait is truncated by {@link #WAIT_MAX} to cap end‑to‑end latency.
   */
  public static final long WAIT_BASE = SECONDS.toMillis(1);

  /**
   * Upper bound (milliseconds) for randomized waits before emitting a response.
   *
   * <p>Used with {@link #WAIT_BASE} to limit the exponential jitter range. Prevents excessive
   * latency while still masking local responses effectively.
   */
  public static final long WAIT_MAX = SECONDS.toMillis(2);

  /**
   * Per‑peer acceptance limit for probe requests within a rolling minute.
   *
   * <p>Incoming requests exceeding this threshold are rejected with {@code OVERLOAD}. This setting
   * protects resources and improves fairness across connected peers.
   */
  public static final int COUNTER_MAX_PEER = 10;

  /**
   * The maximum number of probes started locally in the past minute. This is the maximum
   * conceivable value; the probes should be used with a number of requests per minute closer to the
   * per-peer limit times the minimum expected number of peers. Around this value, and certainly
   * above it, remote OVERLOADs may start coming in, which are not useful. The Metropolis-Hastings
   * correction makes behavior potentially inconsistent, so keeping an eye on remote OVERLOADs is
   * wise.
   */
  public static final int COUNTER_MAX_LOCAL =
      COUNTER_MAX_PEER * OpennetManager.MAX_PEERS_FOR_SCALING;

  /** Number of accepted probes at the last minute, keyed by peer. */
  private final Map<PeerNode, Counter> accepted;

  private final Node node;

  private final Timer timer;

  // Whether to respond to different types of probe requests.
  private volatile boolean respondBandwidth;
  private volatile boolean respondBuild;
  private volatile boolean respondIdentifier;
  private volatile boolean respondLinkLengths;
  private volatile boolean respondLocation;
  private volatile boolean respondStoreSize;
  private volatile boolean respondUptime;
  private volatile boolean respondRejectStats;
  private volatile boolean respondOverallBulkOutputCapacityUsage;

  private volatile long probeIdentifier;

  /**
   * Applies multiplicative Gaussian noise of mean 1.0 and the specified sigma to the input value.
   *
   * @param input Value to apply noise to.
   * @param sigma Proportion change at one standard deviation.
   * @return Value +/- Gaussian percentage.
   */
  private double randomNoise(final double input, final double sigma) {
    return node.network().stats().randomNoise(input, sigma);
  }

  /**
   * Counts as probe request transfer.
   *
   * @param bytes Bytes received.
   */
  @Override
  public void sentBytes(int bytes) {
    node.network().stats().probeRequestCtr.sentBytes(bytes);
  }

  /**
   * Counts as probe request transfer.
   *
   * @param bytes Bytes received.
   */
  @Override
  public void receivedBytes(int bytes) {
    node.network().stats().probeRequestCtr.receivedBytes(bytes);
  }

  /**
   * No payload in probes.
   *
   * @param bytes Ignored.
   */
  @Override
  public void sentPayload(int bytes) {
    // Intentionally empty: probes carry no payload.
  }

  /**
   * Creates a new probe helper bound to a running {@code Node} instance.
   *
   * <p>The instance reads configuration keys under the {@code node} section to determine which
   * probe types are permitted to respond locally, initializes a per-peer acceptance map used for
   * short-term rate limiting, and starts a daemon {@link Timer} used to release acceptance slots.
   *
   * @param node the owning node that provides configuration, routing, statistics, and randomness;
   *     must be a live instance for forwarding and response generation
   */
  public Probe(final Node node) {
    this.node = node;
    this.accepted = Collections.synchronizedMap(new HashMap<>());
    this.timer = new Timer(true);

    int sortOrder = 0;
    final SubConfig nodeConfig = node.getConfig().get("node");

    nodeConfig.register(
        "probeBandwidth",
        true,
        new Option.Meta(
            sortOrder++, true, true, "Node.probeBandwidthShort", "Node.probeBandwidthLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return respondBandwidth;
          }

          @Override
          public void set(Boolean val) {
            respondBandwidth = val;
          }
        });
    respondBandwidth = nodeConfig.getBoolean("probeBandwidth");
    nodeConfig.register(
        "probeBuild",
        true,
        new Option.Meta(sortOrder++, true, true, "Node.probeBuildShort", "Node.probeBuildLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return respondBuild;
          }

          @Override
          public void set(Boolean val) {
            respondBuild = val;
          }
        });
    respondBuild = nodeConfig.getBoolean("probeBuild");
    nodeConfig.register(
        "probeIdentifier",
        true,
        new Option.Meta(
            sortOrder++,
            true,
            true,
            "Node.probeRespondIdentifierShort",
            "Node.probeRespondIdentifierLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return respondIdentifier;
          }

          @Override
          public void set(Boolean val) {
            respondIdentifier = val;
          }
        });
    respondIdentifier = nodeConfig.getBoolean("probeIdentifier");
    nodeConfig.register(
        "probeLinkLengths",
        true,
        new Option.Meta(
            sortOrder++, true, true, "Node.probeLinkLengthsShort", "Node.probeLinkLengthsLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return respondLinkLengths;
          }

          @Override
          public void set(Boolean val) {
            respondLinkLengths = val;
          }
        });
    respondLinkLengths = nodeConfig.getBoolean("probeLinkLengths");
    nodeConfig.register(
        "probeLocation",
        true,
        new Option.Meta(
            sortOrder++, true, true, "Node.probeLocationShort", "Node.probeLocationLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return respondLocation;
          }

          @Override
          public void set(Boolean val) {
            respondLocation = val;
          }
        });
    respondLocation = nodeConfig.getBoolean("probeLocation");
    nodeConfig.register(
        "probeStoreSize",
        true,
        new Option.Meta(
            sortOrder++, true, true, "Node.probeStoreSizeShort", "Node.probeStoreSizeLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return respondStoreSize;
          }

          @Override
          public void set(Boolean val) {
            respondStoreSize = val;
          }
        });
    respondStoreSize = nodeConfig.getBoolean("probeStoreSize");
    nodeConfig.register(
        "probeUptime",
        true,
        new Option.Meta(sortOrder++, true, true, "Node.probeUptimeShort", "Node.probeUptimeLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return respondUptime;
          }

          @Override
          public void set(Boolean val) {
            respondUptime = val;
          }
        });
    respondUptime = nodeConfig.getBoolean("probeUptime");
    nodeConfig.register(
        "probeRejectStats",
        true,
        new Option.Meta(
            sortOrder++, true, true, "Node.probeRejectStatsShort", "Node.probeRejectStatsLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return respondRejectStats;
          }

          @Override
          public void set(Boolean val) {
            respondRejectStats = val;
          }
        });
    respondRejectStats = nodeConfig.getBoolean("probeRejectStats");

    nodeConfig.register(
        "probeOverallBulkOutputCapacityUsage",
        true,
        new Option.Meta(
            sortOrder++,
            true,
            true,
            "Node.respondOverallBulkOutputCapacityUsage",
            "Node.respondOverallBulkOutputCapacityUsageLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return respondOverallBulkOutputCapacityUsage;
          }

          @Override
          public void set(Boolean val) {
            respondOverallBulkOutputCapacityUsage = val;
          }
        });
    respondOverallBulkOutputCapacityUsage =
        nodeConfig.getBoolean("probeOverallBulkOutputCapacityUsage");

    nodeConfig.register(
        IDENTIFIER_KEY,
        -1,
        new Option.Meta(
            sortOrder, true, true, "Node.probeIdentifierShort", "Node.probeIdentifierLong"),
        new LongCallback() {
          @Override
          public Long get() {
            return probeIdentifier;
          }

          @Override
          public void set(Long val) {
            probeIdentifier = val;
            // -1 is reserved for picking a random value; don't pick it randomly.
            while (probeIdentifier == -1) probeIdentifier = node.bootstrap().random().nextLong();
          }
        },
        false);
    probeIdentifier = nodeConfig.getLong(IDENTIFIER_KEY);

    /*
     * set() is not used when setting up an option with its default value, thus do so manually to avoid using
     * an identifier of -1.
     */
    try {
      if (probeIdentifier == -1) {
        nodeConfig.getOption(IDENTIFIER_KEY).setValue("-1");
        node.getConfig().store();
      }
    } catch (InvalidConfigValueException | NodeNeedRestartException e) {
      LOG.error("node.identifier set() unexpectedly threw.", e);
    }
  }

  /**
   * Sends an outgoing probe request.
   *
   * <p>The request is created with the provided HTL and {@code Type} and routed using
   * Metropolis–Hastings correction. The {@code listener} receives at most one terminal callback: a
   * successful result for the requested type, or an error/refusal. HTL values outside the supported
   * range are clamped or rejected according to protocol rules.
   *
   * <pre>{@code
   * // Example: request the remote output bandwidth class
   * probe.start((byte) 5, 12345L, Type.BANDWIDTH, listener);
   * }</pre>
   *
   * @param htl hop budget for the request; valid range is 1..{@link #MAX_HTL}; values above the
   *     maximum are interpreted as {@link #MAX_HTL}
   * @param uid an application-provided opaque identifier echoed by responses for correlation; treat
   *     as unique per outstanding probe
   * @param type the kind of probe to run; selects which metric the remote endpoint should return
   * @param listener callback interface that receives exactly one terminal response or error; must
   *     be non-null and thread-safe if shared
   * @see Listener
   */
  public void start(final byte htl, final long uid, final Type type, final Listener listener) {
    request(DMT.createProbeRequest(htl, uid, type), null, listener);
  }

  /**
   * Processes an incoming probe request and relays results back to the source.
   *
   * <p>If the probe has a positive HTL, it is forwarded using Metropolis–Hastings correction and
   * may probabilistically decrement at HTL=1. If HTL reaches zero (or forwarding fails), the node
   * may produce a local response depending on its configuration. A single result or a terminal
   * error is emitted via the internal relay listener.
   *
   * <ul>
   *   <li>Unique identifier and 7‑day uptime percentage
   *   <li>48‑hour or 7‑day uptime percentage
   *   <li>Output bandwidth
   *   <li>Store size
   *   <li>Link lengths
   *   <li>Location
   *   <li>Build number
   * </ul>
   *
   * @param message probe request message containing HTL and type metadata; must be well-formed
   * @param source peer from which the request was received; {@code null} when locally originated
   */
  public void request(Message message, PeerNode source) {
    request(message, source, new ResultRelay(source, message.getLong(DMT.UID)));
  }

  /**
   * Processes a probe request, calling the listener with any results.
   *
   * @param source node from which the probe request was received. If null, it is considered to have
   *     been sent by the local node.
   * @param listener listener for probe response.
   */
  private void request(final Message message, final PeerNode source, final Listener listener) {
    final long uid = message.getLong(DMT.UID);
    final Type type = resolveTypeOrSendError(message, listener);
    if (type == null) return;

    byte htl = normalizeHtlOrReturnSentinel(message, source);
    if (htl == Byte.MIN_VALUE) return;

    final TimerTask releaseTask = acquireSlotOrSendOverload(source, listener);
    if (releaseTask == null) return;

    // One-minute window on acceptance; free up this probe slot in 60 seconds.
    timer.schedule(releaseTask, MINUTES.toMillis(1));

    /*
     * Route to a peer, using Metropolis-Hastings correction and ignoring backoff to get a more uniform
     * endpoint distribution. HTL is decremented before routing so that it's possible to respond locally without
     * attempting to route first. Send a local response if HTL is zero now or becomes zero while trying to route.
     * During routing HTL decrements if a candidate is rejected by the Metropolis-Hastings correction.
     */
    htl = probabilisticDecrement(htl);
    if (htl == 0 || !route(type, uid, htl, listener)) {
      long wait = WAIT_MAX;
      while (wait >= WAIT_MAX)
        wait = (long) (-Math.log(node.bootstrap().random().nextDouble()) * WAIT_BASE / Math.E);
      timer.schedule(
          new TimerTask() {
            @Override
            public void run() {
              respond(type, listener);
            }
          },
          wait);
    }
  }

  private Type resolveTypeOrSendError(final Message message, final Listener listener) {
    final byte typeCode = message.getByte(DMT.TYPE);
    if (Type.isValid(typeCode)) {
      final Type type = Type.valueOf(typeCode);
      LOG.trace("Probe type is {}.", type.name());
      return type;
    }
    LOG.debug("Invalid probe type {}.", typeCode);
    listener.onError(Error.UNRECOGNIZED_TYPE, typeCode, true);
    return null;
  }

  private byte normalizeHtlOrReturnSentinel(final Message message, final PeerNode source) {
    byte htl = message.getByte(DMT.HTL);
    if (htl < 1) {
      if (LOG.isWarnEnabled()) {
        LOG.warn(
            "Received out-of-bounds HTL of {} from {} ({}); discarding.",
            htl,
            source.getIdentityString(),
            source.userToString());
      }
      return Byte.MIN_VALUE;
    } else if (htl > MAX_HTL) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Received out-of-bounds HTL of {} from {} ({}); interpreting as {}.",
            htl,
            source.getIdentityString(),
            source.userToString(),
            MAX_HTL);
      }
      return MAX_HTL;
    }
    return htl;
  }

  private TimerTask acquireSlotOrSendOverload(final PeerNode source, final Listener listener) {
    final Counter counter;
    synchronized (accepted) {
      if (!accepted.containsKey(source)) {
        accepted.put(source, new Counter(source == null ? COUNTER_MAX_LOCAL : COUNTER_MAX_PEER));
      }
      counter = accepted.get(source);
      if (counter.value() < counter.maxAccepted) {
        counter.increment();
        return new TimerTask() {
          @Override
          public void run() {
            synchronized (accepted) {
              counter.decrement();
              if (counter.value() == 0) {
                accepted.remove(source);
              }
            }
          }
        };
      }
    }
    if (LOG.isTraceEnabled())
      LOG.trace("Already accepted maximum number of probes; rejecting incoming.");
    listener.onError(Error.OVERLOAD, null, true);
    return null;
  }

  /**
   * Attempts to route the message to a peer. If the maximum number of sending attempts is exceeded,
   * it fails with the error CANNOT_FORWARD.
   *
   * @return True if no further action needed; false if HTL decremented to zero and a local response
   *     is needed.
   */
  private boolean route(final Type type, final long uid, byte htl, final Listener listener) {
    // Recreate the request so that any sub-messages or unintended fields are not forwarded.
    final Message message = DMT.createProbeRequest(htl, uid, type);
    for (int sendAttempts = 0; sendAttempts < MAX_SEND_ATTEMPTS; sendAttempts++) {
      final PeerNode[] peers = node.network().connectedPeers();
      final int degree = peers.length;
      if (handleNoPeers(degree, listener)) return true;

      final PeerNode candidate = peers[node.bootstrap().random().nextInt(degree)];
      if (!candidate.isConnected()) {
        LOG.debug("Peer in connectedPeers was not connected.");
        continue;
      }

      final float acceptProbability = acceptProbability(degree, candidate.getDegree());
      LOG.trace("acceptProbability is {}", acceptProbability);
      if (node.bootstrap().random().nextFloat() < acceptProbability) {
        LOG.trace("Accepted candidate.");
        if (trySendToCandidate(candidate, type, uid, htl, message, listener)) {
          return true;
        }
        // Else: the candidate disconnected during send/filter; try again.
      } else {
        htl = probabilisticDecrement(htl);
        if (htl == 0) return false;
      }
    }

    LOG.warn("Aborting probe request: send attempt limit reached.");
    listener.onError(Error.CANNOT_FORWARD, null, true);
    return true;
  }

  private boolean handleNoPeers(final int degree, final Listener listener) {
    if (degree != 0) return false;
    LOG.debug("Aborting probe request: no connections.");
    listener.onError(Error.DISCONNECTED, null, true);
    return true;
  }

  private float acceptProbability(final int localDegree, final int candidateDegree) {
    if (candidateDegree == 0) return 1.0f;
    return (float) localDegree / candidateDegree;
  }

  private boolean trySendToCandidate(
      final PeerNode candidate,
      final Type type,
      final long uid,
      final byte htl,
      final Message message,
      final Listener listener) {
    final MessageFilter filter = createResponseFilter(type, candidate, uid, htl);
    message.set(DMT.HTL, htl);
    try {
      node.network().usm().addAsyncFilter(filter, new ResultListener(listener), this);
      LOG.trace("Sending.");
      candidate.transport().sendAsync(message, null, this);
      return true;
    } catch (NotConnectedException e) {
      LOG.debug("Peer became disconnected between check and send attempt.", e);
    } catch (DisconnectedException e) {
      LOG.debug("Peer became disconnected while attempting to add filter.", e);
    }
    return false;
  }

  /**
   * @param type probe result type requested.
   * @param candidate node to filter for response from.
   * @param uid probe request uid, also to be used in any result.
   * @param htl the current probe HTL; used to calculate timeout.
   * @return filter for the requested result type, probe error, and probe refusal.
   */
  private static MessageFilter createResponseFilter(
      final Type type, final PeerNode candidate, final long uid, final byte htl) {
    final long timeout = (htl - 1) * TIMEOUT_PER_HTL + TIMEOUT_HTL1;
    final MessageFilter filter = createFilter(candidate, uid, timeout);

    switch (type) {
      case BANDWIDTH -> filter.setType(DMT.ProbeBandwidth);
      case BUILD -> filter.setType(DMT.ProbeBuild);
      case IDENTIFIER -> filter.setType(DMT.ProbeIdentifier);
      case LINK_LENGTHS -> filter.setType(DMT.ProbeLinkLengths);
      case LOCATION -> filter.setType(DMT.ProbeLocation);
      case STORE_SIZE -> filter.setType(DMT.ProbeStoreSize);
      case UPTIME_48H, UPTIME_7D -> filter.setType(DMT.ProbeUptime);
      case REJECT_STATS -> filter.setType(DMT.ProbeRejectStats);
      case OVERALL_BULK_OUTPUT_CAPACITY_USAGE ->
          filter.setType(DMT.ProbeOverallBulkOutputCapacityUsage);
      default -> throw new UnsupportedOperationException("Missing filter for " + type.name());
    }

    // Refusal or an error should also be listened for so it can be relayed.
    filter.or(
        createFilter(candidate, uid, timeout)
            .setType(DMT.ProbeRefused)
            .or(createFilter(candidate, uid, timeout).setType(DMT.ProbeError)));

    return filter;
  }

  private static MessageFilter createFilter(
      final PeerNode source, final long uid, final long timeout) {
    return MessageFilter.create().setSource(source).setField(DMT.UID, uid).setTimeout(timeout);
  }

  /**
   * Depending on node settings, sends a message to the source containing either a refusal or the
   * requested result.
   */
  private void respond(final Type type, final Listener listener) {

    if (!respondTo(type)) {
      listener.onRefused();
      return;
    }

    /*
     * This adds noise to the results to make information less identifiable. The goal is to make it difficult
     * to determine which value a node actually has; that any given value could mean a small range of common
     * values. Different result types have different sigma values such that one sigma contains multiple
     * reasonable values.
     */
    switch (type) {
      /*
       * 5% noise:
       * Reasonable output bandwidth limit is 20 KiB, and people are likely to set limits in increments
       * of 1 KiB. 1 KiB / 20 KiB = 0.05 sigma.
       * 1,024 (2^10) bytes per KiB.
       */
      case BANDWIDTH ->
          listener.onOutputBandwidth(
              (float)
                  randomNoise((double) node.network().outputBandwidthLimit() / (1 << 10), 0.05));
      case BUILD -> listener.onBuild(node.services().nodeUpdater().getMainVersion());
      case IDENTIFIER -> {
        /*
         * 5% noise:
         * Reasonable uptime percentage is at least ~40 hours a week, or ~20%. This uptime is
         *  quantized, so only something above a full percentage point (0.01 * 168 hours = 1.68 hours) of
         * change will be guaranteed (from a percentage with a decimal component close to zero) to be
         * reflected. 1% / 20% = 0.05 sigma.
         *
         * 7-day uptime with random noise, then quantized. Quantization is to make it very, very
         * difficult to get useful information out of any given result because it is included with an
         * identifier.
         */
        long percent =
            Math.round(randomNoise(100 * node.network().uptimeEstimator().getUptimeWeek(), 0.05));
        // Clamp to byte.
        if (percent > Byte.MAX_VALUE) percent = Byte.MAX_VALUE;
        else if (percent < Byte.MIN_VALUE) percent = Byte.MIN_VALUE;
        listener.onIdentifier(probeIdentifier, (byte) percent);
      }
      case LINK_LENGTHS -> {
        PeerNode[] peers = node.network().connectedPeers();
        float[] linkLengths = new float[peers.length];
        int i = 0;
        /*
         * 1% noise:
         * Link lengths are in the range [0.0, 0.5], and any change is enough to make the
         * match not exact between locations. Taking as an example a link length of 0.2. and with the
         * assumption that a change of 0.002 is enough to make it still useful for statistics but not
         * useful for identification, 0.002 change / 0.2 link length = 0.01 sigma.
         */
        double myLoc = node.network().location();
        for (PeerNode peer : peers) {
          double peerLoc = peer.getLocation();
          if (Location.isValid(peerLoc)) {
            linkLengths[i++] = (float) randomNoise(Location.distance(myLoc, peerLoc), 0.01);
          }
        }
        linkLengths = Arrays.copyOf(linkLengths, i);
        Arrays.sort(linkLengths);
        listener.onLinkLengths(linkLengths);
      }
      case LOCATION -> listener.onLocation((float) node.network().location());
      /*
       * 5% noise:
       * Reasonable datastore size is 20 GiB, and size is likely set in, at most, increments of 1 GiB.
       * 1 GiB / 20 GiB = 0.05 sigma.
       * 1,073,741,824 bytes (2^30) per GiB.
       */
      case STORE_SIZE ->
          listener.onStoreSize((float) randomNoise((double) node.getStoreSize() / (1 << 30), 0.05));
      /*
       * 8% noise:
       * Continuing with the assumption that reasonable weekly uptime is around 40 hours, this allows
       * for 6 hours per day, 12 hours per 48 hours, or 25%. A half-hour seems enough
       * ambiguity, so 0.5 hours / 48 hours ~= 1%, and 1% / 25% = 0.04 sigma.
       */
      case UPTIME_48H ->
          listener.onUptime(
              (float) randomNoise(100 * node.network().uptimeEstimator().getUptime(), 0.04));
      /*
       * 2.4% noise:
       * As a 168-hour uptime covers a longer period, 1 hour of ambiguity seems enough.
       * 1 hour / 168 hours ~= 0.6%, and 0.6% / 20% = 0.03 sigma.
       */
      case UPTIME_7D ->
          listener.onUptime(
              (float) randomNoise(100 * node.network().uptimeEstimator().getUptimeWeek(), 0.03));
      case REJECT_STATS -> {
        byte[] stats = node.network().stats().getNoisyRejectStats();
        listener.onRejectStats(stats);
      }
      case OVERALL_BULK_OUTPUT_CAPACITY_USAGE -> {
        byte bandwidthClass =
            DMT.bandwidthClassForCapacityUsage(node.network().outputBandwidthLimit());
        listener.onOverallBulkOutputCapacity(
            bandwidthClass,
            (float) randomNoise(node.network().stats().getBandwidthLiabilityUsage(), 0.1));
      }
      default -> throw new UnsupportedOperationException("Missing response for " + type.name());
    }
  }

  private boolean respondTo(Type type) {
    return switch (type) {
      case BANDWIDTH -> respondBandwidth;
      case BUILD -> respondBuild;
      case IDENTIFIER -> respondIdentifier;
      case LINK_LENGTHS -> respondLinkLengths;
      case LOCATION -> respondLocation;
      case STORE_SIZE -> respondStoreSize;
      case UPTIME_48H, UPTIME_7D -> respondUptime;
      case REJECT_STATS -> respondRejectStats;
      case OVERALL_BULK_OUTPUT_CAPACITY_USAGE -> respondOverallBulkOutputCapacityUsage;
    };
  }

  /**
   * Decrements 20% of the time at HTL 1; otherwise always. This is to protect the responding node,
   * whereas the anonymity of the node which initiated the request is not a concern.
   *
   * @param htl current HTL
   * @return new HTL
   */
  private byte probabilisticDecrement(byte htl) {
    assert htl > 0;
    if (htl == 1) {
      if (node.bootstrap().random().nextFloat() < DECREMENT_PROBABILITY) return 0;
      return 1;
    }
    return (byte) (htl - 1);
  }

  /**
   * Filter listener which determines the type of result and calls the appropriate probe listener
   * method.
   */
  @SuppressWarnings("ClassCanBeRecord")
  private static class ResultListener implements AsyncMessageFilterCallback {

    private final Listener listener;

    /**
     * @param listener to call appropriate methods for events such as matched messages or timeout.
     */
    public ResultListener(Listener listener) {
      this.listener = listener;
    }

    @Override
    public void onDisconnect(PeerContext context) {
      if (LOG.isTraceEnabled()) LOG.trace("Next node in chain disconnected.");
      listener.onError(Error.DISCONNECTED, null, true);
    }

    /**
     * Parses provided a message and called the appropriate "Probe.Listener" method for the type of
     * result.
     *
     * @param message Probe result.
     */
    @Override
    public void onMatched(Message message) {
      LOG.trace("Matched {}", message.getSpec().getName());
      if (message.getSpec().equals(DMT.ProbeBandwidth)) {
        listener.onOutputBandwidth(message.getFloat(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT));
      } else if (message.getSpec().equals(DMT.ProbeBuild)) {
        listener.onBuild(message.getInt(DMT.BUILD));
      } else if (message.getSpec().equals(DMT.ProbeIdentifier)) {
        listener.onIdentifier(
            message.getLong(DMT.PROBE_IDENTIFIER), message.getByte(DMT.UPTIME_PERCENT));
      } else if (message.getSpec().equals(DMT.ProbeLinkLengths)) {
        listener.onLinkLengths(message.getFloatArray(DMT.LINK_LENGTHS));
      } else if (message.getSpec().equals(DMT.ProbeLocation)) {
        listener.onLocation(message.getFloat(DMT.LOCATION));
      } else if (message.getSpec().equals(DMT.ProbeStoreSize)) {
        listener.onStoreSize(message.getFloat(DMT.STORE_SIZE));
      } else if (message.getSpec().equals(DMT.ProbeUptime)) {
        listener.onUptime(message.getFloat(DMT.UPTIME_PERCENT));
      } else if (message.getSpec().equals(DMT.ProbeRejectStats)) {
        listener.onRejectStats(message.getShortBufferBytes(DMT.REJECT_STATS));
      } else if (message.getSpec().equals(DMT.ProbeOverallBulkOutputCapacityUsage)) {
        listener.onOverallBulkOutputCapacity(
            message.getByte(DMT.OUTPUT_BANDWIDTH_CLASS), message.getFloat(DMT.CAPACITY_USAGE));
      } else if (message.getSpec().equals(DMT.ProbeError)) {
        final byte rawError = message.getByte(DMT.TYPE);
        if (Error.isValid(rawError)) {
          listener.onError(Error.valueOf(rawError), null, false);
        } else {
          // Not recognized locally.
          listener.onError(Error.UNKNOWN, rawError, false);
        }
      } else if (message.getSpec().equals(DMT.ProbeRefused)) {
        listener.onRefused();
      } else {
        throw new UnsupportedOperationException(
            "Missing handling for " + message.getSpec().getName());
      }
    }

    @Override
    public void onRestarted(PeerContext context) {
      // Intentionally empty: no special handling needed on restart for probes.
    }

    @Override
    public void onTimeout() {
      if (LOG.isTraceEnabled()) LOG.trace("Timed out.");
      listener.onError(Error.TIMEOUT, null, true);
    }

    @Override
    public boolean shouldTimeout() {
      return false;
    }
  }

  /**
   * Listener which relays responses to the node specified during construction. Used for received
   * probe requests. This leads to reconstructing the messages but removes potentially harmful
   * sub-messages and also removes the need for duplicate message sending code elsewhere, If the
   * result includes a trace, this would be the place to add local results to it.
   */
  private class ResultRelay implements Listener {

    private final PeerNode source;
    private final Long uid;

    /**
     * @param source peer from which the request was received and to which send the response.
     * @throws IllegalArgumentException if a source is null.
     */
    public ResultRelay(PeerNode source, Long uid) {
      this.source = source;
      this.uid = uid;
    }

    private void send(Message message) {
      if (!source.isConnected()) {
        if (LOG.isDebugEnabled()) LOG.debug(SOURCE_DISCONNECT);
        return;
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug("Relaying {} back to {}", message.getSpec().getName(), source.userToString());
      }
      try {
        source.transport().sendAsync(message, null, Probe.this);
      } catch (NotConnectedException e) {
        if (LOG.isDebugEnabled()) LOG.debug(SOURCE_DISCONNECT, e);
      }
    }

    @Override
    public void onError(Error error, Byte code, boolean local) {
      send(DMT.createProbeError(uid, error));
    }

    @Override
    public void onRefused() {
      send(DMT.createProbeRefused(uid));
    }

    @Override
    public void onOutputBandwidth(float outputBandwidth) {
      send(DMT.createProbeBandwidth(uid, outputBandwidth));
    }

    @Override
    public void onBuild(int build) {
      send(DMT.createProbeBuild(uid, build));
    }

    @Override
    public void onIdentifier(long identifier, byte uptimePercentage) {
      send(DMT.createProbeIdentifier(uid, identifier, uptimePercentage));
    }

    @Override
    public void onLinkLengths(float[] linkLengths) {
      send(DMT.createProbeLinkLengths(uid, linkLengths));
    }

    @Override
    public void onLocation(float location) {
      send(DMT.createProbeLocation(uid, location));
    }

    @Override
    public void onStoreSize(float storeSize) {
      send(DMT.createProbeStoreSize(uid, storeSize));
    }

    @Override
    public void onUptime(float uptimePercentage) {
      send(DMT.createProbeUptime(uid, uptimePercentage));
    }

    @Override
    public void onRejectStats(byte[] stats) {
      if (stats.length < 4) {
        LOG.warn("Unknown length for stats: {}", stats.length);
        onError(Error.UNKNOWN, Error.UNKNOWN.code, true);
      } else {
        if (stats.length > 4) stats = Arrays.copyOf(stats, 4);
        send(DMT.createProbeRejectStats(uid, stats));
      }
    }

    @Override
    public void onOverallBulkOutputCapacity(
        byte bandwidthClassForCapacityUsage, float capacityUsage) {
      send(
          DMT.createProbeOverallBulkOutputCapacityUsage(
              uid, bandwidthClassForCapacityUsage, capacityUsage));
    }
  }
}
