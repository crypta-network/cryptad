package network.crypta.node;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.compat.BandwidthIndicator;
import network.crypta.compat.DetectedIP;
import network.crypta.compat.ExternalIpDetector;
import network.crypta.compat.PortForwardProvider;
import network.crypta.config.BooleanCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.StringCallback;
import network.crypta.config.SubConfig;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.alerts.IPUndetectedUserAlert;
import network.crypta.runtime.alerts.InvalidAddressOverrideUserAlert;
import network.crypta.runtime.alerts.SimpleUserAlert;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.spi.ConnectivityNoticeSnapshot;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.NativeThread;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import network.crypta.support.transport.ip.IPAddressDetector;
import network.crypta.support.transport.ip.IPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Detects the node's public IP address.
 *
 * <p>This component aggregates multiple sources to infer the current externally visible IP address
 * for the node, independent of any specific port. Sources include:
 *
 * <ul>
 *   <li>Local interface inspection via {@link IPAddressDetector}
 *   <li>External detector reports (e.g., STUN) via {@link IPDetectorManager}
 *   <li>Peer observations (what connected peers report)
 *   <li>User-provided overrides and temporary hints
 * </ul>
 *
 * <p>Port-specific detection (opennet/darknet) is handled by {@link NodeIPPortDetector} and is
 * outside the scope of this class.
 */
public class NodeIPDetector {
  private static final Logger LOG = LoggerFactory.getLogger(NodeIPDetector.class);
  private static final String IN_CONFIG = " in config: ";

  /** Parent {@link Node} that owns this detector. */
  final Node node;

  /** Explicit forced IP address set by configuration. */
  FreenetInetAddress overrideIPAddress;

  /**
   * String form of the explicit IP override. Retained even when invalid so the UI can surface the
   * exact value supplied by the user.
   */
  String overrideIPAddressString;

  /** Whether configuration allows binding to localhost addresses. */
  volatile boolean allowBindToLocalhost;

  /** Previously used IP address, if any. */
  FreenetInetAddress oldIPAddress;

  /** Public addresses and NAT characteristics reported by external detectors. */
  DetectedIP[] externalDetectedIPs;

  /** Most recent detection result (may contain multiple candidates). */
  FreenetInetAddress[] lastIPAddress;

  private static class MinimumMTU {

    /** The minimum reported MTU on all detected interfaces. */
    private int minMtu = Integer.MAX_VALUE;

    /**
     * Reports an MTU observed on an interface or by a detector.
     *
     * <p>If this lowers the running minimum, the method returns {@code true}.
     */
    boolean report(int mtu) {
      if (mtu <= 0) return false;
      if (mtu < minMtu) {
        // Log the previous minimum; the new minimum is applied below.
        LOG.info("Reduce MTU; previous minimum={}", minMtu);
        minMtu = mtu;
        return true;
      }
      return false;
    }

    public int get() {
      return minMtu > 0 ? minMtu : 1500;
    }
  }

  private final MinimumMTU minimumMTUIPv4 = new MinimumMTU();
  private final MinimumMTU minimumMTUIPv6 = new MinimumMTU();

  /** Low-level IP address detector for local interfaces. */
  private final IPAddressDetector ipDetector;

  /** Manages external IP detectors (for example, STUN). */
  final IPDetectorManager ipDetectorManager;

  /** UserAlert shown when {@code ipAddressOverride} has invalid hostname or IP syntax. */
  private final InvalidAddressOverrideUserAlert invalidAddressOverrideAlert;

  private volatile boolean hasValidAddressOverride;

  /** UserAlert shown when no usable IP address can be detected. */
  private final IPUndetectedUserAlert primaryIPUndetectedAlert;

  // Note: Potentially redundant; see lastIPAddress
  FreenetInetAddress[] lastIP;

  /** Set when there is evidence that the node may be behind a symmetric NAT. */
  boolean maybeSymmetric;

  /** Whether external detectors have completed (or none are present). */
  private boolean hasDetectedDetectors;

  /** Whether local interfaces and peers have been queried for address inference. */
  private boolean hasDetectedIAD;

  /** Subsidiary detectors that consume the primary address for port-specific checks. */
  private NodeIPPortDetector[] portDetectors;

  private boolean hasValidIP;
  private boolean firstDetection = true;

  SimpleUserAlert maybeSymmetricAlert;

  /**
   * Creates a detector bound to the given node.
   *
   * @param node the owning {@link Node}; must not be {@code null}
   */
  public NodeIPDetector(Node node) {
    this.node = node;
    ipDetectorManager = new IPDetectorManager(node, this);
    ipDetector = new IPAddressDetector(SECONDS.toMillis(10), this);
    invalidAddressOverrideAlert = new InvalidAddressOverrideUserAlert(node);
    primaryIPUndetectedAlert = new IPUndetectedUserAlert(node);
    portDetectors = new NodeIPPortDetector[0];
  }

  /**
   * Registers a {@link NodeIPPortDetector} that depends on the primary address.
   *
   * <p>Thread-safe. Call before starting detection to ensure the detector receives initial updates.
   *
   * @param detector the dependent detector instance
   */
  public synchronized void addPortDetector(NodeIPPortDetector detector) {
    portDetectors = Arrays.copyOf(portDetectors, portDetectors.length + 1);
    portDetectors[portDetectors.length - 1] = detector;
  }

  /**
   * Notifies external port-forward providers about changes in the public interface port set.
   *
   * @param ports current set of public interface ports to announce
   */
  public void notifyPortChange(Set<network.crypta.compat.ForwardPort> ports) {
    ipDetectorManager.notifyPortChange(ports);
  }

  /**
   * Detects the current primary IP address candidates.
   *
   * <p>Combines local interface detection, external detector reports, peer inference, and
   * configuration overrides. The result may contain multiple addresses when more than one source is
   * plausible.
   *
   * @param dumpLocalAddresses when {@code true}, filters out non-routable entries unless they are
   *     explicit hostnames; otherwise returns all candidates
   * @return an array of candidate addresses in precedence order (never {@code null})
   */
  FreenetInetAddress[] detectPrimaryIPAddress(boolean dumpLocalAddresses) {
    boolean addedValidIP = false;
    LOG.debug("Redetect IP addresses");
    ArrayList<FreenetInetAddress> addresses = new ArrayList<>();

    addedValidIP |= addOverrideIfPresent(addresses);

    if (!node.network().dontDetect()) {
      addedValidIP |= innerDetect(addresses);
    }

    updateValidIPAndAlerts(addedValidIP);

    lastIPAddress = addresses.toArray(new FreenetInetAddress[0]);
    if (dumpLocalAddresses) {
      return filterLocalAddresses(lastIPAddress);
    }
    return lastIPAddress;
  }

  private boolean addOverrideIfPresent(List<FreenetInetAddress> addresses) {
    boolean addedValidIP = false;
    if (overrideIPAddress != null) {
      // If the IP is overridden and the override is valid, the override has to be the first
      // element. overrideIPAddress will be null if the override is invalid
      addresses.add(overrideIPAddress);
      if (overrideIPAddress.isRealInternetAddress(false, true, allowBindToLocalhost)) {
        addedValidIP = true;
      }
    }
    return addedValidIP;
  }

  private void updateValidIPAndAlerts(boolean addedValidIP) {
    if (node.services().clientCore() == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Client core not initialized");
      synchronized (this) {
        hasValidIP = addedValidIP;
      }
      return;
    }

    boolean hadValidIP = computeAndSetValidityForAlert(addedValidIP);
    if (hadValidIP == addedValidIP) {
      return;
    }
    if (addedValidIP) {
      if (LOG.isDebugEnabled()) LOG.debug("Valid primary address available");
      onAddedValidIP();
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("No valid primary address");
      onNotAddedValidIP();
    }
  }

  private boolean computeAndSetValidityForAlert(boolean addedValidIP) {
    boolean hadValidIP;
    synchronized (this) {
      hadValidIP = hasValidIP;
      hasValidIP = addedValidIP;
      if (firstDetection) {
        hadValidIP = !addedValidIP;
        firstDetection = false;
      }
    }
    return hadValidIP;
  }

  private FreenetInetAddress[] filterLocalAddresses(FreenetInetAddress[] addresses) {
    ArrayList<FreenetInetAddress> filtered = new ArrayList<>(addresses.length);
    for (FreenetInetAddress addr : addresses) {
      if (addr == null) continue;
      if ((Objects.equals(addr, overrideIPAddress) && addr.hasHostnameNoIP())
          || IPUtil.isValidAddress(addr.getAddress(), false)) {
        filtered.add(addr);
      }
    }
    return filtered.toArray(new FreenetInetAddress[0]);
  }

  private void onAddedValidIP() {
    node.services().clientCore().getAlerts().unregister(primaryIPUndetectedAlert);
    node.network().onAddedValidIP();
  }

  private void onNotAddedValidIP() {
    node.services().clientCore().getAlerts().register(primaryIPUndetectedAlert);
  }

  /**
   * Core of the IP detection algorithm.
   *
   * @param addresses destination list; appends candidate addresses in precedence order
   * @return whether a routable Internet address was added to {@code addresses}
   */
  private boolean innerDetect(List<FreenetInetAddress> addresses) {
    boolean addedValidIP = false;
    InetAddress[] detectedAddrs = getDirectDetectionsAndMarkDetected();

    addedValidIP |= addDirectDetections(addresses, detectedAddrs);
    addedValidIP |= addExternalDetections(addresses);

    boolean hadAddedValidIP = addedValidIP;
    PeerInferenceResult peers = inferFromPeers(addresses, detectedAddrs);
    addedValidIP |= peers.addedValidIP;

    // Add the old address only if we have no choice, or if we only have the word of two peers to go
    // on.
    if (!(hadAddedValidIP || peers.confidence > 2)
        && (oldIPAddress != null)
        && !oldIPAddress.equals(overrideIPAddress)) {
      addresses.add(oldIPAddress);
      // Don't set addedValidIP: there is an excellent chance that this is out of date.
    }

    return addedValidIP;
  }

  private InetAddress[] getDirectDetectionsAndMarkDetected() {
    InetAddress[] detectedAddrs = ipDetector.getAddressNoCallback();
    assert (detectedAddrs != null);
    synchronized (this) {
      hasDetectedIAD = true;
    }
    return detectedAddrs;
  }

  private boolean addDirectDetections(
      List<FreenetInetAddress> addresses, InetAddress[] detectedAddrs) {
    boolean addedValidIP = false;
    for (InetAddress detectedAddr : detectedAddrs) {
      FreenetInetAddress addr = new FreenetInetAddress(detectedAddr);
      if (!addresses.contains(addr)) {
        LOG.info("Direct detection returns address {}", addr);
        addresses.add(addr);
        if (addr.isRealInternetAddress(false, false, false)) addedValidIP = true;
      }
    }
    return addedValidIP;
  }

  private boolean addExternalDetections(List<FreenetInetAddress> addresses) {
    boolean addedValidIP = false;
    if (externalDetectedIPs == null) return false;
    for (DetectedIP detectedIp : externalDetectedIPs) {
      InetAddress addr = detectedIp.publicAddress;
      if (addr == null) continue;
      FreenetInetAddress a = new FreenetInetAddress(addr);
      if (!addresses.contains(a)) {
        LOG.info("External detector reports public address {}", a);
        addresses.add(a);
        if (a.isRealInternetAddress(false, false, false)) addedValidIP = true;
      }
    }
    return addedValidIP;
  }

  private record PeerInferenceResult(int confidence, boolean addedValidIP) {}

  private PeerInferenceResult inferFromPeers(
      List<FreenetInetAddress> addresses, InetAddress[] detectedAddrs) {
    if (node.network().peers() == null) return new PeerInferenceResult(0, false);

    PeerNode[] peerList = node.network().peers().myPeers();
    Map<FreenetInetAddress, Integer> countsByPeer = buildCountsByPeer(peerList);

    if (countsByPeer.isEmpty()) {
      return new PeerInferenceResult(0, false);
    }
    if (countsByPeer.size() == 1) {
      return handleSingleCount(countsByPeer, addresses);
    }
    return handleMultipleCounts(countsByPeer, addresses, detectedAddrs);
  }

  private Map<FreenetInetAddress, Integer> buildCountsByPeer(PeerNode[] peerList) {
    Map<FreenetInetAddress, Integer> countsByPeer = new HashMap<>();
    if (peerList == null) return countsByPeer;
    // Note: Could use a standard mutable int object
    for (PeerNode pn : peerList) {
      FreenetInetAddress addr = detectAddressFromPeer(pn);
      if (addr == null) continue;
      if (countsByPeer.containsKey(addr)) countsByPeer.put(addr, countsByPeer.get(addr) + 1);
      else countsByPeer.put(addr, 1);
    }
    return countsByPeer;
  }

  private FreenetInetAddress detectAddressFromPeer(PeerNode pn) {
    if (!pn.isConnected()) {
      LOG.debug("Skip peer; not connected");
      return null;
    }
    if (!pn.isRealConnection()) {
      // Only let seed server connections through. We have to trust them anyway.
      if (!(pn instanceof SeedServerPeerNode)) return null;
      LOG.debug("Skip peer; not a real connection and not a seed node: {}", pn);
    }
    LOG.debug("Evaluate peer connection for IP inference: {}", pn);
    Peer p = pn.getRemoteDetectedPeer();
    LOG.debug("Peer's remote-detected descriptor: {}", p);
    if (p == null || p.isNull()) return null;
    FreenetInetAddress addr = p.getFreenetAddress();
    LOG.debug("Peer-provided address: {}", addr);
    if (addr == null) return null;
    InetAddress peerAddress = addr.getAddress(false);
    if (peerAddress == null || !IPUtil.isValidAddress(peerAddress, false)) {
      LOG.debug("Ignore peer address; not a valid Internet address");
      return null;
    }
    LOG.debug("Peer {} reports our address {}", pn.getPeer(), addr);
    return addr;
  }

  private PeerInferenceResult handleSingleCount(
      Map<FreenetInetAddress, Integer> countsByPeer, List<FreenetInetAddress> addresses) {
    Entry<FreenetInetAddress, Integer> countByPeer = countsByPeer.entrySet().iterator().next();
    FreenetInetAddress addr = countByPeer.getKey();
    int confidence = countByPeer.getValue();
    LOG.debug("Everyone agrees we are {}", addr);
    boolean addedValidIP = false;
    if (!addresses.contains(addr)) {
      if (addr.isRealInternetAddress(false, false, false)) addedValidIP = true;
      addresses.add(addr);
    }
    return new PeerInferenceResult(confidence, addedValidIP);
  }

  private PeerInferenceResult handleMultipleCounts(
      Map<FreenetInetAddress, Integer> countsByPeer,
      List<FreenetInetAddress> addresses,
      InetAddress[] detectedAddrs) {
    TopTwo top = selectTopTwo(countsByPeer);
    boolean addedValidIP = false;
    int confidence = 0;
    if (shouldUseBest(top, detectedAddrs)) {
      addedValidIP |= addAddressIfAbsent(addresses, top.best, "best peer", top.bestPopularity);
      confidence = top.bestPopularity;
      addedValidIP |= maybeAddSecondBest(top, addresses);
    }
    return new PeerInferenceResult(confidence, addedValidIP);
  }

  private record TopTwo(
      FreenetInetAddress best,
      int bestPopularity,
      FreenetInetAddress secondBest,
      int secondBestPopularity) {}

  private TopTwo selectTopTwo(Map<FreenetInetAddress, Integer> countsByPeer) {
    FreenetInetAddress best = null;
    FreenetInetAddress secondBest = null;
    int bestPopularity = 0;
    int secondBestPopularity = 0;
    for (Map.Entry<FreenetInetAddress, Integer> entry : countsByPeer.entrySet()) {
      FreenetInetAddress cur = entry.getKey();
      int curPop = entry.getValue();
      LOG.debug("Peer-inferred address {} votes {}", cur, curPop);
      if (curPop >= bestPopularity) {
        secondBestPopularity = bestPopularity;
        bestPopularity = curPop;
        secondBest = best;
        best = cur;
      }
    }
    return new TopTwo(best, bestPopularity, secondBest, secondBestPopularity);
  }

  private boolean hasAnyRealDetectedAddress(InetAddress[] detectedAddrs) {
    for (InetAddress detectedAddr : detectedAddrs) {
      if (IPUtil.isValidAddress(detectedAddr, false)) return true;
    }
    return false;
  }

  private boolean shouldUseBest(TopTwo top, InetAddress[] detectedAddrs) {
    return top.best != null
        && (top.bestPopularity > 1 || !hasAnyRealDetectedAddress(detectedAddrs));
  }

  private boolean maybeAddSecondBest(TopTwo top, List<FreenetInetAddress> addresses) {
    if (top.secondBest == null || top.secondBestPopularity <= 1) return false;
    return addAddressIfAbsent(
        addresses, top.secondBest, "second best peer", top.secondBestPopularity);
  }

  private boolean addAddressIfAbsent(
      List<FreenetInetAddress> addresses, FreenetInetAddress addr, String label, int popularity) {
    if (addresses.contains(addr)) return false;
    LOG.debug("Add {} {} (votes={})", label, addr, popularity);
    addresses.add(addr);
    return addr.isRealInternetAddress(false, false, false);
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("NodeIPDetector." + key);
  }

  @SuppressWarnings("SameParameterValue")
  FreenetInetAddress[] getPrimaryIPAddress(boolean dumpLocal) {
    if (lastIPAddress == null) return detectPrimaryIPAddress(dumpLocal);
    return lastIPAddress;
  }

  public boolean hasDirectlyDetectedIP() {
    InetAddress[] addrs = ipDetector.getAddress(node.network().executor());
    for (InetAddress addr : addrs) {
      if (IPUtil.isValidAddress(addr, false)) {
        if (LOG.isDebugEnabled()) LOG.debug("Direct detection available: {}", addr);
        return true;
      }
    }
    return false;
  }

  /**
   * Processes detections reported by external detectors.
   *
   * <p>Each {@link DetectedIP} may include the public address and an MTU estimate. This method
   * updates MTU minima and triggers an address re-detection.
   *
   * @param list detection results; {@code null} entries are ignored
   */
  public void processDetectedIPs(DetectedIP[] list) {
    externalDetectedIPs = list;
    for (DetectedIP detectedIp : externalDetectedIPs) {
      reportMTU(detectedIp.getMtu(), detectedIp.publicAddress instanceof Inet6Address);
    }
    redetectAddress();
  }

  /**
   * Reports an observed MTU.
   *
   * @param mtu the observed MTU in bytes; values {@code <= 0} are ignored
   * @param forIPv6 whether the MTU applies to IPv6 (otherwise IPv4)
   */
  public void reportMTU(int mtu, boolean forIPv6) {
    boolean mtuChanged = false;
    if (forIPv6) mtuChanged |= minimumMTUIPv6.report(mtu);
    else mtuChanged |= minimumMTUIPv4.report(mtu);

    if (mtuChanged) node.network().updateMTU();
  }

  /**
   * Re-runs primary address detection and notifies dependent port detectors when the result
   * changes.
   *
   * <p>Also persists the node file after updating dependent detectors.
   */
  public void redetectAddress() {
    FreenetInetAddress[] newIP = detectPrimaryIPAddress(false);
    NodeIPPortDetector[] detectors;
    synchronized (this) {
      if (Arrays.equals(newIP, lastIP)) return;
      lastIP = newIP;
      detectors = portDetectors;
    }
    for (NodeIPPortDetector detector : detectors) detector.update();
    node.writeNodeFile();
  }

  /**
   * Sets a previously used address as a hint for inference when peer evidence is limited.
   *
   * @param freenetAddress the historical address to consider
   */
  public void setOldIPAddress(FreenetInetAddress freenetAddress) {
    this.oldIPAddress = freenetAddress;
  }

  /**
   * Registers configuration keys relevant to IP detection and initializes state from the config.
   *
   * <p>Keys: {@code ipAddressOverride}, {@code tempIPAddressHint}, and {@code
   * allowBindToLocalhost}.
   *
   * @param nodeConfig the configuration section
   * @param sortOrder the current sort order for settings
   * @return the next sort order value after registration
   */
  public int registerConfigs(SubConfig nodeConfig, int sortOrder) {
    sortOrder = registerIpAddressOverride(nodeConfig, sortOrder);
    sortOrder = registerTempIpAddressHint(nodeConfig, sortOrder);
    sortOrder = registerAllowBindToLocalhost(nodeConfig, sortOrder);
    return sortOrder;
  }

  private int registerIpAddressOverride(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "ipAddressOverride",
        "",
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "NodeIPDectector.ipOverride",
            "NodeIPDectector.ipOverrideLong"),
        new IpOverrideCallback());

    initIpAddressOverride(nodeConfig);
    return sortOrder;
  }

  private class IpOverrideCallback extends StringCallback {

    @Override
    public String get() {
      return overrideIPAddressString == null ? "" : overrideIPAddressString;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      boolean hadValidAddressOverride = hasValidAddressOverride();
      // Note: External notifications (if any) are handled elsewhere
      if (val.isEmpty()) {
        // Set to null
        overrideIPAddressString = val;
        overrideIPAddress = null;
        // Clearing the override should also clear any previous invalid state, so the
        // node stops warning about a bad override after the user removes it.
        synchronized (NodeIPDetector.this) {
          hasValidAddressOverride = true;
        }
        if (!hadValidAddressOverride) {
          unregisterInvalidOverrideAlert();
        }
        lastIPAddress = null;
        redetectAddress();
        return;
      }
      FreenetInetAddress addr;
      try {
        addr = new FreenetInetAddress(val, false, true);
      } catch (HostnameSyntaxException _) {
        throw new InvalidConfigValueException(
            unknownHostError("hostname or IP address syntax error"));
      } catch (UnknownHostException e) {
        throw new InvalidConfigValueException(unknownHostError(e.getMessage()));
      }
      // Compare as IPs.
      if (addr.equals(overrideIPAddress)) return;
      overrideIPAddressString = val;
      overrideIPAddress = addr;
      lastIPAddress = null;
      synchronized (NodeIPDetector.this) {
        hasValidAddressOverride = true;
      }
      if (!hadValidAddressOverride) {
        unregisterInvalidOverrideAlert();
      }
      redetectAddress();
    }

    private String unknownHostError(String value) {
      return NodeL10n.getBase()
          .getString("NodeIPDetector.unknownHostErrorInIPOverride", "error", value);
    }

    private void unregisterInvalidOverrideAlert() {
      NodeClientCore cc = node.services().clientCore();
      if (cc == null) return;
      network.crypta.runtime.alerts.UserAlertManager alerts = cc.getAlerts();
      if (alerts == null) return;
      alerts.unregister(invalidAddressOverrideAlert);
    }
  }

  private void initIpAddressOverride(SubConfig nodeConfig) {
    hasValidAddressOverride = true;
    overrideIPAddressString = nodeConfig.getString("ipAddressOverride");
    if (overrideIPAddressString.isEmpty()) {
      overrideIPAddress = null;
      return;
    }
    try {
      overrideIPAddress = new FreenetInetAddress(overrideIPAddressString, false, true);
    } catch (HostnameSyntaxException e) {
      synchronized (this) {
        hasValidAddressOverride = false;
      }
      String msg =
          "Invalid IP override syntax: " + overrideIPAddressString + IN_CONFIG + e.getMessage();
      LOG.warn("{} — ignoring the configured IP override and starting up anyway", msg);
      overrideIPAddress = null;
    } catch (UnknownHostException e) {
      // This condition is unlikely with the current FreenetInetAddress constructor; kept for
      // robustness.
      String msg =
          "Unknown host in ipAddressOverride: "
              + overrideIPAddressString
              + IN_CONFIG
              + e.getMessage();
      LOG.warn("{} — starting up without an IP override", msg);
      overrideIPAddress = null;
    }
  }

  private int registerTempIpAddressHint(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "tempIPAddressHint",
        "",
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "NodeIPDectector.tempAddressHint",
            "NodeIPDectector.tempAddressHintLong"),
        new StringCallback() {

          @Override
          public String get() {
            return "";
          }

          @Override
          public void set(String val) throws InvalidConfigValueException {
            if (val.isEmpty()) {
              return;
            }
            if (overrideIPAddress != null) return;
            try {
              oldIPAddress = new FreenetInetAddress(val, false);
            } catch (UnknownHostException e) {
              throw new InvalidConfigValueException("Unknown host: " + e.getMessage());
            }
            redetectAddress();
          }
        });

    String ipHintString = nodeConfig.getString("tempIPAddressHint");
    if (!ipHintString.isEmpty()) {
      try {
        oldIPAddress = new FreenetInetAddress(ipHintString, false);
      } catch (UnknownHostException e) {
        String msg =
            "Unknown host for tempIPAddressHint: " + ipHintString + IN_CONFIG + e.getMessage();
        LOG.warn(msg);
        oldIPAddress = null;
      }
    }
    return sortOrder;
  }

  private int registerAllowBindToLocalhost(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "allowBindToLocalhost",
        false,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "NodeIPDetector.allowBindToLocalhost",
            "NodeIPDetector.allowBindToLocalhostLong"),
        BooleanCallback.from(
            () -> allowBindToLocalhost,
            value -> {
              if (!Objects.equals(allowBindToLocalhost, value)) {
                allowBindToLocalhost = value;
                throw new NodeNeedRestartException("allowBindToLocalhost needs a restart");
              }
            }));
    allowBindToLocalhost = nodeConfig.getBoolean("allowBindToLocalhost");
    return sortOrder;
  }

  /**
   * Starts background detection and schedules follow-up tasks.
   *
   * <p>Registers alerts for invalid overrides, launches the periodic IP re-detector, triggers
   * initial detection, and schedules a delayed ARK insert to avoid redundant work at startup.
   */
  public void start() {
    boolean haveValidAddressOverride = hasValidAddressOverride();
    if (!haveValidAddressOverride) {
      onNotGetValidAddressOverride();
    }
    node.network().executor().execute(ipDetector, "IP address re-detector");
    redetectAddress();
    // Delay ARK insertion by 60 seconds to limit redundant inserts when IP detection lags startup.
    // Not a FastRunnable because the insert can take a noticeable time to begin.
    node.network()
        .ticker()
        .queueTimedJob(
            new Runnable() {
              @Override
              public void run() {
                NodeIPPortDetector[] detectors;
                synchronized (this) {
                  detectors = portDetectors;
                }
                for (NodeIPPortDetector detector : detectors) detector.startARK();
              }
            },
            SECONDS.toMillis(60));
  }

  /**
   * Hints that a peer connected, prompting external detectors to run at elevated priority.
   *
   * <p>Runs asynchronously on a high-priority thread.
   */
  public void onConnectedPeer() {
    // Run off thread, but at high priority.
    // Initial messages don't need an up-to-date IP for the node itself, but
    // announcements do. However, announcements are not sent instantly.
    node.network()
        .executor()
        .execute(
            new PrioRunnable() {

              @Override
              public void run() {
                ipDetectorManager.maybeRun();
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
              }
            });
  }

  /** Registers an external IP detector. */
  public void registerExternalIpDetector(ExternalIpDetector detector) {
    ipDetectorManager.registerExternalDetector(detector);
  }

  /** Unregisters an external IP detector. */
  @SuppressWarnings("unused")
  public void unregisterExternalIpDetector(ExternalIpDetector detector) {
    ipDetectorManager.unregisterExternalDetector(detector);
  }

  /**
   * Returns whether all detection paths have completed.
   *
   * @return {@code true} when neither external nor interface detection is still pending
   */
  public synchronized boolean isDetecting() {
    return !(hasDetectedDetectors && hasDetectedIAD);
  }

  void markExternalDetectionsComplete() {
    if (LOG.isDebugEnabled()) LOG.debug("Mark external detection complete");
    synchronized (this) {
      hasDetectedDetectors = true;
    }
  }

  /**
   * Returns the minimum detected MTU for the given IP family.
   *
   * @param ipv6 {@code true} for IPv6, {@code false} for IPv4
   * @return the MTU in bytes; defaults to 1500 when unknown
   */
  public int getMinimumDetectedMTU(boolean ipv6) {
    return ipv6 ? minimumMTUIPv6.get() : minimumMTUIPv4.get();
  }

  /**
   * Returns the minimum detected MTU across IPv4 and IPv6.
   *
   * @return the MTU in bytes; defaults to 1500 when unknown
   */
  public int getMinimumDetectedMTU() {
    return Math.min(minimumMTUIPv4.get(), minimumMTUIPv6.get());
  }

  /**
   * Updates user alerts when a symmetric NAT is suspected.
   *
   * <p>If no detectors are registered, a visible {@link SimpleUserAlert} is created; otherwise any
   * existing alert is removed.
   */
  public void setMaybeSymmetric() {
    if (ipDetectorManager != null && ipDetectorManager.isEmpty()) {
      if (maybeSymmetricAlert == null) {
        maybeSymmetricAlert =
            new SimpleUserAlert(
                true,
                l10n("maybeSymmetricTitle"),
                l10n("maybeSymmetric"),
                l10n("maybeSymmetricShort"),
                UserAlert.ERROR);
      }
      if (node.services().clientCore() != null && node.services().clientCore().getAlerts() != null)
        node.services().clientCore().getAlerts().register(maybeSymmetricAlert);
    } else {
      if (maybeSymmetricAlert != null)
        node.services().clientCore().getAlerts().unregister(maybeSymmetricAlert);
    }
  }

  /** Registers a port-forward provider (for example, UPnP/NAT-PMP). */
  @SuppressWarnings("unused")
  public void registerPortForwardProvider(PortForwardProvider forward) {
    ipDetectorManager.registerPortForwardProvider(forward);
  }

  /** Unregisters a port-forward provider. */
  @SuppressWarnings("unused")
  public void unregisterPortForwardProvider(PortForwardProvider forward) {
    ipDetectorManager.unregisterPortForwardProvider(forward);
  }

  // Note: multiple instances are not supported; a single indicator is tracked.
  /**
   * Registers the active bandwidth indicator.
   *
   * @param indicator indicator instance to register
   */
  @SuppressWarnings("unused")
  public synchronized void registerBandwidthIndicator(BandwidthIndicator indicator) {
    bandwidthIndicator = indicator;
  }

  /**
   * Unregisters the active bandwidth indicator.
   *
   * @param indicator indicator instance to unregister (logged for diagnostics)
   */
  @SuppressWarnings("unused")
  public synchronized void unregisterBandwidthIndicator(BandwidthIndicator indicator) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Unregistering bandwidth indicator: {}", indicator);
    }
    bandwidthIndicator = null;
  }

  /**
   * Returns the currently registered bandwidth indicator, if any.
   *
   * @return the indicator or {@code null}
   */
  public synchronized BandwidthIndicator getBandwidthIndicator() {
    return bandwidthIndicator;
  }

  private BandwidthIndicator bandwidthIndicator;

  boolean hasValidAddressOverride() {
    synchronized (this) {
      return hasValidAddressOverride;
    }
  }

  private void onNotGetValidAddressOverride() {
    node.services().clientCore().getAlerts().register(invalidAddressOverrideAlert);
  }

  /** Adds the connection type UI box content via the detector manager. */
  @SuppressWarnings("unused")
  public void addConnectionTypeBox(HTMLNode contentNode) {
    ipDetectorManager.addConnectionTypeBox(contentNode);
  }

  /** Returns the current connection-type notice as a detached snapshot, if active. */
  public ConnectivityNoticeSnapshot connectionTypeNotice() {
    return ipDetectorManager.connectionTypeNotice();
  }

  /**
   * Returns whether no external IP detectors are currently registered.
   *
   * @return {@code true} when detection relies solely on local interfaces and peers
   */
  public boolean hasNoExternalIpDetectors() {
    return !ipDetectorManager.hasDetectors();
  }

  /** Returns whether a STUN detector is present. */
  public boolean hasStunDetector() {
    return ipDetectorManager.hasStunDetector();
  }
}
