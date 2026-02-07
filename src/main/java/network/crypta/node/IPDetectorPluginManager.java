package network.crypta.node;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MINUTES;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.clients.http.ConnectivityToadlet;
import network.crypta.clients.http.ExternalLinkToadlet;
import network.crypta.io.AddressTracker;
import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.AbstractUserAlert;
import network.crypta.node.useralerts.ProxyUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.pluginmanager.DetectedIP;
import network.crypta.pluginmanager.ForwardPort;
import network.crypta.pluginmanager.ForwardPortCallback;
import network.crypta.pluginmanager.ForwardPortStatus;
import network.crypta.pluginmanager.FredPlugin;
import network.crypta.pluginmanager.FredPluginIPDetector;
import network.crypta.pluginmanager.FredPluginPortForward;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.transport.ip.IPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates IP-detection and port-forwarding plugins and decides when to run them.
 *
 * <p>The manager aggregates {@link FredPluginIPDetector} implementations (typically one, but
 * multiple are allowed) and applies lightweight heuristics to determine when detection should be
 * executed. It also receives callbacks from {@link FredPluginPortForward} plugins and updates user
 * alerts accordingly. Long-running work executes on the node's executor; this class keeps only the
 * scheduling and aggregation logic.
 *
 * <p>Lifecycle: Call {@link #start()} once after {@code UserAlertManager} is available. The manager
 * then schedules periodic checks (every minute) and triggers detections as needed. Methods may be
 * called from different threads; internal state changes are synchronized on {@code this}.
 */
public class IPDetectorPluginManager implements ForwardPortCallback {
  private static final Logger LOG = LoggerFactory.getLogger(IPDetectorPluginManager.class);
  private static final String KEY_SUFFIX_MAYBE_FORWARDED = "MaybeForwarded";
  private static final String KEY_SUFFIX_NOT_FORWARDED = "NotForwarded";
  private static final String L10N_PORT1 = "port1";
  private static final String L10N_PORT2 = "port2";
  private static final String LOG_DETECTED_IP_PREFIX = "Detected IP: ";
  private static final String FOR_WORD = " for ";
  // Shared tail used by several port-forwarding result logs: protocol and reason string.
  private static final String PROTOCOL_AND_REASON = "{} ({})";

  /**
   * User alert that summarizes which UDP ports appear not to be forwarded.
   *
   * <p>The alert treats negative port entries as "definitely not forwarded" and non-negative
   * entries as "maybe not forwarded". It updates its priority based on the inferred NAT type and
   * the severity of forwarding issues.
   */
  public class PortForwardAlert extends AbstractUserAlert {

    private int[] portsNotForwarded;

    private short maxPriorityShown;
    private int maxPortsLength;

    @Override
    public String anchor() {
      return "port-forward:" + System.identityHashCode(this);
    }

    @Override
    public String dismissButtonText() {
      return NodeL10n.getBase().getString("UserAlert.hide");
    }

    @Override
    public HTMLNode getHTMLText() {
      HTMLNode div = new HTMLNode("div");
      String url = ExternalLinkToadlet.escape(HTMLEncoder.encode(l10n("portForwardHelpURL")));
      boolean maybeForwarded = true;
      for (int portNotForwarded : portsNotForwarded) {
        if (portNotForwarded < 0) {
          maybeForwarded = false;
          break;
        }
      }
      String keySuffix = maybeForwarded ? KEY_SUFFIX_MAYBE_FORWARDED : KEY_SUFFIX_NOT_FORWARDED;
      if (portsNotForwarded.length == 1) {
        NodeL10n.getBase()
            .addL10nSubstitution(
                div,
                "IPDetectorPluginManager.forwardPort" + keySuffix,
                new String[] {"port", "link"},
                new HTMLNode[] {HTMLNode.text(Math.abs(portsNotForwarded[0])), HTMLNode.link(url)});
      } else if (portsNotForwarded.length == 2) {
        NodeL10n.getBase()
            .addL10nSubstitution(
                div,
                "IPDetectorPluginManager.forwardTwoPorts" + keySuffix,
                new String[] {L10N_PORT1, L10N_PORT2, "link", "connectivity"},
                new HTMLNode[] {
                  HTMLNode.text(Math.abs(portsNotForwarded[0])),
                  HTMLNode.text(Math.abs(portsNotForwarded[1])),
                  HTMLNode.link(url),
                  HTMLNode.link(ConnectivityToadlet.CONNECTIVITY_PATH)
                });
      } else {
        LOG.error(
            "Port forward alert HTML skipped; unknown port count to forward ({})",
            portsNotForwarded.length);
      }
      if (innerGetPriorityClass() == UserAlert.ERROR) {
        div.addChild("#", " " + l10n("symmetricPS"));
      }
      return div;
    }

    @Override
    public short getPriorityClass() {
      return innerGetPriorityClass();
    }

    public short innerGetPriorityClass() {
      if (connectionType == DetectedIP.SYMMETRIC_NAT
          || connectionType == DetectedIP.SYMMETRIC_UDP_FIREWALL)
        // Only able to connect to directly connected / full-cone nodes.
        return UserAlert.ERROR;
      if (portsNotForwarded != null) {
        for (int portNotForwarded : portsNotForwarded)
          if (portNotForwarded < 0) return UserAlert.ERROR;
      }
      return UserAlert.MINOR;
    }

    @Override
    public String getShortText() {
      String prefix =
          innerGetPriorityClass() == UserAlert.ERROR
              ? l10n("seriousConnectionProblems")
              : l10n("connectionProblems");
      prefix += " ";
      boolean maybeForwarded = true;
      for (int portNotForwarded : portsNotForwarded) {
        if (portNotForwarded < 0) {
          maybeForwarded = false;
          break;
        }
      }
      String keySuffix = maybeForwarded ? KEY_SUFFIX_MAYBE_FORWARDED : KEY_SUFFIX_NOT_FORWARDED;
      if (portsNotForwarded.length == 1) {
        return prefix
            + l10n(
                "forwardPortShort" + keySuffix,
                "port",
                Integer.toString(Math.abs(portsNotForwarded[0])));
      } else if (portsNotForwarded.length == 2) {
        return prefix
            + l10n(
                "forwardTwoPortsShort" + keySuffix,
                new String[] {L10N_PORT1, L10N_PORT2},
                new String[] {
                  Integer.toString(Math.abs(portsNotForwarded[0])),
                  Integer.toString(Math.abs(portsNotForwarded[1]))
                });
      } else {
        LOG.error(
            "Port forward alert short text skipped; unknown port count to forward ({})",
            portsNotForwarded.length);
        return "";
      }
    }

    @Override
    public String getText() {
      String url = l10n("portForwardHelpURL");
      boolean maybeForwarded = true;
      for (int portNotForwarded : portsNotForwarded) {
        if (portNotForwarded < 0) {
          maybeForwarded = false;
          break;
        }
      }
      String keySuffix = maybeForwarded ? KEY_SUFFIX_MAYBE_FORWARDED : KEY_SUFFIX_NOT_FORWARDED;
      if (portsNotForwarded.length == 1) {
        return l10n(
            "forwardPort" + keySuffix,
            new String[] {"port", "link", "/link"},
            new String[] {Integer.toString(Math.abs(portsNotForwarded[0])), "", " (" + url + ")"});
      } else if (portsNotForwarded.length == 2) {
        return l10n(
            "forwardTwoPorts" + keySuffix,
            new String[] {L10N_PORT1, L10N_PORT2, "link", "/link"},
            new String[] {
              Integer.toString(Math.abs(portsNotForwarded[0])),
              Integer.toString(Math.abs(portsNotForwarded[1])),
              "",
              " (" + url + ")"
            });
      } else {
        LOG.error(
            "Port forward alert text skipped; unknown port count to forward ({})",
            portsNotForwarded.length);
        return "";
      }
    }

    @Override
    public String getTitle() {
      return getShortText();
    }

    @Override
    public boolean isValid() {
      portsNotForwarded = getUDPPortsNotForwarded();
      if (portsNotForwarded.length > maxPortsLength) {
        valid = true;
        maxPortsLength = portsNotForwarded.length;
      }
      short prio = innerGetPriorityClass();
      if (prio < maxPriorityShown) {
        valid = true;
        maxPriorityShown = prio;
      }
      if (portsNotForwarded.length == 0) return false;
      return valid;
    }

    @Override
    public void isValid(boolean validity) {
      valid = validity;
    }

    @Override
    public void onDismiss() {
      valid = false;
    }

    @Override
    public boolean shouldUnregisterOnDismiss() {
      return false;
    }

    @Override
    public boolean userCanDismiss() {
      return true;
    }
  }

  /**
   * Simple user alert used for connectivity summaries (no UDP, symmetric NAT, etc.).
   *
   * <p>When {@code suggestPortForward} is {@code true}, the alert appends guidance about forwarding
   * one or two UDP ports, depending on what {@link #getUDPPortsNotForwarded()} reports.
   */
  public class MyUserAlert extends AbstractUserAlert {

    final boolean suggestPortForward;
    private int[] portsNotForwarded;

    public MyUserAlert(String title, String text, boolean suggestPortForward, short code) {
      super(
          false,
          title,
          Body.of(text, title, null),
          code,
          true,
          new DismissOptions(NodeL10n.getBase().getString("UserAlert.hide"), false));
      this.suggestPortForward = suggestPortForward;
      portsNotForwarded = new int[] {};
    }

    @Override
    public HTMLNode getHTMLText() {
      HTMLNode div = new HTMLNode("div");
      div.addChild("#", super.getText());
      if (suggestPortForward) {
        if (portsNotForwarded.length == 1) {
          NodeL10n.getBase()
              .addL10nSubstitution(
                  div,
                  "IPDetectorPluginManager.suggestForwardPortWithLink",
                  new String[] {"link", "port"},
                  new HTMLNode[] {
                    HTMLNode.link(
                        ExternalLinkToadlet.escape(
                            "http://wiki.freenetproject.org/FirewallAndRouterIssues")),
                    HTMLNode.text(portsNotForwarded[0])
                  });
        } else {
          NodeL10n.getBase()
              .addL10nSubstitution(
                  div,
                  "IPDetectorPluginManager.suggestForwardTwoPortsWithLink",
                  new String[] {"link", L10N_PORT1, L10N_PORT2},
                  new HTMLNode[] {
                    HTMLNode.link(
                        ExternalLinkToadlet.escape(
                            "http://wiki.freenetproject.org/FirewallAndRouterIssues")),
                    HTMLNode.text(portsNotForwarded[0]),
                    HTMLNode.text(portsNotForwarded[1])
                  });
        }
      }
      return div;
    }

    @Override
    public String getText() {
      if (!suggestPortForward) return super.getText();
      StringBuilder sb = new StringBuilder();
      sb.append(super.getText());
      if (portsNotForwarded.length == 1) {
        sb.append(
            l10n("suggestForwardPort", "port", Integer.toString(Math.abs(portsNotForwarded[0]))));
      } else if (portsNotForwarded.length >= 2) {
        sb.append(
            l10n(
                "suggestForwardTwoPorts",
                new String[] {L10N_PORT1, L10N_PORT2},
                new String[] {
                  Integer.toString(Math.abs(portsNotForwarded[0])),
                  Integer.toString(Math.abs(portsNotForwarded[1]))
                }));
        if (portsNotForwarded.length > 2)
          LOG.error("Cannot display more than 2 ports to forward ({})", portsNotForwarded.length);
      }

      return sb.toString();
    }

    @Override
    public void isValid(boolean validity) {
      valid = validity;
    }

    @Override
    public boolean isValid() {
      portsNotForwarded = getUDPPortsNotForwarded();
      return valid && (portsNotForwarded.length > 0);
    }

    @Override
    public void onDismiss() {
      valid = false;
    }

    @Override
    public boolean userCanDismiss() {
      return false;
    }
  }

  private final NodeIPDetector detector;
  private final Node node;
  FredPluginIPDetector[] plugins;
  FredPluginPortForward[] portForwardPlugins;
  private final MyUserAlert noConnectionAlert;
  private final MyUserAlert symmetricAlert;
  private final MyUserAlert portRestrictedAlert;
  private final MyUserAlert restrictedAlert;
  private short connectionType;
  private ProxyUserAlert proxyAlert;
  private final PortForwardAlert portForwardAlert;
  private volatile boolean started;

  IPDetectorPluginManager(Node node, NodeIPDetector detector) {
    plugins = new FredPluginIPDetector[0];
    portForwardPlugins = new FredPluginPortForward[0];
    this.node = node;
    this.detector = detector;
    noConnectionAlert =
        new MyUserAlert(l10n("noConnectivityTitle"), l10n("noConnectivity"), true, UserAlert.ERROR);
    symmetricAlert =
        new MyUserAlert(l10n("symmetricTitle"), l10n("symmetric"), true, UserAlert.ERROR);
    portRestrictedAlert =
        new MyUserAlert(
            l10n("portRestrictedTitle"), l10n("portRestricted"), true, UserAlert.WARNING);
    restrictedAlert =
        new MyUserAlert(l10n("restrictedTitle"), l10n("restricted"), false, UserAlert.MINOR);
    portForwardAlert = new PortForwardAlert();
  }

  /**
   * Returns the UDP ports that appear not to be forwarded for this node.
   *
   * <p>The array contains zero, one, or two entries corresponding to the darknet and opennet ports
   * (when known). Each element encodes certainty via its sign:
   *
   * <ul>
   *   <li>Negative value: definitely not forwarded.
   *   <li>Positive value: maybe not forwarded (status is inconclusive or suggests NAT).
   * </ul>
   *
   * @return array of port numbers with sign semantics as above; never {@code null}
   */
  public int[] getUDPPortsNotForwarded() {
    OpennetManager om = node.network().opennet();
    Status darknetStatus =
        (node.network().peers().anyDarknetPeers()
            ? node.network().darknetCrypto().getDetectedConnectivityStatus()
            : AddressTracker.Status.DONT_KNOW);
    Status opennetStatus =
        om == null ? Status.DONT_KNOW : om.getCrypto().getDetectedConnectivityStatus();

    boolean opennetUnknown = (om == null) || isUnknown(opennetStatus);
    boolean darknetUnknown = isUnknown(darknetStatus);

    if (opennetUnknown) {
      if (darknetUnknown) return new int[] {};
      return new int[] {indicator(darknetStatus, node.network().darknetPortNumber())};
    }

    if (darknetUnknown) {
      return new int[] {indicator(opennetStatus, om.getCrypto().getPortNumber())};
    }

    return new int[] {
      indicator(darknetStatus, node.network().darknetPortNumber()),
      indicator(opennetStatus, om.getCrypto().getPortNumber())
    };
  }

  private static boolean isUnknown(Status status) {
    return status.compareTo(AddressTracker.Status.DONT_KNOW) >= 0;
  }

  private static int indicator(Status status, int portNumber) {
    return (status.compareTo(AddressTracker.Status.MAYBE_NATED) < 0 ? -1 : 1) * portNumber;
  }

  private static final String L10N_PREFIX = "IPDetectorPluginManager.";

  private String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  /**
   * Looks up a localized string under the manager's prefix and substitutes a single parameter.
   *
   * @param key message key (without the {@link #L10N_PREFIX} prefix)
   * @param pattern placeholder name to substitute
   * @param value replacement value for the placeholder
   * @return localized text
   */
  public String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase()
        .getString(L10N_PREFIX + key, new String[] {pattern}, new String[] {value});
  }

  /**
   * Looks up a localized string under the manager's prefix and substitutes multiple parameters.
   *
   * @param key message key (without the {@link #L10N_PREFIX} prefix)
   * @param patterns placeholder names to substitute
   * @param values replacement values for each placeholder (same order/length as {@code patterns})
   * @return localized text
   */
  public String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, patterns, values);
  }

  /**
   * Starts the manager and registers user alerts.
   *
   * <p>After this call, the manager performs an immediate detection attempt (subject to heuristics)
   * and schedules later checks at one-minute intervals.
   */
  void start() {
    // Cannot be initialized until UserAlertManager has been created.
    proxyAlert = new ProxyUserAlert(node.services().clientCore().getAlerts(), false);
    node.services().clientCore().getAlerts().register(portForwardAlert);
    started = true;
    tryMaybeRun();
  }

  /**
   * Start the plugin detection, if necessary. Either way, schedule another attempt in 1 minute's
   * time.
   */
  @SuppressWarnings("java:S1181") // Plugin boundary: contain plugin-caused Errors
  private void tryMaybeRun() {
    try {
      maybeRun();
    } catch (Throwable t) {
      LOG.error("Unhandled error during IP detection scheduling: {}", t, t);
    }
    node.network().ticker().queueTimedJob(this::tryMaybeRun, MINUTES.toMillis(1));
  }

  /**
   * Registers an IP-detection plugin.
   *
   * @param d plugin instance to register
   * @throws NullPointerException if {@code d} is {@code null}
   */
  public void registerDetectorPlugin(FredPluginIPDetector d) {
    if (d == null) throw new NullPointerException();
    synchronized (this) {
      lastDetectAttemptEndedTime = -1;
      plugins = Arrays.copyOf(plugins, plugins.length + 1);
      plugins[plugins.length - 1] = d;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Register IP detector plugin: {}", d);
    maybeRun();
  }

  /**
   * Unregisters a previously registered IP-detection plugin.
   *
   * @param d plugin instance to remove
   */
  public void unregisterDetectorPlugin(FredPluginIPDetector d) {
    DetectorRunner runningDetector;
    synchronized (this) {
      int count = 0;
      for (FredPluginIPDetector plugin : plugins) {
        if (plugin == d) count++;
      }
      if (count == 0) return;
      FredPluginIPDetector[] newPlugins = new FredPluginIPDetector[plugins.length - count];
      int x = 0;
      for (FredPluginIPDetector plugin : plugins) {
        if (plugin != d) newPlugins[x++] = plugin;
      }
      plugins = newPlugins;
      // Will be removed when returns in the DetectorRunner
      runningDetector = runners.get(d);
    }
    if (runningDetector != null) runningDetector.kill();
  }

  /* Heuristics for when to run IP detection (e.g., STUN-like probing).
   *
   * - After a failed attempt that yielded no usable IP, wait 5 minutes before retrying.
   * - If a direct (public) IP was detected and either (a) no peers are older than
   *   30 minutes or (b) we have connected to at least two distinct real-IP peers since
   *   startup, skip detection (we might still be firewalled, so this is not a hard ban).
   * - With zero peers: run at most once every 6 hours (time not persisted across restarts).
   * - With peers present: skip if detection ran within the last hour.
   * - Guard against bogus peer reports:
   *   If one or two connected peers report the same IP, other nodes have been connected
   *   recently, and this state has persisted for 2 minutes, run detection.
   * - If no connected peers with real internet addresses exist for 2 minutes, but there
   *   are disconnected peers, run detection (hourly while down) to discover a new IP.
   */

  private final HashMap<FredPluginIPDetector, DetectorRunner> runners = new HashMap<>();
  private final HashSet<FredPluginIPDetector> failedRunners = new HashSet<>();
  private long lastDetectAttemptEndedTime;
  private volatile long firstTimeUrgent;

  /**
   * Evaluates the current state and runs detection plugins when heuristics allow.
   *
   * <p>Fast, non-blocking: schedules work to the executor when a run is needed. Safe to call
   * frequently.
   */
  public void maybeRun() {
    if (!started) return;
    if (LOG.isDebugEnabled()) LOG.debug("Maybe running IP detection plugins");
    PeerNode[] peers = node.network().peerNodes();
    PeerNode[] conns = node.network().connectedPeers();
    int peerCount = node.network().peers().countValidPeers();
    FreenetInetAddress[] nodeAddrs = detector.getPrimaryIPAddress(true);
    long now = System.currentTimeMillis();

    if (switch (gateOnPluginState(now)) {
      case RETURN, START_AND_RETURN -> true;
      case PROCEED -> false;
    }) {
      return;
    }

    if (detector.hasDirectlyDetectedIP() && !shouldDetectDespiteRealIP(now, conns, nodeAddrs)) {
      return;
    }

    if (peerCount == 0) {
      if (shouldDetectNoPeers(now)) startDetect();
    } else {
      if (shouldDetectWithPeers(now, peers, conns, nodeAddrs)) startDetect();
    }
  }

  private enum GateDecision {
    RETURN,
    START_AND_RETURN,
    PROCEED
  }

  private GateDecision gateOnPluginState(long now) {
    synchronized (this) {
      if (plugins.length == 0) {
        if (LOG.isDebugEnabled()) LOG.debug("No IP detection plugins registered");
        detector.hasDetectedPM();
        return GateDecision.RETURN;
      }
      if (runners.size() == plugins.length) {
        if (LOG.isDebugEnabled()) LOG.debug("All IP detection plugins already running");
        return GateDecision.RETURN;
      }
      if (failedRunners.size() == plugins.length) {
        // If a detection attempt failed to produce an IP in the last 5 minutes, don't try again
        // yet.
        if (now - lastDetectAttemptEndedTime < MINUTES.toMillis(5)) {
          if (LOG.isDebugEnabled()) LOG.debug("Skip detect; last failure < 5 minutes ago");
          return GateDecision.RETURN;
        }
        if (LOG.isDebugEnabled()) LOG.debug("Retry detect after previous failure");
        startDetect();
        return GateDecision.START_AND_RETURN;
      }
    }
    return GateDecision.PROCEED;
  }

  /**
   * Given that we have no peers, should we run the detection plugins? Algorithm: Run the detection
   * once every 6 hours.
   *
   * @param now The time at the start of the calling method.
   * @return True if we should run detection.
   */
  private boolean shouldDetectNoPeers(long now) {
    boolean tooSoon = now - lastDetectAttemptEndedTime < HOURS.toMillis(6);
    if (tooSoon && LOG.isDebugEnabled()) {
      // No peers; throttle to once every 6 hours.
      LOG.debug("No peers; last detect < 6 hours");
    }
    // Must try once when not tooSoon
    return !tooSoon;
  }

  /**
   * Given that we have some peers, should we run the detection plugins?
   *
   * @param now The time at the beginning of the calling method.
   * @param peers The node's peers.
   * @param conns The node's connected peers.
   * @return True if we should run detection.
   */
  private boolean shouldDetectWithPeers(
      long now, PeerNode[] peers, PeerNode[] conns, FreenetInetAddress[] nodeAddrs) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Evaluate detect with peers={}, conns={}; counting eligible peers",
          peers.length,
          conns.length);

    PeerStats stats = computePeerStats(peers, nodeAddrs, now);

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Eligible peers: connected={}, disconnected={}",
          stats.realConnections,
          stats.realDisconnected);

    Decision urgentDecision = decideUrgentWhenNoConnections(stats, now);
    if (urgentDecision == Decision.TRUE) return true;

    // Always evaluate the 6-minute mass-disconnect override, even when the
    // hourly throttle would suppress an "urgent" detect decision.
    if (hasNoPeers(stats)) return shouldDetectNoPeers(now);
    if (shouldDetectAfterRecentDisconnects(stats, now)) return true;

    if (urgentDecision == Decision.FALSE) return false;

    logNotUrgent(conns, peers);

    return detector.maybeSymmetric && lastDetectAttemptEndedTime <= 0;
  }

  private boolean hasNoPeers(PeerStats stats) {
    return stats.realConnections == 0 && stats.realDisconnected == 0;
  }

  private void logNotUrgent(PeerNode[] conns, PeerNode[] peers) {
    if (LOG.isDebugEnabled())
      LOG.debug("Not urgent; connected={}, peers={}", conns.length, peers.length);
    firstTimeUrgent = 0;
  }

  private boolean shouldDetectAfterRecentDisconnects(PeerStats stats, long now) {
    return (stats.realConnections == 0
        && stats.realDisconnected > 0
        && stats.recentlyConnected > 2
        && (now - lastDetectAttemptEndedTime > MINUTES.toMillis(6)));
  }

  private enum Decision {
    TRUE,
    FALSE,
    CONTINUE
  }

  private Decision decideUrgentWhenNoConnections(PeerStats stats, long now) {
    if (!(stats.realConnections == 0 && stats.realDisconnected > 0)) {
      return Decision.CONTINUE;
    }
    if (firstTimeUrgent <= 0) firstTimeUrgent = now;
    if (hasOldIP()) {
      return decideWithOldIP(now);
    }
    return decideImmediateDetect(now);
  }

  private boolean hasOldIP() {
    return detector.oldIPAddress != null
        && detector.oldIPAddress.isRealInternetAddress(false, false, false);
  }

  private Decision decideWithOldIP(long now) {
    if (LOG.isTraceEnabled()) LOG.trace("Schedule detect in 2 minutes (oldIPAddress present)");
    if (now - firstTimeUrgent > MINUTES.toMillis(2)) {
      firstTimeUrgent = now; // Reset now rather than on the next round.
      if (LOG.isDebugEnabled()) LOG.debug("Detect now; 2 minutes elapsed (oldIPAddress present)");
      return checkHourlyThrottleDecision(now);
    }
    return Decision.FALSE;
  }

  private Decision decideImmediateDetect(long now) {
    if (LOG.isDebugEnabled()) LOG.debug("Detect now (no oldIPAddress)");
    return checkHourlyThrottleDecision(now);
  }

  private Decision checkHourlyThrottleDecision(long now) {
    if (isHourlyThrottled(now)) {
      if (LOG.isDebugEnabled()) LOG.debug("Throttle active; only once per hour");
      return Decision.FALSE;
    }
    return Decision.TRUE;
  }

  private boolean isHourlyThrottled(long now) {
    return now - lastDetectAttemptEndedTime < HOURS.toMillis(1);
  }

  private record PeerStats(int realConnections, int realDisconnected, int recentlyConnected) {}

  private PeerStats computePeerStats(PeerNode[] peers, FreenetInetAddress[] nodeAddrs, long now) {
    int realConnections = 0;
    int realDisconnected = 0;
    int recentlyConnected = 0;
    for (PeerNode p : peers) {
      if (isPeerEligible(p, nodeAddrs)) {
        boolean connected = p.isConnected();
        realConnections += connected ? 1 : 0;
        realDisconnected += connected ? 0 : 1;
        if (!connected && recentlyConnected(p, now)) recentlyConnected++;
      }
    }
    return new PeerStats(realConnections, realDisconnected, recentlyConnected);
  }

  private static boolean isRelevantPeer(PeerNode p) {
    if (p.isDisabled()) return false;
    Peer peer = p.getPeer();
    if (peer == null) return false;
    return peer.getFreenetAddress() != null;
  }

  private static boolean isPeerEligible(PeerNode p, FreenetInetAddress[] nodeAddrs) {
    if (!isRelevantPeer(p)) return false;
    FreenetInetAddress a = p.getPeer().getFreenetAddress();
    InetAddress addr = a.getAddress(false);
    return isAddrUsable(addr) && !isOurAddress(nodeAddrs, a);
  }

  private static boolean isAddrUsable(InetAddress addr) {
    // Only treat peers with a concrete, validated InetAddress as usable.
    // Peers often report null addresses transiently (e.g., on connection or IP-less transports).
    // Counting those as usable inflates real connection counts and can suppress necessary
    // detection.
    return (addr != null) && IPUtil.isValidAddress(addr, false);
  }

  private static boolean recentlyConnected(PeerNode p, long now) {
    return now - p.lastReceivedPacketTime() < MINUTES.toMillis(5);
  }

  private static boolean isOurAddress(FreenetInetAddress[] nodeAddrs, FreenetInetAddress a) {
    for (FreenetInetAddress nodeAddr : nodeAddrs) {
      if (a.equals(nodeAddr)) return true;
    }
    return false;
  }

  /**
   * Should we run the detection plugins despite having a directly detected IP address?
   *
   * @param now The time at the beginning of the calling method.
   * @param peers The node's peers.
   * @param nodeAddrs Our peers' addresses.
   * @return True if we should run detection.
   */
  private boolean shouldDetectDespiteRealIP(
      long now, PeerNode[] peers, FreenetInetAddress[] nodeAddrs) {
    // We might still be firewalled?
    // First, check only once per day or startup
    if (now - lastDetectAttemptEndedTime < HOURS.toMillis(12)) {
      if (LOG.isDebugEnabled()) LOG.debug("Skip detect; direct IP present; last check < 12 hours");
      return false;
    }

    if (LOG.isDebugEnabled()) LOG.debug("Evaluate detect despite direct IP");
    RealIPCheck check = analyzePeersForRealIP(peers, nodeAddrs, now);
    if (check.externalConnectedCount > 2) {
      if (LOG.isDebugEnabled())
        LOG.debug("Skip detect; direct IP present; connected to >=3 distinct real IPs");
      return false;
    }
    if (!check.hasOldPeers) {
      // No peers older than 30 minutes
      if (LOG.isDebugEnabled()) LOG.debug("Skip detect; peers < 30 minutes old");
      return false;
    }
    return true;
  }

  private record RealIPCheck(int externalConnectedCount, boolean hasOldPeers) {}

  private RealIPCheck analyzePeersForRealIP(
      PeerNode[] peers, FreenetInetAddress[] nodeAddrs, long now) {
    HashSet<InetAddress> addressesConnected = new HashSet<>();
    boolean hasOldPeers = false;
    for (PeerNode p : peers) {
      if (!isConnectedOrRecent(p, now)) continue;
      if (isExternalConnectedRealIP(p, nodeAddrs)) {
        addressesConnected.add(p.getPeer().getAddress(false));
      }
      if (isOldPeer(p, now)) hasOldPeers = true;
    }
    return new RealIPCheck(addressesConnected.size(), hasOldPeers);
  }

  private static boolean isConnectedOrRecent(PeerNode p, long now) {
    return p.isConnected() || (now - p.lastReceivedPacketTime() < HOURS.toMillis(24));
  }

  private static boolean isOldPeer(PeerNode p, long now) {
    long l = p.getPeerAddedTime();
    return (l <= 0) || (now - l > MINUTES.toMillis(30));
  }

  private static boolean isExternalConnectedRealIP(PeerNode p, FreenetInetAddress[] nodeAddrs) {
    if (!p.isConnected()) return false;
    Peer peer = p.getPeer();
    if (peer == null) return false;
    InetAddress addr = peer.getAddress(false);
    if (addr == null || !IPUtil.isValidAddress(peer.getAddress(), false)) return false;
    for (FreenetInetAddress nodeAddr : nodeAddrs) {
      if (addr.equals(nodeAddr.getAddress(false))) return false;
    }
    return true;
  }

  private void startDetect() {
    if (LOG.isDebugEnabled()) LOG.debug("Start IP detection");
    synchronized (this) {
      failedRunners.clear();
      for (FredPluginIPDetector plugin : plugins) {
        if (runners.containsKey(plugin)) continue;
        DetectorRunner d = new DetectorRunner(plugin);
        runners.put(plugin, d);
        node.network().executor().execute(d, "Plugin detector runner for " + plugin.getClass());
      }
    }
  }

  /**
   * Executes detection for a single plugin instance. Runs on the node executor and isolates plugin
   * failures so a misbehaving plugin cannot crash the manager.
   */
  public class DetectorRunner implements Runnable {

    final FredPluginIPDetector plugin;

    public DetectorRunner(FredPluginIPDetector detector) {
      plugin = detector;
    }

    /** Stops the underlying plugin via the plugin manager. */
    public void kill() {
      node.services().pluginManager().killPlugin((FredPlugin) plugin, 0);
    }

    @SuppressWarnings("java:S1181") // Plugin boundary: contain plugin-caused Errors
    @Override
    public void run() {
      try {
        realRun();
      } catch (Throwable t) {
        LOG.error("Unhandled error during detector runner execution: {}", t, t);
      }
    }

    /** Runs the plugin, updates alerts, and notifies the node detector. */
    public void realRun() {
      if (LOG.isDebugEnabled()) LOG.debug("Run plugin detection");
      try {
        List<DetectedIP> v = collectDetectedIPs();
        synchronized (IPDetectorPluginManager.this) {
          lastDetectAttemptEndedTime = System.currentTimeMillis();
          boolean failed = v.isEmpty() || !hasAnyValidPublicAddress(v);
          if (failed) {
            if (LOG.isDebugEnabled()) LOG.debug("No valid public IP detected");
            failedRunners.add(plugin);
            return;
          }
        }

        // Node does not know about individual interfaces, so just process the lot.
        // Note: If we use interfaces, take the most popular conclusion for each one.
        DetectedIP[] list = v.toArray(new DetectedIP[0]);
        NatCounts counts = countNatTypes(list);
        updateAlertsFromCounts(counts);
        detector.processDetectedIPs(list);
        updateNoConnectivityAlert();
      } finally {
        boolean finished;
        synchronized (IPDetectorPluginManager.this) {
          runners.remove(plugin);
          finished = runners.isEmpty();
        }
        if (finished) detector.hasDetectedPM();
      }
    }

    /** Collects the IPs reported by the plugin; shields plugin exceptions. */
    @SuppressWarnings("java:S1181") // Plugin boundary: contain plugin-caused Errors
    private List<DetectedIP> collectDetectedIPs() {
      List<DetectedIP> result = new ArrayList<>();
      try {
        DetectedIP[] detected = plugin.getAddress();
        if (detected != null) Collections.addAll(result, detected);
      } catch (Throwable t) {
        LOG.error("Unhandled error while collecting detected IPs: {}", t, t);
      }
      return result;
    }

    private boolean hasAnyValidPublicAddress(List<DetectedIP> v) {
      for (DetectedIP ip : v) {
        if (LOG.isDebugEnabled())
          LOG.debug(LOG_DETECTED_IP_PREFIX + "{}" + FOR_WORD + "{}", ip, plugin);
        if (ip.publicAddress != null && IPUtil.isValidAddress(ip.publicAddress, false)) {
          if (LOG.isDebugEnabled()) LOG.debug("Accept detected address");
          return true;
        }
      }
      if (v.isEmpty() && LOG.isDebugEnabled()) LOG.debug("No IPs found");
      return false;
    }

    private static final class NatCounts {
      int open;
      int fullCone;
      int restricted;
      int portRestricted;
      int symmetric;
      int closed;
    }

    private NatCounts countNatTypes(DetectedIP[] list) {
      NatCounts c = new NatCounts();
      for (DetectedIP d : list) {
        LOG.info(LOG_DETECTED_IP_PREFIX + "{}: type={}", d.publicAddress, d.natType);
        switch (d.natType) {
          case DetectedIP.FULL_CONE_NAT -> c.fullCone++;
          case DetectedIP.FULL_INTERNET -> c.open++;
          case DetectedIP.NO_UDP -> c.closed++;
          case DetectedIP.NOT_SUPPORTED -> {
            // Ignore
          }
          case DetectedIP.RESTRICTED_CONE_NAT -> c.restricted++;
          case DetectedIP.PORT_RESTRICTED_NAT -> c.portRestricted++;
          case DetectedIP.SYMMETRIC_NAT, DetectedIP.SYMMETRIC_UDP_FIREWALL -> c.symmetric++;
          default -> {
            // Unknown natType; ignore
          }
        }
      }
      return c;
    }

    private void updateAlertsFromCounts(NatCounts c) {
      if (c.closed > 0
          && (c.open + c.fullCone + c.restricted + c.portRestricted + c.symmetric) == 0) {
        proxyAlert.setAlert(noConnectionAlert);
        proxyAlert.isValid(true);
        connectionType = DetectedIP.NO_UDP;
      } else if (c.symmetric > 0 && (c.open + c.fullCone + c.restricted + c.portRestricted == 0)) {
        proxyAlert.setAlert(symmetricAlert);
        proxyAlert.isValid(true);
        connectionType = DetectedIP.SYMMETRIC_NAT;
      } else if (c.portRestricted > 0 && (c.open + c.fullCone + c.restricted == 0)) {
        proxyAlert.setAlert(portRestrictedAlert);
        proxyAlert.isValid(true);
        connectionType = DetectedIP.PORT_RESTRICTED_NAT;
      } else if (c.restricted > 0 && (c.open + c.fullCone == 0)) {
        proxyAlert.setAlert(restrictedAlert);
        proxyAlert.isValid(true);
        connectionType = DetectedIP.RESTRICTED_CONE_NAT;
      } else if (c.fullCone > 0 && c.open == 0) {
        proxyAlert.isValid(false);
        connectionType = DetectedIP.FULL_CONE_NAT;
      } else if (c.open > 0) {
        proxyAlert.isValid(false);
      }
    }

    private void updateNoConnectivityAlert() {
      if (connectionType == DetectedIP.NO_UDP) {
        SimpleUserAlert toRegister = null;
        synchronized (this) {
          if (noConnectivityAlert == null)
            noConnectivityAlert =
                toRegister =
                    new SimpleUserAlert(
                        false,
                        l10n("noConnectivityTitle"),
                        l10n("noConnectivity"),
                        l10n("noConnectivityShort"),
                        UserAlert.ERROR);
        }
        if (toRegister != null) node.services().clientCore().getAlerts().register(toRegister);
      } else {
        UserAlert toKill;
        synchronized (this) {
          toKill = noConnectivityAlert;
          noConnectivityAlert = null;
        }
        if (toKill != null) node.services().clientCore().getAlerts().unregister(toKill);
      }
    }
  }

  private SimpleUserAlert noConnectivityAlert;

  public synchronized boolean isEmpty() {
    return plugins.length == 0;
  }

  public void registerPortForwardPlugin(FredPluginPortForward forward) {
    if (forward == null) throw new NullPointerException();
    synchronized (this) {
      portForwardPlugins = Arrays.copyOf(portForwardPlugins, portForwardPlugins.length + 1);
      portForwardPlugins[portForwardPlugins.length - 1] = forward;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Register port forward plugin: {}", forward);
    forward.onChangePublicPorts(node.network().publicInterfacePorts(), this);
  }

  /** Remove a plugin. */
  public void unregisterPortForwardPlugin(FredPluginPortForward forward) {
    synchronized (this) {
      int count = 0;
      for (FredPluginPortForward portForwardPlugin : portForwardPlugins) {
        if (portForwardPlugin == forward) count++;
      }
      if (count == 0) return;
      FredPluginPortForward[] newPlugins =
          new FredPluginPortForward[portForwardPlugins.length - count];
      int x = 0;
      for (FredPluginPortForward portForwardPlugin : portForwardPlugins) {
        if (portForwardPlugin != forward) newPlugins[x++] = portForwardPlugin;
      }
      portForwardPlugins = newPlugins;
    }
  }

  @SuppressWarnings("java:S1181") // Plugin boundary: contain plugin-caused Errors
  void notifyPortChange(final Set<ForwardPort> newPorts) {
    FredPluginPortForward[] localPortForwardPlugins;
    synchronized (this) {
      localPortForwardPlugins = portForwardPlugins;
    }
    for (final FredPluginPortForward plugin : localPortForwardPlugins) {
      node.network()
          .executor()
          .execute(
              () -> {
                try {
                  plugin.onChangePublicPorts(newPorts, IPDetectorPluginManager.this);
                } catch (Throwable t) {
                  LOG.error("onChangePublicPorts on {} threw: {}", plugin, t, t);
                }
              },
              "Notify " + plugin + " of ports list change");
    }
  }

  /**
   * Receives results from port-forwarding plugins and logs a summarized status per port.
   *
   * <p>Triggers a follow-up detection run on the executor after processing the statuses.
   *
   * @param statuses map of ports to their latest {@link ForwardPortStatus}
   */
  @Override
  public void portForwardStatus(Map<ForwardPort, ForwardPortStatus> statuses) {
    Set<ForwardPort> currentPorts = node.network().publicInterfacePorts();
    for (ForwardPort p : currentPorts) {
      ForwardPortStatus status = statuses.get(p);
      if (status == null) continue;
      if (status.status == ForwardPortStatus.DEFINITE_SUCCESS) {
        LOG.info(
            "event=port_forward_definite_success name={} port={} for " + PROTOCOL_AND_REASON,
            p.name,
            p.portNumber,
            p.protocol,
            status.reasonString);
      } else if (status.status == ForwardPortStatus.PROBABLE_SUCCESS) {
        LOG.info(
            "event=port_forward_probable_success name={} port={} for " + PROTOCOL_AND_REASON,
            p.name,
            p.portNumber,
            p.protocol,
            status.reasonString);
      } else if (status.status == ForwardPortStatus.MAYBE_SUCCESS) {
        LOG.info(
            "event=port_forward_maybe_success name={} port={} for {}; recommend out-of-band"
                + " verification ({})",
            p.name,
            p.portNumber,
            p.protocol,
            status.reasonString);
      } else if (status.status == ForwardPortStatus.DEFINITE_FAILURE) {
        LOG.error(
            "event=port_forward_definite_failure name={} port={} for " + PROTOCOL_AND_REASON,
            p.name,
            p.portNumber,
            p.protocol,
            status.reasonString);
      } else if (status.status == ForwardPortStatus.PROBABLE_FAILURE) {
        LOG.error(
            "event=port_forward_probable_failure name={} port={} for " + PROTOCOL_AND_REASON,
            p.name,
            p.portNumber,
            p.protocol,
            status.reasonString);
      }
      // Not much more we can do / want to do for now
      // Note: status.externalPort is currently unused.
    }
    node.network().executor().execute(this::maybeRun, "Redetect IP after port forward changed");
  }

  /**
   * Returns whether at least one IP-detection plugin is registered.
   *
   * @return {@code true} if one or more detectors are present
   */
  public synchronized boolean hasDetectors() {
    return plugins.length > 0;
  }

  /**
   * Adds the connection-type alert (if active) to the given HTML container.
   *
   * <p>Precondition: {@link #start()} has been called. If not, a log entry is emitted and the
   * method returns without modifying {@code contentNode}.
   *
   * @param contentNode target container
   */
  public void addConnectionTypeBox(HTMLNode contentNode) {
    if (node.services().clientCore() == null) return;
    if (node.services().clientCore().getAlerts() == null) return;
    if (proxyAlert == null) {
      LOG.error("start() not called yet");
      return;
    }
    if (proxyAlert.isValid())
      contentNode.addChild(node.services().clientCore().getAlerts().renderAlert(proxyAlert));
  }

  /**
   * Returns whether the JSTUN plugin is loaded or in the process of loading.
   *
   * @return {@code true} if a plugin named {@code JSTUN} is active or loading
   */
  public boolean hasJSTUN() {
    return node.services().pluginManager().isPluginLoadedOrLoadingOrWantLoad("JSTUN");
  }
}
