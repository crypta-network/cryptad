package network.crypta.runtime.alerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.runtime.updater.NodeUpdateManager;
import network.crypta.support.HTMLNode;

import static java.util.concurrent.TimeUnit.DAYS;

/**
 * User-facing alert that summarizes connectivity and peer-health conditions observed by the {@link
 * network.crypta.node.PeerManager}.
 *
 * <p>This alert aggregates counters and timing metrics coming from the node and the peer manager
 * and turns them into a single short title, a longer text, and an HTML rendition that can be
 * rendered in the web user interface. Typical usage is that the peer manager updates the counters
 * via the provided setter methods whenever its internal state changes. UI code then polls the alert
 * by calling {@link #isValid()}, {@link #getPriorityClass()}, and either {@link #getText()} or
 * {@link #getHTMLText()} to decide if an alert must be displayed and with which severity.
 *
 * <p>The instance is stateful and reads supplemental values from {@link NodeStats} and {@link
 * NodeUpdateManager}. The class performs lightweight computations only; it does not start
 * background tasks or perform I/O. Methods that derive the current message snapshot synchronize on
 * {@code this} to provide a consistent view of the counters and thresholds during formatting. The
 * class itself does not enforce any life-cycle; callers are expected to keep one instance per node
 * and update it as needed.
 *
 * <ul>
 *   <li>Connectivity summary for darknet/opennet and overall peers.
 *   <li>Problem highlighting for clock skew, connection errors, and latency-related metrics.
 *   <li>Outdated build detection when auto-updating is disabled or not available.
 * </ul>
 *
 * @see network.crypta.node.PeerManager
 * @see NodeStats
 * @see NodeUpdateManager
 * @see AbstractUserAlert
 */
public class PeerManagerUserAlert extends AbstractUserAlert {
  private static final String L10N_PREFIX = "PeerManagerUserAlert.";
  private static final String PARAM_COUNT = "count";
  private static final String PARAM_MAX = "max";
  private static final String PARAM_DELAY = "delay";
  private static final String PARAM_PING = "ping";

  final NodeStats n;
  final NodeUpdateManager nodeUpdater;
  // See update() for details.
  int conns = 0;
  int peers = 0;
  int neverConn = 0;
  int clockProblem = 0;
  int connError = 0;
  int disconnDarknetPeers = 0;
  int bwlimitDelayTime = 1;
  int nodeAveragePingTime = 1;
  long oldestNeverConnectedPeerAge = 0;
  private boolean bwlimitDelayAlertRelevant;
  private boolean nodeAveragePingAlertRelevant;
  int darknetConns = 0;
  int tooNewPeersDarknet = 0;
  int tooNewPeersTotal = 0;
  boolean isOpennetEnabled;
  boolean darknetDefinitelyPortForwarded;
  boolean darknetAssumeNAT;
  private volatile boolean isOutdated;

  /**
   * A minimum number of simultaneously connected peers required before the alert stops reporting
   * "too few connections" conditions. Expressed as a simple connection count and used only by the
   * messaging logic; it does not affect network behavior.
   */
  public static final int MIN_CONN_ALERT_THRESHOLD = 3;

  /**
   * Upper bound for connected darknet peers before the alert starts flagging an unusually high
   * number of darknet connections. This only influences alert wording and severity.
   */
  public static final int MAX_DARKNET_CONN_ALERT_THRESHOLD = 100;

  /**
   * Maximum number of disconnected peers tolerated before a warning about many disconnected peers
   * is generated.
   */
  public static final int MAX_DISCONN_PEER_ALERT_THRESHOLD = 50;

  /**
   * Upper bound for peers that have never connected before a warning is raised. The count refers to
   * peers known to the node that have not yet established a successful session.
   */
  public static final int MAX_NEVER_CONNECTED_PEER_ALERT_THRESHOLD = 5;

  /**
   * A minimum number of peers with clock problems required before the alert mentions clock
   * skew-related issues. Values at or below this threshold suppress clock-related messaging.
   */
  public static final int MIN_CLOCK_PROBLEM_PEER_ALERT_THRESHOLD = 5;

  /**
   * A minimum number of peers with unknown connection errors required before the alert includes a
   * connection-error message. The counter comes from the peer manager's diagnostics.
   */
  public static final int MIN_CONN_ERROR_ALERT_THRESHOLD = 5;

  /**
   * Maximum tolerated age, in milliseconds, for the oldest never-connected peer before the alert
   * highlights peers that have not connected for a long time. Two weeks by default.
   */
  public static final long MAX_OLDEST_NEVER_CONNECTED_PEER_AGE_ALERT_THRESHOLD =
      DAYS.toMillis(14); // 2 weeks

  /**
   * Creates a new alert binder for peer-related messaging.
   *
   * <p>The alert pulls transient metrics such as bandwidth delay and average ping time from {@code
   * n}, and update availability information from {@code nodeUpdater}. It does not take ownership of
   * either object; callers must ensure the supplied references remain valid for the life of this
   * alert instance.
   *
   * @param n node-wide statistics provider used to read delay and latency thresholds; must be
   *     non-{@code null} and refer to the current node instance
   * @param nodeUpdater update coordinator used to decide when the installation is considered
   *     outdated; must be non-{@code null} and already initialized
   */
  public PeerManagerUserAlert(NodeStats n, NodeUpdateManager nodeUpdater) {
    super(
        false,
        null,
        null,
        (short) 0,
        true,
        new AbstractUserAlert.DismissOptions(
            NodeL10n.getBase().getString("UserAlert.hide"), false));
    this.n = n;
    this.nodeUpdater = nodeUpdater;
  }

  /**
   * Returns a short, single-line title identifying the most important current condition.
   *
   * <p>The title is derived from the internal counters at the time of the call and prefers
   * high-severity, user-actionable topics (for example, no peers, too few connections, or
   * suspicious timing metrics). The method is synchronized through an internal monitor to keep the
   * decision consistent with {@link #getText()}.
   *
   * @return a localized string from {@link NodeL10n} describing the primary condition
   * @throws IllegalArgumentException if no condition matches the internal state snapshot
   */
  @Override
  public String getTitle() {
    synchronized (this) {
      if (isOutdated) return l10n("outdatedUpdateTitle");
      if (!isOpennetEnabled) {
        String darknetTitle = getDarknetConnectivityTitleIfAny();
        if (darknetTitle != null) return darknetTitle;
      }
      if (hasTooHighBwlimitDelayTime()) return l10n("tooHighBwlimitDelayTimeTitle");
      if (hasTooHighNodeAveragePingTime()) return l10n("tooHighPingTimeTitle");
      if (hasTooManyClockProblems()) return l10n("clockProblemTitle");
      if (hasTooManyNeverConnectedPeers()) return l10n("tooManyNeverConnectedTitle");
      if (hasTooManyConnectionErrors()) return l10n("connErrorTitle");
      if (hasTooManyDisconnectedDarknetPeers()) return l10n("tooManyDisconnectedTitle");
      if (hasTooManyDarknetConnections()) return l10n("tooManyConnsTitle");
      if (hasTooOldNeverConnectedPeers()) return l10n("tooOldNeverConnectedPeersTitle");
      else throw new IllegalArgumentException("Not valid");
    }
  }

  private String getDarknetConnectivityTitleIfAny() {
    if (peers == 0) return l10n("noPeersTitle");
    if (conns == 0) return l10n("noConnsTitle");
    if (conns < MIN_CONN_ALERT_THRESHOLD)
      return l10nCount("onlyFewConnsTitle", Integer.toString(conns));
    return null;
  }

  /**
   * Returns a compact text variant for UIs that present only a short line.
   *
   * <p>For this alert the short text is identical to {@link #getTitle()}. Callers that need a more
   * descriptive explanation should use {@link #getText()} or {@link #getHTMLText()} instead.
   *
   * @return a localized one-line string suitable for compact listings
   */
  @Override
  public String getShortText() {
    return getTitle();
  }

  private String l10nCount(String key, String value) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, PARAM_COUNT, value);
  }

  private String l10n(String key, String[] pattern, String[] value) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, pattern, value);
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  /**
   * Returns a detailed, localized description of the current condition.
   *
   * <p>The text explains the primary reason for the alert (for example, no peers, connection
   * errors, timing problems) and, in some cases, includes suggestions. Use {@link #getHTMLText()}
   * when rich content such as links is desired.
   *
   * @return a human-readable message describing the condition at call time
   * @throws IllegalArgumentException if the internal state does not map to any known message
   */
  @Override
  public String getText() {
    String s;
    synchronized (this) {
      if (isOutdated) return l10n("outdatedUpdate");
      if (peers == 0 && !isOpennetEnabled) {
        return l10n("noPeersDarknet");
      } else if ((s = getLowConnProblemTextIfAny()) != null) {
        return s;
      } else if (conns == 0 && !isOpennetEnabled) {
        return l10n("noConns");
      } else if (conns == 1 && !isOpennetEnabled) {
        return l10n("oneConn");
      } else if (conns == 2 && !isOpennetEnabled) {
        return l10n("twoConns");
      } else if ((s = getOtherProblemsTextIfAny()) == null) {
        throw new IllegalArgumentException("Not valid");
      }
      return s;
    }
  }

  /**
   * Replaces all occurrences of {@code find} in {@code text} with {@code replace} using regular
   * expression semantics for the search pattern.
   *
   * <p>This method treats {@code find} as a regular expression as defined by {@link
   * java.lang.String#split(String, int)}. For literal substring replacement, prefer {@link
   * #replaceAll(String, String, String)}.
   *
   * @param text the source text to process; must not be {@code null}
   * @param find the pattern to match; interpreted as a regular expression
   * @param replace the replacement inserted for each match; may be empty
   * @return a new string with all matches replaced; identical to {@code text} when no matches are
   *     found
   */
  public static String replace(String text, String find, String replace) {
    return replaceCareful(text, find, replace);
  }

  /**
   * Replaces all literal occurrences of {@code find} in {@code text} with {@code replace}.
   *
   * <p>The search is performed using simple substring scanning (not a regular expression) and
   * continues until no further matches are found. Empty inputs are returned unchanged.
   *
   * @param text the source text to process; must not be {@code null}
   * @param find the exact literal substring to look for; an empty value results in the original
   *     {@code text}
   * @param replace the substitution text inserted for each literal match; may be empty
   * @return a new string with all literal matches replaced, or the original string when no matches
   *     exist
   */
  public static String replaceAll(String text, String find, String replace) {
    int i;
    while ((i = text.indexOf(find)) >= 0) {
      text = text.substring(0, i) + replace + text.substring(i + find.length());
    }
    return text;
  }

  /**
   * Replaces all occurrences of the regular-expression {@code find} in {@code text} with {@code
   * replace} by splitting and joining.
   *
   * <p>This method delegates to {@link String#split(String, int)} with {@code limit = -1} and then
   * rejoins the pieces, which avoids some corner cases of {@link java.util.regex.Matcher} replace
   * methods while preserving regular-expression semantics for {@code find}. If you do not need
   * regex behavior, use {@link #replaceAll(String, String, String)} instead.
   *
   * @param text the full text to transform; must not be {@code null}
   * @param find the search expression, interpreted as a Java regular expression
   * @param replace the replacement to insert between split segments; may be empty
   * @return a newly allocated string reflecting the replacements; never {@code null}
   */
  public static String replaceCareful(String text, String find, String replace) {
    String[] split = text.split(find, -1);
    StringBuilder sb =
        new StringBuilder(text.length() + (split.length - 1) * (replace.length() - find.length()));
    for (int i = 0; i < split.length; i++) {
      sb.append(split[i]);
      if (i < split.length - 1) sb.append(replace);
    }
    return sb.toString();
  }

  /**
   * Produces an HTML representation of the current alert message suitable for embedding in the
   * node's web interface.
   *
   * <p>The returned {@link HTMLNode} is a single {@code div} containing localized text and, for
   * some conditions, a link guiding the user to relevant pages (for example, adding friends). The
   * structure is intentionally simple, so callers can insert the node directly into larger
   * templates without additional escaping.
   *
   * @return a newly created {@link HTMLNode} containing the message snapshot at call time
   * @throws IllegalArgumentException if the internal state does not correspond to any known
   *     condition
   */
  @Override
  public HTMLNode getHTMLText() {
    HTMLNode alertNode = new HTMLNode("div");

    synchronized (this) {
      if (isOutdated)
        // Arguably we should provide a button to turn on auto-update,
        // but very few users will turn off auto-update completely.
        // This is useful to not lose those who do, however.
        alertNode.addChild("#", l10n("outdatedUpdate"));
      else if (peers == 0 && !isOpennetEnabled) {
        alertNode.addChild("#", l10n("noPeersDarknet"));
      } else {
        String lowConn = getLowConnProblemTextIfAny();
        if (lowConn != null) {
          alertNode.addChild("#", lowConn);
          return alertNode;
        }

        String countText = getDarknetConnCountHtmlTextIfAny();
        if (countText != null) {
          alertNode.addChild("#", countText);
          return alertNode;
        }

        if (hasTooManyNeverConnectedPeers()) {
          NodeL10n.getBase()
              .addL10nSubstitution(
                  alertNode,
                  "PeerManagerUserAlert.tooManyNeverConnectedWithLink",
                  new String[] {"link", PARAM_COUNT},
                  new HTMLNode[] {HTMLNode.link("/friends/myref.fref"), HTMLNode.text(neverConn)});
          return alertNode;
        }

        String other = getOtherProblemsTextIfAny();
        if (other != null) {
          alertNode.addChild("#", other);
        } else {
          throw new IllegalArgumentException("not valid");
        }
      }
    }
    return alertNode;
  }

  private String getDarknetConnCountHtmlTextIfAny() {
    if (conns == 0 && !isOpennetEnabled) return l10n("noConns");
    if (conns == 1 && !isOpennetEnabled) return l10n("oneConn");
    if (conns == 2 && !isOpennetEnabled) return l10n("twoConns");
    return null;
  }

  private boolean calculateIsOutdated() {
    // Do not show the message if updater is enabled.
    if (nodeUpdater.isEnabled()) return false;
    if (nodeUpdater.isBlown()) return false;
    synchronized (this) {
      if (tooNewPeersDarknet >= PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET) return true;
      return conns < PeerManager.OUTDATED_MAX_CONNS
          && tooNewPeersTotal >= PeerManager.OUTDATED_MIN_TOO_NEW_TOTAL;
    }
  }

  /**
   * Returns the priority class for the current alert snapshot.
   *
   * <p>The value is derived from connectivity state, problem counters, and update status. Higher
   * severities take precedence. This method is side-effect-free and safe to call repeatedly.
   *
   * @return one of the standard {@link UserAlert} severity constants indicating UI importance
   */
  @Override
  public short getPriorityClass() {
    synchronized (this) {
      if (isOutdated) {
        if (conns == 0) return UserAlert.CRITICAL_ERROR;
        else return UserAlert.ERROR;
      }
      Short dns = getDarknetOnlySeverityIfAny();
      if (dns != null) return dns;

      Short prob = getProblemDrivenSeverityIfAny();
      if (prob != null) return prob;
      return ERROR;
    }
  }

  private Short getDarknetOnlySeverityIfAny() {
    if (peers == 0 && !isOpennetEnabled) return UserAlert.CRITICAL_ERROR;
    if (conns == 0 && !isOpennetEnabled) return UserAlert.ERROR;
    if (conns < 3 && !isOpennetEnabled) return ERROR;
    return null;
  }

  private Short getProblemDrivenSeverityIfAny() {
    if (conns < 3 && hasTooManyClockProblems()) return ERROR;
    if (conns < 3 && hasTooManyConnectionErrors()) return ERROR;
    if (hasTooHighBwlimitDelayTime()) return ERROR;
    if (hasTooHighNodeAveragePingTime()) return ERROR;
    if (hasTooManyClockProblems()) return ERROR;
    if (hasTooManyNeverConnectedPeers()) return WARNING;
    if (hasTooManyConnectionErrors()) return WARNING;
    if (hasTooManyDisconnectedDarknetPeers()) return WARNING;
    if (hasTooManyDarknetConnections()) return WARNING;
    if (hasTooOldNeverConnectedPeers()) return WARNING;
    return null;
  }

  /**
   * Reports whether the alert is currently relevant and should be shown.
   *
   * <p>The decision considers connection counts, problem counters, latency-related metrics from
   * {@link NodeStats}, and whether the installation appears outdated based on {@link
   * NodeUpdateManager}. The method triggers a lightweight internal refresh before evaluating the
   * conditions.
   *
   * @return {@code true} when at least one condition warrants notifying the user; {@code false}
   *     otherwise
   */
  @Override
  public boolean isValid() {
    // only update here so we don't get odd behavior with it fluctuating
    update();
    boolean ret;
    synchronized (this) {
      ret =
          ((peers == 0 && !isOpennetEnabled)
              || (conns < 3 && !isOpennetEnabled)
              || (neverConn > MAX_NEVER_CONNECTED_PEER_ALERT_THRESHOLD)
              || (disconnDarknetPeers > MAX_DISCONN_PEER_ALERT_THRESHOLD
                  && !darknetDefinitelyPortForwarded
                  && !darknetAssumeNAT)
              || (darknetConns > MAX_DARKNET_CONN_ALERT_THRESHOLD)
              || (clockProblem > MIN_CLOCK_PROBLEM_PEER_ALERT_THRESHOLD)
              || (connError > MIN_CONN_ERROR_ALERT_THRESHOLD)
              || (bwlimitDelayAlertRelevant
                  && (bwlimitDelayTime > NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD))
              || (nodeAveragePingAlertRelevant
                  && (nodeAveragePingTime > NodeStats.MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD))
              || (oldestNeverConnectedPeerAge
                  > MAX_OLDEST_NEVER_CONNECTED_PEER_AGE_ALERT_THRESHOLD));
    }
    if (!ret) ret = isOutdated;
    return ret;
  }

  private synchronized void update() {
    bwlimitDelayTime = (int) n.getBwlimitDelayTime();
    nodeAveragePingTime = (int) n.getNodeAveragePingTime();
    oldestNeverConnectedPeerAge = n.peers.getOldestNeverConnectedDarknetPeerAge();
    bwlimitDelayAlertRelevant = n.isBwlimitDelayAlertRelevant();
    nodeAveragePingAlertRelevant = n.isNodeAveragePingAlertRelevant();
    isOutdated = calculateIsOutdated();
    // Potential refactor: centralize updates via PeerManager listeners.
  }

  private String getLowConnProblemTextIfAny() {
    if (conns < 3 && hasTooManyClockProblems())
      return l10nCount("clockProblem", Integer.toString(clockProblem));
    if (conns < 3 && hasTooManyConnectionErrors() && !isOpennetEnabled)
      return l10nCount("connError", Integer.toString(connError));
    return null;
  }

  private String getOtherProblemsTextIfAny() {
    if (hasTooHighBwlimitDelayTime()) {
      return l10n(
          "tooHighBwlimitDelayTime",
          new String[] {PARAM_DELAY, PARAM_MAX},
          new String[] {
            Integer.toString(bwlimitDelayTime),
            Long.toString(NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD)
          });
    }
    if (hasTooHighNodeAveragePingTime()) {
      return l10n(
          "tooHighPingTime",
          new String[] {PARAM_PING, PARAM_MAX},
          new String[] {
            Integer.toString(nodeAveragePingTime),
            Long.toString(NodeStats.MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD)
          });
    }
    if (hasTooManyClockProblems()) {
      return l10nCount("clockProblem", Integer.toString(clockProblem));
    }
    if (hasTooManyNeverConnectedPeers()) {
      return l10nCount("tooManyNeverConnected", Integer.toString(neverConn));
    }
    if (hasTooManyConnectionErrors()) {
      return l10nCount("connError", Integer.toString(connError));
    }
    if (hasTooManyDisconnectedDarknetPeers()) {
      return l10n(
          "tooManyDisconnected",
          new String[] {PARAM_COUNT, PARAM_MAX},
          new String[] {
            Integer.toString(disconnDarknetPeers),
            Integer.toString(MAX_DISCONN_PEER_ALERT_THRESHOLD)
          });
    }
    if (hasTooManyDarknetConnections()) {
      return l10n(
          "tooManyConns",
          new String[] {PARAM_COUNT, PARAM_MAX},
          new String[] {
            Integer.toString(conns), Integer.toString(MAX_DARKNET_CONN_ALERT_THRESHOLD)
          });
    }
    if (hasTooOldNeverConnectedPeers()) {
      return l10n("tooOldNeverConnectedPeers");
    }
    return null;
  }

  // Helper predicates to reduce the cognitive complexity of content methods
  private boolean hasTooHighBwlimitDelayTime() {
    return bwlimitDelayAlertRelevant
        && (bwlimitDelayTime > NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD);
  }

  private boolean hasTooHighNodeAveragePingTime() {
    return nodeAveragePingAlertRelevant
        && (nodeAveragePingTime > NodeStats.MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD);
  }

  private boolean hasTooManyClockProblems() {
    return clockProblem > MIN_CLOCK_PROBLEM_PEER_ALERT_THRESHOLD;
  }

  private boolean hasTooManyNeverConnectedPeers() {
    return neverConn > MAX_NEVER_CONNECTED_PEER_ALERT_THRESHOLD;
  }

  private boolean hasTooManyConnectionErrors() {
    return connError > MIN_CONN_ERROR_ALERT_THRESHOLD;
  }

  private boolean hasTooManyDisconnectedDarknetPeers() {
    return disconnDarknetPeers > MAX_DISCONN_PEER_ALERT_THRESHOLD
        && !darknetDefinitelyPortForwarded
        && !darknetAssumeNAT;
  }

  private boolean hasTooManyDarknetConnections() {
    return darknetConns > MAX_DARKNET_CONN_ALERT_THRESHOLD;
  }

  private boolean hasTooOldNeverConnectedPeers() {
    return oldestNeverConnectedPeerAge > MAX_OLDEST_NEVER_CONNECTED_PEER_AGE_ALERT_THRESHOLD;
  }

  // Setters for cross-package updates (PeerManager)
  /**
   * Flags that the opennet port is definitively reachable from the public Internet, according to
   * the caller's observation.
   *
   * @param value {@code true} if reachability has been confirmed; {@code false} if it has not been
   *     confirmed or is known to be unreachable
   */
  public synchronized void setOpennetDefinitelyPortForwarded(boolean value) {
    // Intentionally no-op: opennet-specific forwarding state does not currently affect alert text.
  }

  /**
   * Flags that the darknet port is definitively reachable from the public Internet, according to
   * the caller's observation.
   *
   * @param value {@code true} if reachability has been confirmed; {@code false} if it has not been
   *     confirmed or is known to be unreachable
   */
  public synchronized void setDarknetDefinitelyPortForwarded(boolean value) {
    this.darknetDefinitelyPortForwarded = value;
  }

  /**
   * Hints that the opennet side is likely behind a NAT and should be considered accordingly when
   * deciding whether to surface disconnect-related hints.
   *
   * @param value {@code true} to assume a NAT is present; {@code false} to avoid applying that
   *     assumption
   */
  public synchronized void setOpennetAssumeNAT(boolean value) {
    // Intentionally no-op: opennet-specific NAT hints do not currently affect alert text.
  }

  /**
   * Hints that the darknet side is likely behind a NAT and should be considered accordingly when
   * deciding whether to surface disconnect-related hints.
   *
   * @param value {@code true} to assume a NAT is present; {@code false} to avoid applying that
   *     assumption
   */
  public synchronized void setDarknetAssumeNAT(boolean value) {
    this.darknetAssumeNAT = value;
  }

  /**
   * Sets the latest count of currently connected darknet peers as measured by the peer manager.
   *
   * @param value number of active darknet connections; negative values are not expected
   */
  public synchronized void setDarknetConns(int value) {
    this.darknetConns = value;
  }

  /**
   * Sets the latest total count of currently connected peers across the relevant modes.
   *
   * @param value number of active connections; negative values are not expected
   */
  public synchronized void setConns(int value) {
    this.conns = value;
  }

  /**
   * Sets the total number of known darknet peers, connected or not, according to the peer manager.
   *
   * @param value count of darknet peers; negative values are not expected
   */
  public synchronized void setDarknetPeers(int value) {
    // Intentionally no-op: total darknet peer count is not currently consumed by alert predicates.
  }

  /**
   * Sets the number of darknet peers that are currently disconnected.
   *
   * @param value count of disconnected darknet peers; negative values are not expected
   */
  public synchronized void setDisconnDarknetPeers(int value) {
    this.disconnDarknetPeers = value;
  }

  /**
   * Sets the total number of known peers (all modes) tracked by the peer manager.
   *
   * @param value peer count; negative values are not expected
   */
  public synchronized void setPeers(int value) {
    this.peers = value;
  }

  /**
   * Sets the number of peers that have never successfully connected to this node.
   *
   * @param value count of never-connected peers; negative values are not expected
   */
  public synchronized void setNeverConn(int value) {
    this.neverConn = value;
  }

  /**
   * Sets the number of peers currently exhibiting significant clock skew or clock-related problems.
   *
   * @param value count of peers with clock problems; negative values are not expected
   */
  public synchronized void setClockProblem(int value) {
    this.clockProblem = value;
  }

  /**
   * Sets the number of peers for which the most recent connection attempt failed with an unknown or
   * generic error.
   *
   * @param value count of peers with connection errors; negative values are not expected
   */
  public synchronized void setConnError(int value) {
    this.connError = value;
  }

  /**
   * Enables or disables opennet participation as observed by the caller. When disabled, alert
   * wording focuses on darknet-only conditions.
   *
   * @param value {@code true} if opennet is enabled; {@code false} if disabled
   */
  public synchronized void setOpennetEnabled(boolean value) {
    this.isOpennetEnabled = value;
  }

  /**
   * Reports the count of darknet peers that appear to run a newer, incompatible build and are
   * therefore considered "too new" for the local node.
   *
   * @param value number of too-new darknet peers; negative values are not expected
   */
  public synchronized void setTooNewPeersDarknet(int value) {
    this.tooNewPeersDarknet = value;
  }

  /**
   * Reports the total number of peers that appear to run a newer, incompatible build across all
   * modes.
   *
   * @param value total number of too-new peers; negative values are not expected
   */
  public synchronized void setTooNewPeersTotal(int value) {
    this.tooNewPeersTotal = value;
  }
}
