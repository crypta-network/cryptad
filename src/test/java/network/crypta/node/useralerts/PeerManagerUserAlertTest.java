package network.crypta.node.useralerts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.function.Consumer;
import java.util.stream.Stream;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerManagerUserAlertTest {

  @Mock private NodeStats nodeStats;
  @Mock private NodeUpdateManager nodeUpdateManager;

  private PeerManagerUserAlert newAlert() {
    return new PeerManagerUserAlert(nodeStats, nodeUpdateManager);
  }

  @BeforeEach
  void resetL10n() {
    // Ensure NodeL10n is initialized so translations resolve deterministically.
    NodeL10n.getBase();
  }

  // --- helpers
  // Removed generic boolean field setter to avoid false-positive duplication warnings.

  @SuppressWarnings("java:S3011")
  private static void setOldestNeverConnectedPeerAge(
      PeerManagerUserAlert alert, long oldestNeverConnectedPeerAge) {
    try {
      Field f = alert.getClass().getDeclaredField("oldestNeverConnectedPeerAge");
      f.setAccessible(true);
      f.setLong(alert, oldestNeverConnectedPeerAge);
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  @SuppressWarnings("java:S3011")
  private static void setPeersOnNodeStats(NodeStats stats, PeerManager pm) {
    try {
      Field f = NodeStats.class.getDeclaredField("peers");
      f.setAccessible(true);
      f.set(stats, pm);
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  // targeted helpers to avoid repeated string literals in reflection
  @SuppressWarnings("java:S3011")
  private static void setIsOutdated(PeerManagerUserAlert alert) {
    try {
      Field f = alert.getClass().getDeclaredField("isOutdated");
      f.setAccessible(true);
      f.setBoolean(alert, true);
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  @SuppressWarnings("java:S3011")
  private static void setBwlimitDelayAlertRelevant(PeerManagerUserAlert alert, boolean value) {
    try {
      Field f = alert.getClass().getDeclaredField("bwlimitDelayAlertRelevant");
      f.setAccessible(true);
      f.setBoolean(alert, value);
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  @SuppressWarnings("java:S3011")
  private static void setNodeAveragePingAlertRelevant(PeerManagerUserAlert alert, boolean value) {
    try {
      Field f = alert.getClass().getDeclaredField("nodeAveragePingAlertRelevant");
      f.setAccessible(true);
      f.setBoolean(alert, value);
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  private void stubNodeStatsForSafeUpdate() {
    when(nodeStats.getBwlimitDelayTime()).thenReturn(0.0);
    when(nodeStats.getNodeAveragePingTime()).thenReturn(0.0);
    when(nodeStats.isBwlimitDelayAlertRelevant()).thenReturn(false);
    when(nodeStats.isNodeAveragePingAlertRelevant()).thenReturn(false);
    // Provide a PeerManager for nodeStats.peers used by update().
    PeerManager pm = mock(PeerManager.class);
    when(pm.getOldestNeverConnectedDarknetPeerAge()).thenReturn(0L);
    // nodeStats is a mock of a class; set its public final field via reflection.
    setPeersOnNodeStats(nodeStats, pm);
  }

  // --- replace helpers
  @Test
  @DisplayName("replaceCareful_whenMultipleOccurrences_replacesAll")
  void replaceCareful_whenMultipleOccurrences_replacesAll() {
    String out = PeerManagerUserAlert.replaceCareful("aaaa", "aa", "b");
    assertEquals("bb", out);
    assertEquals("bb", PeerManagerUserAlert.replace("aaaa", "aa", "b"));
  }

  @Test
  @DisplayName("replaceAll_whenNoOccurrences_returnsOriginal")
  void replaceAll_whenNoOccurrences_returnsOriginal() {
    String out = PeerManagerUserAlert.replaceAll("abc", "x", "y");
    assertEquals("abc", out);
  }

  // --- getTitle
  @Test
  @DisplayName("getTitle_whenOutdated_returnsOutdatedTitle")
  void getTitle_whenOutdated_returnsOutdatedTitle() {
    PeerManagerUserAlert alert = newAlert();
    setIsOutdated(alert);
    String expected = NodeL10n.getBase().getString("PeerManagerUserAlert.outdatedUpdateTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("getTitle_whenNoPeersDarknet_returnsNoPeersTitle")
  void getTitle_whenNoPeersDarknet_returnsNoPeersTitle() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = false;
    alert.peers = 0;
    String expected = NodeL10n.getBase().getString("PeerManagerUserAlert.noPeersTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("getTitle_whenNoConnections_returnsNoConnsTitle")
  void getTitle_whenNoConnections_returnsNoConnsTitle() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = false;
    alert.peers = 1;
    alert.conns = 0;
    String expected = NodeL10n.getBase().getString("PeerManagerUserAlert.noConnsTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("getTitle_whenFewConnections_returnsOnlyFewConnsTitle")
  void getTitle_whenFewConnections_returnsOnlyFewConnsTitle() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = false;
    alert.peers = 5;
    alert.conns = 2;
    String expected =
        NodeL10n.getBase()
            .getString("PeerManagerUserAlert.onlyFewConnsTitle", "count", Integer.toString(2));
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("getTitle_whenHighBwDelay_returnsBwDelayTitle")
  void getTitle_whenHighBwDelay_returnsBwDelayTitle() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true; // avoid darknet-only early branches
    alert.peers = 5;
    alert.conns = 5;
    alert.bwlimitDelayTime = (int) (NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD + 1);
    setBwlimitDelayAlertRelevant(alert, true);
    String expected =
        NodeL10n.getBase().getString("PeerManagerUserAlert.tooHighBwlimitDelayTimeTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("getTitle_whenHighPing_returnsPingTitle")
  void getTitle_whenHighPing_returnsPingTitle() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.peers = 5;
    alert.conns = 5;
    alert.nodeAveragePingTime = (int) (NodeStats.MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD + 1);
    setNodeAveragePingAlertRelevant(alert, true);
    String expected = NodeL10n.getBase().getString("PeerManagerUserAlert.tooHighPingTimeTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("getTitle_whenClockProblems_returnsClockProblemTitle")
  void getTitle_whenClockProblems_returnsClockProblemTitle() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.peers = 5;
    alert.conns = 5;
    alert.clockProblem = PeerManagerUserAlert.MIN_CLOCK_PROBLEM_PEER_ALERT_THRESHOLD + 1;
    String expected = NodeL10n.getBase().getString("PeerManagerUserAlert.clockProblemTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("getTitle_whenTooManyNeverConnected_returnsNeverConnectedTitle")
  void getTitle_whenTooManyNeverConnected_returnsNeverConnectedTitle() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.peers = 5;
    alert.conns = 5;
    alert.neverConn = PeerManagerUserAlert.MAX_NEVER_CONNECTED_PEER_ALERT_THRESHOLD + 1;
    String expected =
        NodeL10n.getBase().getString("PeerManagerUserAlert.tooManyNeverConnectedTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("getTitle_whenConnError_returnsConnErrorTitle")
  void getTitle_whenConnError_returnsConnErrorTitle() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.peers = 5;
    alert.conns = 5;
    alert.connError = PeerManagerUserAlert.MIN_CONN_ERROR_ALERT_THRESHOLD + 1;
    String expected = NodeL10n.getBase().getString("PeerManagerUserAlert.connErrorTitle");
    assertEquals(expected, alert.getTitle());
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("thresholdTitleCases")
  @DisplayName("getTitle_thresholdConditions_expectMatchingTitle")
  void getTitle_thresholdConditions_expectMatchingTitle(
      String scenarioName, Consumer<PeerManagerUserAlert> mutator, String expectedKey) {
    PeerManagerUserAlert alert = newAlert();
    // Baseline to avoid earlier branches
    alert.isOpennetEnabled = true;
    alert.peers = 10;
    alert.conns = 10;
    // Apply scenario-specific mutation
    mutator.accept(alert);
    String expected = NodeL10n.getBase().getString(expectedKey);
    assertEquals(expected, alert.getTitle());
  }

  private static Stream<Arguments> thresholdTitleCases() {
    return Stream.of(
        Arguments.of(
            "TooManyDisconnected",
            (Consumer<PeerManagerUserAlert>)
                a -> {
                  a.disconnDarknetPeers = PeerManagerUserAlert.MAX_DISCONN_PEER_ALERT_THRESHOLD + 1;
                  a.darknetDefinitelyPortForwarded = false;
                  a.darknetAssumeNAT = false;
                },
            "PeerManagerUserAlert.tooManyDisconnectedTitle"),
        Arguments.of(
            "TooManyDarknetConns",
            (Consumer<PeerManagerUserAlert>)
                a -> a.darknetConns = PeerManagerUserAlert.MAX_DARKNET_CONN_ALERT_THRESHOLD + 1,
            "PeerManagerUserAlert.tooManyConnsTitle"),
        Arguments.of(
            "OldNeverConnected",
            (Consumer<PeerManagerUserAlert>)
                a ->
                    setOldestNeverConnectedPeerAge(
                        a,
                        PeerManagerUserAlert.MAX_OLDEST_NEVER_CONNECTED_PEER_AGE_ALERT_THRESHOLD
                            + 1),
            "PeerManagerUserAlert.tooOldNeverConnectedPeersTitle"));
  }

  @Test
  @DisplayName("getTitle_whenNoCondition_throwsIllegalArgument")
  void getTitle_whenNoCondition_throwsIllegalArgument() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true; // skip darknet-specific early titles
    alert.peers = 5;
    alert.conns = 5;
    alert.clockProblem = 0;
    alert.connError = 0;
    alert.neverConn = 0;
    alert.darknetConns = 0;
    alert.disconnDarknetPeers = 0;
    setBwlimitDelayAlertRelevant(alert, false);
    setNodeAveragePingAlertRelevant(alert, false);
    setOldestNeverConnectedPeerAge(alert, 0);
    assertThrows(IllegalArgumentException.class, alert::getTitle);
  }

  // --- getText
  @Test
  @DisplayName("getText_whenNoPeersDarknet_returnsNoPeersDarknet")
  void getText_whenNoPeersDarknet_returnsNoPeersDarknet() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = false;
    alert.peers = 0;
    String expected = NodeL10n.getBase().getString("PeerManagerUserAlert.noPeersDarknet");
    assertEquals(expected, alert.getText());
  }

  @ParameterizedTest(name = "getText_conn_{0}")
  @MethodSource("connTextCases")
  @DisplayName("getText_connCounts_expectMatchingText")
  void getText_connCounts_expectMatchingText(int conns, String expectedKey) {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = false;
    alert.peers = 2; // ensure not hitting noPeersDarknet branch
    alert.conns = conns;
    String expected = NodeL10n.getBase().getString(expectedKey);
    assertEquals(expected, alert.getText());
  }

  private static Stream<Arguments> connTextCases() {
    return Stream.of(
        Arguments.of(0, "PeerManagerUserAlert.noConns"),
        Arguments.of(1, "PeerManagerUserAlert.oneConn"),
        Arguments.of(2, "PeerManagerUserAlert.twoConns"));
  }

  @Test
  @DisplayName("getText_whenHighBwDelay_includesValues")
  void getText_whenHighBwDelay_includesValues() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.conns = 5;
    alert.peers = 5;
    alert.bwlimitDelayTime = (int) (NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD + 7);
    setBwlimitDelayAlertRelevant(alert, true);
    String expected =
        NodeL10n.getBase()
            .getString(
                "PeerManagerUserAlert.tooHighBwlimitDelayTime",
                new String[] {"delay", "max"},
                new String[] {
                  Integer.toString(alert.bwlimitDelayTime),
                  Long.toString(NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD)
                });
    assertEquals(expected, alert.getText());
  }

  @Test
  @DisplayName("getText_whenHighPing_includesValues")
  void getText_whenHighPing_includesValues() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.conns = 5;
    alert.peers = 5;
    alert.nodeAveragePingTime = (int) (NodeStats.MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD + 3);
    setNodeAveragePingAlertRelevant(alert, true);
    String expected =
        NodeL10n.getBase()
            .getString(
                "PeerManagerUserAlert.tooHighPingTime",
                new String[] {"ping", "max"},
                new String[] {
                  Integer.toString(alert.nodeAveragePingTime),
                  Long.toString(NodeStats.MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD)
                });
    assertEquals(expected, alert.getText());
  }

  @Test
  @DisplayName("getHTMLText_whenTooManyNeverConnected_containsLinkAndCount")
  void getHTMLText_whenTooManyNeverConnected_containsLinkAndCount() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.peers = 5;
    alert.conns = 5;
    alert.neverConn = PeerManagerUserAlert.MAX_NEVER_CONNECTED_PEER_ALERT_THRESHOLD + 2;
    HTMLNode html = alert.getHTMLText();
    String rendered = html.generateChildren();
    assertTrue(rendered.contains("/friends/myref.fref"));
    assertTrue(rendered.contains(Integer.toString(alert.neverConn)));
  }

  // --- getPriorityClass
  @Test
  @DisplayName("getPriorityClass_whenOutdatedAndNoConns_isCritical")
  void getPriorityClass_whenOutdatedAndNoConns_isCritical() {
    PeerManagerUserAlert alert = newAlert();
    alert.conns = 0;
    setIsOutdated(alert);
    assertEquals(UserAlert.CRITICAL_ERROR, alert.getPriorityClass());
  }

  @Test
  @DisplayName("getPriorityClass_whenOutdatedWithConns_isError")
  void getPriorityClass_whenOutdatedWithConns_isError() {
    PeerManagerUserAlert alert = newAlert();
    alert.conns = 4;
    setIsOutdated(alert);
    assertEquals(UserAlert.ERROR, alert.getPriorityClass());
  }

  @Test
  @DisplayName("getPriorityClass_whenNoPeersDarknet_isCritical")
  void getPriorityClass_whenNoPeersDarknet_isCritical() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = false;
    alert.peers = 0;
    assertEquals(UserAlert.CRITICAL_ERROR, alert.getPriorityClass());
  }

  @Test
  @DisplayName("getPriorityClass_whenNeverConnectedTooMany_isWarning")
  void getPriorityClass_whenNeverConnectedTooMany_isWarning() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.peers = 5;
    alert.conns = 5;
    alert.neverConn = PeerManagerUserAlert.MAX_NEVER_CONNECTED_PEER_ALERT_THRESHOLD + 1;
    assertEquals(UserAlert.WARNING, alert.getPriorityClass());
  }

  @Test
  @DisplayName("getPriorityClass_whenNoConditions_returnsError")
  void getPriorityClass_whenNoConditions_returnsError() {
    PeerManagerUserAlert alert = newAlert();
    alert.isOpennetEnabled = true;
    alert.peers = 10;
    alert.conns = 10;
    setOldestNeverConnectedPeerAge(alert, 0);
    assertEquals(UserAlert.ERROR, alert.getPriorityClass());
  }

  // --- isValid
  @Test
  @DisplayName("isValid_whenTooManyDisconnectedAndNotPortForwarded_returnsTrue")
  void isValid_whenTooManyDisconnectedAndNotPortForwarded_returnsTrue() {
    PeerManagerUserAlert alert = newAlert();
    alert.disconnDarknetPeers = PeerManagerUserAlert.MAX_DISCONN_PEER_ALERT_THRESHOLD + 10;
    alert.darknetDefinitelyPortForwarded = false;
    alert.darknetAssumeNAT = false;

    stubNodeStatsForSafeUpdate();

    assertTrue(alert.isValid());
  }

  @Test
  @DisplayName("isValid_whenNoConditionsAndUpdaterDisabledButPeersSayOutdated_returnsTrue")
  void isValid_whenNoConditionsAndUpdaterDisabledButPeersSayOutdated_returnsTrue() {
    PeerManagerUserAlert alert = newAlert();
    // No direct alert conditions
    alert.isOpennetEnabled = true;
    alert.peers = 10;
    alert.conns = 1; // below OUTDATED_MAX_CONNS makes outdated more likely when tooNewTotal >= 5
    alert.tooNewPeersDarknet = PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET; // 1 -> triggers outdated
    alert.tooNewPeersTotal = PeerManager.OUTDATED_MIN_TOO_NEW_TOTAL; // conservative, also enough

    when(nodeUpdateManager.isEnabled()).thenReturn(false);
    when(nodeUpdateManager.isBlown()).thenReturn(false);

    stubNodeStatsForSafeUpdate();

    assertTrue(alert.isValid());
  }
}
