package network.crypta.node;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.updater.UpdateOverMandatoryManager;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class AnnouncerTest {

  @Mock private OpennetManager om;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerManager peers;

  @Mock private Ticker ticker;

  @Mock private PriorityAwareExecutor executor;

  @Mock private NodeUpdateManager updater;

  @Mock private UpdateOverMandatoryManager uom;

  @Mock private NodeClientCore clientCore;

  @Mock private UserAlertManager alerts;

  // (no helpers)

  @Test
  @DisplayName("readSeednodes when file has multiple blocks returns only non-empty SFS")
  void readSeednodes_whenFileHasMultipleBlocks_returnsOnlyNonEmpty(@TempDir Path tmp)
      throws IOException {
    Path file = tmp.resolve("seednodes.txt");
    String content =
        """
        foo=bar
        End
        End
        # header
        baz=qux
        End
        """;
    Files.writeString(file, content, StandardCharsets.UTF_8);

    List<SimpleFieldSet> out = Announcer.readSeednodes(file.toFile());

    assertEquals(2, out.size(), "Should parse 2 non-empty SimpleFieldSet blocks");
    // Verify keys are present
    boolean hasFoo = out.stream().anyMatch(sfs -> "bar".equals(sfs.get("foo")));
    boolean hasBaz = out.stream().anyMatch(sfs -> "qux".equals(sfs.get("baz")));
    assertTrue(hasFoo, "First block should contain foo=bar");
    assertTrue(hasBaz, "Third block should contain baz=qux");
  }

  @ParameterizedTest(name = "aim={0} => threshold={1}")
  @CsvSource({"0,0", "5,2", "8,4", "20,10", "30,10"})
  @DisplayName("getAnnouncementThreshold applies min(10, aim/2)")
  void getAnnouncementThreshold_variousTargets_expectedMin(int aim, int expected) {
    when(om.getNode()).thenReturn(node);
    when(om.getNumberOfConnectedPeersToAimIncludingDarknet()).thenReturn(aim);
    Announcer announcer = new Announcer(om);

    int threshold = announcer.getAnnouncementThreshold();

    assertEquals(expected, threshold);
  }

  @Test
  @DisplayName("maybeSendAnnouncementOffThread when enoughPeers true does not schedule")
  void maybeSendAnnouncementOffThread_whenEnoughPeersTrue_doesNotSchedule() {
    when(om.getNode()).thenReturn(node);
    when(node.network().ticker()).thenReturn(ticker);
    Announcer announcer = Mockito.spy(new Announcer(om));
    doReturn(true).when(announcer).enoughPeers();

    announcer.maybeSendAnnouncementOffThread();

    verify(ticker, never()).queueTimedJob(any(Runnable.class), any(Long.class));
  }

  @Test
  @DisplayName("maybeSendAnnouncementOffThread when not enough peers schedules immediate job")
  void maybeSendAnnouncementOffThread_whenNotEnoughPeers_schedulesImmediate() {
    when(om.getNode()).thenReturn(node);
    when(node.network().ticker()).thenReturn(ticker);
    Announcer announcer = Mockito.spy(new Announcer(om));
    doReturn(false).when(announcer).enoughPeers();

    announcer.maybeSendAnnouncementOffThread();

    ArgumentCaptor<Runnable> r = ArgumentCaptor.forClass(Runnable.class);
    ArgumentCaptor<Long> delay = ArgumentCaptor.forClass(Long.class);
    verify(ticker, times(1)).queueTimedJob(r.capture(), delay.capture());
    assertEquals(0L, delay.getValue(), "Should schedule immediately with 0 delay");
    assertNotNull(r.getValue(), "Runnable should not be null");
  }

  @Test
  @DisplayName("sendAnnouncement returns false when opennet disabled")
  void sendAnnouncement_whenOpennetDisabled_returnsFalse() {
    when(om.getNode()).thenReturn(node);
    when(node.network().isOpennetEnabled()).thenReturn(false);
    Announcer announcer = new Announcer(om);

    SeedServerPeerNode seed = mock(SeedServerPeerNode.class);

    boolean result = announcer.sendAnnouncement(seed);

    assertFalse(result, "Should not announce when opennet is disabled");
    // No executor interaction expected
    verify(node, never()).getExecutor();
  }

  @Test
  @DisplayName(
      "isWaitingForUpdater reflects killAnnouncement flag when updater disabled and too-new peers >"
          + " 10")
  void isWaitingForUpdater_whenKillAnnouncementConditionMet_true() {
    when(om.getNode()).thenReturn(node);
    when(om.stopping()).thenReturn(false);
    when(node.network().peers()).thenReturn(peers);
    when(peers.countConnectedPeers()).thenReturn(0);
    // ensure target > opennetCount(=0) so we do NOT early-return "enough"
    when(om.getNumberOfConnectedPeersToAimIncludingDarknet()).thenReturn(2);

    // Updater: disabled, and UOM not fetching from two
    when(node.services().nodeUpdater()).thenReturn(updater);
    when(updater.isEnabled()).thenReturn(false);
    when(updater.isArmed()).thenReturn(true);
    when(updater.getUpdateOverMandatory()).thenReturn(uom);
    when(uom.fetchingFromTwo()).thenReturn(false);

    // Too-new peers > 10 triggers killAnnouncement path
    when(peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false)).thenReturn(11);

    // Executor present (no-op execution to avoid deep interactions)
    when(node.getExecutor()).thenReturn(executor);
    doAnswer(inv -> null).when(executor).execute(any(Runnable.class));

    // Alerts mocked to avoid real notification logic
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    Announcer announcer = new Announcer(om);

    // enoughPeers should return true (since we kill announcements) and set the flag
    assertTrue(announcer.enoughPeers(), "Announcement should be killed and treated as enoughPeers");
    assertTrue(announcer.isWaitingForUpdater(), "Waiting-for-updater flag should be set");

    // Alert should be registered once
    verify(alerts, times(1)).register(Mockito.<UserAlert>any());
  }

  @Test
  @DisplayName("timeGotEnoughPeers tracks first time above threshold and resets below")
  void enoughPeers_timeTracking_setsAndResets() {
    when(om.getNode()).thenReturn(node);
    when(om.stopping()).thenReturn(false);
    when(node.network().peers()).thenReturn(peers);
    when(node.services().nodeUpdater()).thenReturn(updater);
    when(updater.isEnabled()).thenReturn(true);
    when(updater.isArmed()).thenReturn(true);
    when(updater.getUpdateOverMandatory()).thenReturn(uom);
    when(uom.fetchingFromTwo()).thenReturn(false);
    when(peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false)).thenReturn(0);

    // Target = min(10, aim/2) => aim=8 -> target 4
    when(om.getNumberOfConnectedPeersToAimIncludingDarknet()).thenReturn(8);

    // First call: connected peers = 4 (>= target) => enoughPeers() true and time set
    when(peers.countConnectedPeers()).thenReturn(4, 0); // second call returns 0

    Announcer announcer = new Announcer(om);

    assertTrue(announcer.enoughPeers(), "Should have enough peers at threshold");
    assertTrue(
        announcer.timeGotEnoughPeers() > 0,
        "timeGotEnoughPeers should be set to a positive timestamp");

    // Drop below threshold => enoughPeers false and time reset to -1
    assertFalse(announcer.enoughPeers(), "Should no longer have enough peers");
    assertEquals(-1L, announcer.timeGotEnoughPeers(), "timeGotEnoughPeers should reset to -1");
  }
}
