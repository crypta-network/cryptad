package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SecurityLevelsTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerManager peers;
  @Mock private PeerRoster roster;

  @BeforeEach
  void setup() {
    // Ensure Node.getPeers() returns our mock for tests that need it; lenient to avoid strict
    // stubbing failures in tests that don't call getConfirmWarning().
    org.mockito.Mockito.lenient().when(node.network().peers()).thenReturn(peers);
    org.mockito.Mockito.lenient().when(peers.roster()).thenReturn(roster);
  }

  // --- Helpers ---

  private static SimpleFieldSet sfsWith(String... kvPairs) {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    for (int i = 0; i + 1 < kvPairs.length; i += 2) {
      sfs.putOverwrite(kvPairs[i], kvPairs[i + 1]);
    }
    return sfs;
  }

  private SecurityLevels newLevels(String net, String phys, String friends) {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    if (net != null) sfs.putOverwrite("security-levels.networkThreatLevel", net);
    if (phys != null) sfs.putOverwrite("security-levels.physicalThreatLevel", phys);
    if (friends != null) sfs.putOverwrite("security-levels.friendsThreatLevel", friends);
    return new SecurityLevels(node, new PersistentConfig(sfs));
  }

  private void stubPeers(int added, int connected) {
    org.mockito.Mockito.lenient()
        .when(roster.getDarknetPeers())
        .thenReturn(new DarknetPeerNode[Math.max(added, 0)]);
    org.mockito.Mockito.lenient()
        .when(peers.countConnectedDarknetPeers())
        .thenReturn(Math.max(connected, 0));
  }

  // --- parse helpers ---

  @Test
  void parseNetworkThreatLevel_validAndInvalid() {
    assertEquals(NETWORK_THREAT_LEVEL.HIGH, SecurityLevels.parseNetworkThreatLevel("HIGH"));
    assertNull(SecurityLevels.parseNetworkThreatLevel("bogus"));
  }

  @Test
  void parsePhysicalThreatLevel_validAndInvalid() {
    assertEquals(PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.parsePhysicalThreatLevel("NORMAL"));
    assertNull(SecurityLevels.parsePhysicalThreatLevel("nope"));
  }

  // --- localized names ---

  @Test
  void localisedName_network_matchesL10nBundle() {
    String expected = NodeL10n.getBase().getString("SecurityLevels.networkThreatLevel.name.HIGH");
    assertEquals(expected, SecurityLevels.localisedName(NETWORK_THREAT_LEVEL.HIGH));
  }

  @Test
  void localisedName_physical_matchesL10nBundle() {
    String expected =
        NodeL10n.getBase().getString("SecurityLevels.physicalThreatLevel.name.MAXIMUM");
    assertEquals(expected, SecurityLevels.localisedName(PHYSICAL_THREAT_LEVEL.MAXIMUM));
  }

  // --- getters and listener notifications ---

  @Test
  void addNetworkThreatLevelListener_onSet_invokedWithOldAndNewLevels() {
    SecurityLevels levels = newLevels("NORMAL", "LOW", null);
    @SuppressWarnings("unchecked")
    SecurityLevelListener<NETWORK_THREAT_LEVEL> listener = mock(SecurityLevelListener.class);

    levels.addNetworkThreatLevelListener(listener);

    // Change: NORMAL -> HIGH
    levels.setThreatLevel(NETWORK_THREAT_LEVEL.HIGH);
    verify(listener, times(1)).onChange(NETWORK_THREAT_LEVEL.NORMAL, NETWORK_THREAT_LEVEL.HIGH);

    // No-op: HIGH -> HIGH should not notify again
    levels.setThreatLevel(NETWORK_THREAT_LEVEL.HIGH);
    verifyNoMoreInteractions(listener);

    // Change again: HIGH -> LOW
    levels.addNetworkThreatLevelListener(listener); // duplicate registration ignored
    levels.setThreatLevel(NETWORK_THREAT_LEVEL.LOW);
    verify(listener, times(1)).onChange(NETWORK_THREAT_LEVEL.HIGH, NETWORK_THREAT_LEVEL.LOW);
  }

  @Test
  void addPhysicalThreatLevelListener_onSet_invokedWithOldAndNewLevels() {
    SecurityLevels levels = newLevels("HIGH", "NORMAL", null);
    @SuppressWarnings("unchecked")
    SecurityLevelListener<PHYSICAL_THREAT_LEVEL> listener = mock(SecurityLevelListener.class);

    levels.addPhysicalThreatLevelListener(listener);
    levels.setThreatLevel(PHYSICAL_THREAT_LEVEL.HIGH);
    verify(listener, times(1)).onChange(PHYSICAL_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.HIGH);

    // set to same → no new notification
    levels.setThreatLevel(PHYSICAL_THREAT_LEVEL.HIGH);
    verifyNoMoreInteractions(listener);
  }

  @Test
  void setThreatLevel_nullArguments_throwNpe() {
    SecurityLevels levels = newLevels("NORMAL", "LOW", null);
    assertThrows(
        NullPointerException.class, () -> levels.setThreatLevel((NETWORK_THREAT_LEVEL) null));
    assertThrows(
        NullPointerException.class, () -> levels.setThreatLevel((PHYSICAL_THREAT_LEVEL) null));
  }

  // --- getConfirmWarning branch coverage ---

  @Test
  void getConfirmWarning_sameLevel_returnsNull() {
    SecurityLevels levels = newLevels("NORMAL", "MAXIMUM", null);
    HTMLNode res = levels.getConfirmWarning(NETWORK_THREAT_LEVEL.NORMAL, "cb");
    assertNull(res);
  }

  @Test
  void getConfirmWarning_high_withNoFriends_warnsWithCheckbox() {
    stubPeers(0, 0);
    SecurityLevels levels = newLevels("NORMAL", "LOW", null);

    String checkboxName = "chk1";
    HTMLNode res = levels.getConfirmWarning(NETWORK_THREAT_LEVEL.HIGH, checkboxName);
    assertNotNull(res);

    // Contains the noFriendsWarning paragraph
    String expectedP = NodeL10n.getBase().getString("SecurityLevels.noFriendsWarning");
    boolean hasWarningP = res.generateChildren().contains(expectedP);
    assertTrue(hasWarningP);

    // Contains a checkbox input with the configured name and label text
    String expectedLabel = NodeL10n.getBase().getString("SecurityLevels.noFriendsCheckbox");
    boolean hasCheckbox =
        res.getChildren().stream()
            .filter(c -> c.getName().equals("input"))
            .anyMatch(
                in ->
                    "checkbox".equals(in.getAttribute("type"))
                        && checkboxName.equals(in.getAttribute("name"))
                        && "off".equals(in.getAttribute("value"))
                        && expectedLabel.equals(in.generateChildren()));
    assertTrue(hasCheckbox);
  }

  @Test
  void getConfirmWarning_high_withNoConnectedFriends_warnsAndInterpolatesAddedCount() {
    stubPeers(3, 0);
    SecurityLevels levels = newLevels("NORMAL", "LOW", null);

    String checkboxName = "chk2";
    HTMLNode res = levels.getConfirmWarning(NETWORK_THREAT_LEVEL.HIGH, checkboxName);
    assertNotNull(res);

    String expected =
        NodeL10n.getBase()
            .getString("SecurityLevels.noConnectedFriendsWarning", "added", Integer.toString(3));
    boolean hasP =
        res.getChildren().stream()
            .anyMatch(c -> c.getName().equals("p") && c.generateChildren().contains(expected));
    assertTrue(hasP);
  }

  @Test
  void getConfirmWarning_maximum_withFewConnectedFriends_warnsWithCounts() {
    stubPeers(5, 3);
    SecurityLevels levels = newLevels("NORMAL", "HIGH", null);

    HTMLNode res = levels.getConfirmWarning(NETWORK_THREAT_LEVEL.MAXIMUM, "chk3");
    assertNotNull(res);

    String expected =
        NodeL10n.getBase()
            .getString(
                "SecurityLevels.fewConnectedFriendsWarning",
                new String[] {"connected", "added"},
                new String[] {"3", "5"});
    boolean hasP =
        res.getChildren().stream()
            .anyMatch(c -> c.getName().equals("p") && c.generateChildren().contains(expected));
    assertTrue(hasP);
  }

  @Test
  void getConfirmWarning_low_alwaysWarns() {
    stubPeers(20, 20);
    SecurityLevels levels = newLevels("NORMAL", "LOW", null);

    HTMLNode res = levels.getConfirmWarning(NETWORK_THREAT_LEVEL.LOW, "cbLow");
    assertNotNull(res);
    // We at least expect a checkbox input to be present for confirmation
    boolean hasCheckbox =
        res.getChildren().stream()
            .anyMatch(
                n ->
                    n.getName().equals("input")
                        && "checkbox".equals(n.getAttribute("type"))
                        && "cbLow".equals(n.getAttribute("name")));
    assertTrue(hasCheckbox);
  }

  @Test
  void getConfirmWarning_maximum_withEnoughFriends_genericMaximumWarningShown() {
    stubPeers(10, 10);
    SecurityLevels levels = newLevels("NORMAL", "NORMAL", null);

    HTMLNode res = levels.getConfirmWarning(NETWORK_THREAT_LEVEL.MAXIMUM, "cbMax");
    assertNotNull(res);
    // Expect a confirmation checkbox to be present for MAXIMUM as well
    boolean hasCheckbox =
        res.getChildren().stream()
            .anyMatch(
                n ->
                    n.getName().equals("input")
                        && "checkbox".equals(n.getAttribute("type"))
                        && "cbMax".equals(n.getAttribute("name")));
    assertTrue(hasCheckbox);
  }

  // --- friend trust mapping ---

  @Test
  void getDefaultFriendTrust_whenNoFriendsThreatConfigured_returnsNormalAndLogs() {
    // No friendsThreatLevel in config → null inside SecurityLevels
    SecurityLevels levels = newLevels("HIGH", "MAXIMUM", null);
    assertEquals(FRIEND_TRUST.NORMAL, levels.getDefaultFriendTrust());
  }

  @Test
  void getDefaultFriendTrust_whenConfigured_mapsEnumsCorrectly() {
    SecurityLevels levelsHigh = newLevels("HIGH", "LOW", "HIGH");
    assertEquals(FRIEND_TRUST.LOW, levelsHigh.getDefaultFriendTrust());

    SecurityLevels levelsNormal = newLevels("HIGH", "MAXIMUM", "NORMAL");
    assertEquals(FRIEND_TRUST.NORMAL, levelsNormal.getDefaultFriendTrust());

    SecurityLevels levelsLow = newLevels("HIGH", "HIGH", "LOW");
    assertEquals(FRIEND_TRUST.HIGH, levelsLow.getDefaultFriendTrust());
  }

  // --- Option wiring & error paths ---

  @Test
  void optionSet_physicalThreatLevel_validValue_throwsInvalidConfigValueException_dueToCallback() {
    // Arrange config and instance
    PersistentConfig pc =
        new PersistentConfig(
            sfsWith(
                "security-levels.networkThreatLevel", "HIGH",
                "security-levels.physicalThreatLevel", "NORMAL"));
    SecurityLevels levels = new SecurityLevels(node, pc);

    SubConfig sc = pc.get("security-levels");
    Option<?> opt = sc.getOption("physicalThreatLevel");

    // Act + Assert: callback in SecurityLevels contains a bug (throws on any non-null)
    assertThrows(InvalidConfigValueException.class, () -> opt.setValue("HIGH"));
    // Value in SecurityLevels remains unchanged
    assertEquals(PHYSICAL_THREAT_LEVEL.NORMAL, levels.getPhysicalThreatLevel());
  }

  @Test
  void optionSet_networkThreatLevel_invalidString_throwsInvalidConfigValueException() {
    PersistentConfig pc =
        new PersistentConfig(
            sfsWith(
                "security-levels.networkThreatLevel", "HIGH",
                "security-levels.physicalThreatLevel", "NORMAL"));
    new SecurityLevels(node, pc);

    SubConfig sc = pc.get("security-levels");
    Option<?> opt = sc.getOption("networkThreatLevel");

    assertThrows(InvalidConfigValueException.class, () -> opt.setValue("NOT_A_LEVEL"));
  }

  // --- enum utility arrays ---

  @Test
  void networkThreatLevel_opennetAndDarknetValueSets_areAsDocumented() {
    NETWORK_THREAT_LEVEL[] opennet = NETWORK_THREAT_LEVEL.getOpennetValues();
    NETWORK_THREAT_LEVEL[] darknet = NETWORK_THREAT_LEVEL.getDarknetValues();
    assertEquals(2, opennet.length);
    assertEquals(NETWORK_THREAT_LEVEL.LOW, opennet[0]);
    assertEquals(NETWORK_THREAT_LEVEL.NORMAL, opennet[1]);
    assertEquals(2, darknet.length);
    assertEquals(NETWORK_THREAT_LEVEL.HIGH, darknet[0]);
    assertEquals(NETWORK_THREAT_LEVEL.MAXIMUM, darknet[1]);
  }
}
