package network.crypta.runtime.alerts;

import java.io.File;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.PeerTooOldException;
import network.crypta.runtime.alerts.feed.BasicUserAlertFeedEvent;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // descriptive test method names
class DroppedOldPeersUserAlertTest {

  @Test
  void isEmpty_whenNoAdds_expectTrueAndAfterAddFalse(@TempDir java.nio.file.Path tmp) {
    // Arrange
    DroppedOldPeersUserAlert alert =
        new DroppedOldPeersUserAlert(tmp.resolve("peers.lst").toFile());

    // Assert precondition
    assertTrue(alert.isEmpty());

    // Act
    alert.add(new PeerTooOldException("old", 1, Instant.EPOCH), "Alice");

    // Assert
    assertFalse(alert.isEmpty());
  }

  @Test
  void add_whenNameNullAndQuoted_expectListAndHtmlContainBoth(@TempDir java.nio.file.Path tmp) {
    // Arrange
    File peersFile = tmp.resolve("dropped-peers.lst").toFile();
    DroppedOldPeersUserAlert alert = new DroppedOldPeersUserAlert(peersFile);
    Instant d1 = Instant.ofEpochSecond(1_000);
    Instant d2 = Instant.ofEpochSecond(2_000);

    // Act: add a named and an unnamed (null) peer
    alert.add(new PeerTooOldException("too old", 5, d1), "Alice");
    alert.add(new PeerTooOldException("ancient", 3, d2), null);

    // Assert (text): first line contains filename from l10n intro, then list label, then two names
    String text = alert.getText();
    List<String> lines = text.lines().toList();
    assertTrue(lines.get(0).contains(peersFile.toString()));
    assertEquals(
        NodeL10n.getBase().getString("DroppedOldPeersUserAlert.droppingOldFriendList"),
        lines.get(1));
    assertEquals("\"Alice\"", lines.get(2));
    assertEquals("(unknown name)", lines.get(3));

    // Assert (HTML): structure contains a single <ul> with two <li> entries in order
    HTMLNode html = alert.getHTMLText();
    assertNotNull(html);
    List<HTMLNode> children = html.getChildren();
    HTMLNode ul = null;
    for (HTMLNode child : children) {
      if ("ul".equals(child.getName())) {
        ul = child;
        break;
      }
    }
    assertNotNull(ul, "Expected a <ul> element in HTML output");
    List<HTMLNode> liNodes = ul.getChildren();
    assertEquals(2, liNodes.size());
    assertEquals("li", liNodes.get(0).getName());
    assertEquals("\"Alice\"", liNodes.get(0).getChildren().getFirst().getContent());
    assertEquals("(unknown name)", liNodes.get(1).getChildren().getFirst().getContent());

    // Assert (other invariants)
    assertTrue(alert.userCanDismiss());
    assertTrue(alert.shouldUnregisterOnDismiss());
    assertFalse(alert.isEventNotification());
    assertEquals(UserAlert.CRITICAL_ERROR, alert.getPriorityClass());
    assertEquals("droppedPeersUserAlert", alert.anchor());
    assertEquals(NodeL10n.getBase().getString("UserAlert.hide"), alert.dismissButtonText());
  }

  @Test
  void getTitle_whenMultipleBuilds_expectBuildDateFromMaxBuild(@TempDir java.nio.file.Path tmp) {
    // Arrange
    DroppedOldPeersUserAlert alert =
        new DroppedOldPeersUserAlert(tmp.resolve("peers.txt").toFile());
    Instant older = Instant.ofEpochMilli(1_000L);
    Instant newer = Instant.ofEpochMilli(2_000L);

    // Act: first smaller build (should not win), then larger build (should win)
    alert.add(new PeerTooOldException("x", 1, newer), "P1");
    alert.add(new PeerTooOldException("y", 20, older), "P2");

    // Assert: title includes the date string of the max buildNumber entry (older)
    String title = alert.getTitle();
    String expectedDate =
        DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss zzz yyyy", Locale.US)
            .withZone(ZoneId.systemDefault())
            .format(older);
    assertTrue(title.contains(expectedDate));
  }

  @Test
  void getShortText_whenCalled_expectSameAsTitle(@TempDir java.nio.file.Path tmp) {
    // Arrange
    DroppedOldPeersUserAlert alert = new DroppedOldPeersUserAlert(tmp.resolve("p.txt").toFile());
    alert.add(new PeerTooOldException("r", 7, Instant.EPOCH), "N");

    // Act + Assert
    assertEquals(alert.getTitle(), alert.getShortText());
  }

  @Test
  void getFeedEvent_whenBuilt_expectFieldsMatchAlert(@TempDir java.nio.file.Path tmp) {
    // Arrange
    DroppedOldPeersUserAlert alert =
        new DroppedOldPeersUserAlert(tmp.resolve("peers.bin").toFile());
    alert.add(new PeerTooOldException("r", 42, Instant.ofEpochMilli(1234)), "Zed");

    // Act
    BasicUserAlertFeedEvent event = (BasicUserAlertFeedEvent) alert.getFeedEvent();

    // Assert: fields match the alert, including encoded plain-text length
    assertEquals(alert.getTitle(), event.header());
    assertEquals(alert.getShortText(), event.shortText());
    assertEquals(alert.getText(), event.text());
    assertEquals(UserAlert.CRITICAL_ERROR, event.priorityClass());
    assertEquals(alert.getUpdatedTime(), event.updatedTime());

    int expectedLen = alert.getText().getBytes(UTF_8).length;
    assertEquals(expectedLen, event.text().getBytes(UTF_8).length);
  }

  @Test
  void isValid_whenToggled_expectAlwaysTrueAndNoThrow(@TempDir java.nio.file.Path tmp) {
    // Arrange
    DroppedOldPeersUserAlert alert = new DroppedOldPeersUserAlert(tmp.resolve("f.txt").toFile());
    // Act
    alert.isValid(false); // ignored
    // Assert
    assertTrue(alert.isValid());
  }
}
