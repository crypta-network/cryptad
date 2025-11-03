package network.crypta.node.useralerts;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import network.crypta.clients.fcp.FCPMessage;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class SimpleUserAlertTest {

  @Test
  void constructor_whenCreated_expectFieldsAndDismissalConfigured() {
    // Arrange + Act
    String title = "Test Title";
    String text = "This is a simple alert body.";
    String shortText = "Simple alert";
    short priority = UserAlert.WARNING;
    SimpleUserAlert alert = new SimpleUserAlert(true, title, text, shortText, priority);

    // Assert: basic flags and priority
    assertTrue(alert.userCanDismiss());
    assertTrue(alert.isValid());
    assertEquals(priority, alert.getPriorityClass());
    assertFalse(alert.isEventNotification());

    // Assert: content fields
    assertEquals(title, alert.getTitle());
    assertEquals(text, alert.getText());
    assertEquals(shortText, alert.getShortText());

    // Assert: HTML wrapper is a <div> with a single text node of the body text
    HTMLNode html = alert.getHTMLText();
    assertNotNull(html);
    assertEquals("div", html.getName());
    assertFalse(html.getChildren().isEmpty());
    assertEquals(text, html.getChildren().getFirst().getContent());

    // Assert: dismissal button text and behavior
    assertEquals(NodeL10n.getBase().getString("UserAlert.hide"), alert.dismissButtonText());
    assertTrue(alert.shouldUnregisterOnDismiss());

    // Anchor should be the hashCode rendered as string
    assertEquals(Integer.toString(alert.hashCode()), alert.anchor());
  }

  @Test
  void isValid_whenToggled_expectNoEffectRegardlessOfDismissFlag() {
    // Arrange: one dismissible and one non-dismissible alert
    SimpleUserAlert dismissible = new SimpleUserAlert(true, "t1", "x", "s", UserAlert.MINOR);
    SimpleUserAlert nonDismissible = new SimpleUserAlert(false, "t2", "y", "s", UserAlert.ERROR);

    assertTrue(dismissible.isValid());
    assertTrue(nonDismissible.isValid());

    // Act: calling isValid(false) is a no-op in SimpleUserAlert
    dismissible.isValid(false);
    nonDismissible.isValid(false);

    // Assert: both remain valid
    assertTrue(dismissible.isValid());
    assertTrue(nonDismissible.isValid());
  }

  @Test
  void constructor_whenNullBodyAndTitle_expectGracefulNullsAndEmptyHtmlDiv() {
    // Arrange + Act
    SimpleUserAlert alert = new SimpleUserAlert(false, null, null, null, UserAlert.ERROR);

    // Assert: content fields may be null when constructed as such
    assertNull(alert.getTitle());
    assertNull(alert.getText());
    assertNull(alert.getShortText());

    // HTML node exists and is an empty <div>
    HTMLNode html = alert.getHTMLText();
    assertNotNull(html);
    assertEquals("div", html.getName());
    assertTrue(html.getChildren().isEmpty());
    // generateChildren() should be empty when there are no children/content
    assertEquals("", html.generateChildren());

    // Flags
    assertFalse(alert.userCanDismiss());
    assertTrue(alert.isValid());
    assertEquals(NodeL10n.getBase().getString("UserAlert.hide"), alert.dismissButtonText());
    assertTrue(alert.shouldUnregisterOnDismiss());
  }

  @Test
  void getFCPMessage_whenCalled_expectFeedFieldsReflectAlert() {
    // Arrange
    String title = "Feed Title";
    String text = "Feed body text";
    String shortText = "Feed short";
    short priority = UserAlert.CRITICAL_ERROR;
    SimpleUserAlert alert = new SimpleUserAlert(true, title, text, shortText, priority);

    long updatedTime = alert.getUpdatedTime();
    assertTrue(updatedTime > 0L);

    // Act
    FCPMessage msg = alert.getFCPMessage();
    SimpleFieldSet fs = msg.getFieldSet();

    // Assert
    assertEquals("Feed", msg.getName());
    assertEquals(title, fs.get("Header"));
    assertEquals(shortText, fs.get("ShortText"));
    assertEquals(String.valueOf(priority), fs.get("PriorityClass"));
    assertEquals(String.valueOf(updatedTime), fs.get("UpdatedTime"));

    // Data length is encoded length of the plain text
    int expectedLen = text.getBytes(UTF_8).length;
    assertEquals(String.valueOf(expectedLen), fs.get("DataLength"));
  }
}
