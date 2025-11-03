package network.crypta.node.useralerts;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import network.crypta.clients.fcp.FCPMessage;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class TimeSkewDetectedUserAlertTest {

  @BeforeEach
  void ensureL10nInitialized() {
    // Ensure localization is initialized deterministically
    NodeL10n.getBase();
  }

  @Test
  @DisplayName("constructor_whenCreated_configuresSeverityDismissalAndValidity")
  void constructor_whenCreated_configuresSeverityDismissalAndValidity() {
    // Arrange + Act
    TimeSkewDetectedUserAlert alert = new TimeSkewDetectedUserAlert();

    // Assert: non-dismissible, initially invalid, critical priority
    assertFalse(alert.userCanDismiss());
    assertFalse(alert.isValid());
    assertEquals(UserAlert.CRITICAL_ERROR, alert.getPriorityClass());

    // Dismiss label is localized even if UI hides the control; unregister is false
    assertEquals(NodeL10n.getBase().getString("UserAlert.hide"), alert.dismissButtonText());
    assertFalse(alert.shouldUnregisterOnDismiss());
  }

  @Test
  @DisplayName("getTitleTextShort_whenCalled_returnsLocalizedStrings")
  void getTitleTextShort_whenCalled_returnsLocalizedStrings() {
    // Arrange
    TimeSkewDetectedUserAlert alert = new TimeSkewDetectedUserAlert();

    // Act + Assert
    assertEquals(NodeL10n.getBase().getString("TimeSkewDetectedUserAlert.title"), alert.getTitle());
    assertEquals(NodeL10n.getBase().getString("TimeSkewDetectedUserAlert.text"), alert.getText());
    assertEquals(
        NodeL10n.getBase().getString("TimeSkewDetectedUserAlert.shortText"), alert.getShortText());
  }

  @Test
  @DisplayName("getHTMLText_whenCalled_wrapsPlainTextInDiv")
  void getHTMLText_whenCalled_wrapsPlainTextInDiv() {
    // Arrange
    TimeSkewDetectedUserAlert alert = new TimeSkewDetectedUserAlert();

    // Act
    HTMLNode html = alert.getHTMLText();

    // Assert
    assertNotNull(html);
    assertEquals("div", html.getName());
    assertFalse(html.getChildren().isEmpty());
    assertEquals(
        NodeL10n.getBase().getString("TimeSkewDetectedUserAlert.text"),
        html.getChildren().getFirst().getContent());
  }

  @Test
  @DisplayName("isValid_whenToggled_expectNoEffectBecauseNonDismissible")
  void isValid_whenToggled_expectNoEffectBecauseNonDismissible() {
    // Arrange
    TimeSkewDetectedUserAlert alert = new TimeSkewDetectedUserAlert();
    assertFalse(alert.isValid());

    // Act: attempting to change validity should be ignored for non-dismissible alerts
    alert.isValid(true);

    // Assert: remains invalid
    assertFalse(alert.isValid());
  }

  @Test
  @DisplayName("getFCPMessage_whenCalled_containsExpectedFields")
  void getFCPMessage_whenCalled_containsExpectedFields() {
    // Arrange
    TimeSkewDetectedUserAlert alert = new TimeSkewDetectedUserAlert();
    long updated = alert.getUpdatedTime();

    String title = NodeL10n.getBase().getString("TimeSkewDetectedUserAlert.title");
    String text = NodeL10n.getBase().getString("TimeSkewDetectedUserAlert.text");
    String shortText = NodeL10n.getBase().getString("TimeSkewDetectedUserAlert.shortText");

    // Act
    FCPMessage msg = alert.getFCPMessage();
    SimpleFieldSet fs = msg.getFieldSet();

    // Assert: message name and fields match the alert
    assertEquals("Feed", msg.getName());
    assertEquals(title, fs.get("Header"));
    assertEquals(shortText, fs.get("ShortText"));
    assertEquals(String.valueOf(UserAlert.CRITICAL_ERROR), fs.get("PriorityClass"));
    assertEquals(String.valueOf(updated), fs.get("UpdatedTime"));

    int expectedLen = text.getBytes(UTF_8).length;
    assertEquals(String.valueOf(expectedLen), fs.get("DataLength"));
  }
}
