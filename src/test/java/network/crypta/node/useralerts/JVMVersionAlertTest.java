package network.crypta.node.useralerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.JVMVersion;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class JVMVersionAlertTest {

  @Test
  void constructor_whenCreated_expectDefaultsAndDismissalConfigured() {
    // Arrange + Act
    JVMVersionAlert alert = new JVMVersionAlert();

    // Assert
    assertTrue(alert.userCanDismiss());
    assertTrue(alert.isValid());
    assertEquals(UserAlert.WARNING, alert.getPriorityClass());
    assertEquals(NodeL10n.getBase().getString("UserAlert.hide"), alert.dismissButtonText());
    assertTrue(alert.shouldUnregisterOnDismiss());
    assertFalse(alert.isEventNotification());
  }

  @Test
  void getTitle_whenCalled_expectLocalizedTitleString() {
    JVMVersionAlert alert = new JVMVersionAlert();

    String expected = NodeL10n.getBase().getString("JavaEOLAlert.title");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  void getText_whenCalled_expectBodyWithCurrentVersionAndThreshold() {
    JVMVersionAlert alert = new JVMVersionAlert();

    String expected =
        NodeL10n.getBase()
            .getString(
                "JavaEOLAlert.body",
                new String[] {"current", "new"},
                new String[] {JVMVersion.getCurrent(), JVMVersion.EOL_THRESHOLD});

    assertEquals(expected, alert.getText());
  }

  @Test
  void getShortText_whenCalled_expectSameAsTitle() {
    JVMVersionAlert alert = new JVMVersionAlert();

    assertEquals(alert.getTitle(), alert.getShortText());
  }

  @Test
  void getHTMLText_whenCalled_expectDivWrappingPlainText() {
    JVMVersionAlert alert = new JVMVersionAlert();
    String expectedText = alert.getText();

    HTMLNode html = alert.getHTMLText();
    assertNotNull(html);
    assertEquals("div", html.getName());
    // The constructor stores text as a single child text node for non-"#" elements.
    assertFalse(
        html.getChildren().isEmpty(),
        "Expected the <div> to have a single text child with the message");
    assertEquals(expectedText, html.getChildren().getFirst().getContent());
  }
}
