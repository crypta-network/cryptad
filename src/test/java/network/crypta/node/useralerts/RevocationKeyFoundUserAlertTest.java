package network.crypta.node.useralerts;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Allow method_whenCondition_expectOutcome test naming.
class RevocationKeyFoundUserAlertTest {

  @BeforeEach
  void setUpEnglishL10n() {
    // Ensure a deterministic language for lookups regardless of global test order.
    new NodeL10n(LANGUAGE.ENGLISH, new File("."));
  }

  @Test
  void constructor_whenDisabledNotBlownTrue_buildsCriticalNonDismissibleAlertWithDisabledTextAndHtml() {
    // Arrange
    String message = "Key revoked: C\\\
temp\\file and $HOME";

    String expectedTitle =
        NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.titleDisabled");
    String expectedFirstP =
        NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.textDisabled");
    String expectedSecondP =
        NodeL10n.getBase()
            .getString("RevocationKeyFoundUserAlert.textDisabledDetail", "message", message);
    String expectedText = expectedFirstP + " " + expectedSecondP;

    // Act
    RevocationKeyFoundUserAlert alert = new RevocationKeyFoundUserAlert(message, true);

    // Assert
    assertAll(
        // Core properties
        () -> assertFalse(alert.userCanDismiss(), "Alert must not be user-dismissible"),
        () -> assertEquals(UserAlert.CRITICAL_ERROR, alert.getPriorityClass()),
        () -> assertTrue(alert.isValid(), "Alert must be valid by default"),
        () -> assertEquals(expectedTitle, alert.getTitle()),
        () -> assertEquals(expectedText, alert.getText()),
        () -> assertEquals(expectedText, alert.getShortText()),
        () -> assertEquals(Integer.toString(alert.hashCode()), alert.anchor()),
        () -> assertEquals(null, alert.dismissButtonText()),
        () -> assertFalse(alert.shouldUnregisterOnDismiss()));

    HTMLNode html = alert.getHTMLText();
    assertNotNull(html, "HTML body must be present");
    assertEquals("div", html.getName());
    assertEquals(2, html.getChildren().size(), "HTML body must contain two paragraphs");

    HTMLNode p1 = html.getChildren().get(0);
    HTMLNode p2 = html.getChildren().get(1);
    assertEquals("p", p1.getName());
    assertEquals("p", p2.getName());
    assertEquals(expectedFirstP, p1.generateChildren());
    assertEquals(expectedSecondP, p2.generateChildren());

    // Changing validity must be ignored (always valid)
    alert.isValid(false);
    assertTrue(alert.isValid(), "Validity changes must be ignored");
  }

  @Test
  void constructor_whenDisabledNotBlownFalse_buildsCriticalNonDismissibleAlertWithActiveTextAndHtml() {
    // Arrange
    String message = "Update feed compromised (nonce=$N, path=/var/lib)";

    String expectedTitle = NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.title");
    String expectedFirstP = NodeL10n.getBase().getString("RevocationKeyFoundUserAlert.text");
    String expectedSecondP =
        NodeL10n.getBase()
            .getString("RevocationKeyFoundUserAlert.textDetail", "message", message);
    String expectedText = expectedFirstP + " " + expectedSecondP;

    // Act
    RevocationKeyFoundUserAlert alert = new RevocationKeyFoundUserAlert(message, false);

    // Assert
    assertAll(
        () -> assertFalse(alert.userCanDismiss()),
        () -> assertEquals(UserAlert.CRITICAL_ERROR, alert.getPriorityClass()),
        () -> assertTrue(alert.isValid()),
        () -> assertEquals(expectedTitle, alert.getTitle()),
        () -> assertEquals(expectedText, alert.getText()),
        () -> assertEquals(expectedText, alert.getShortText()));

    HTMLNode html = alert.getHTMLText();
    assertNotNull(html);
    assertEquals("div", html.getName());
    assertEquals(2, html.getChildren().size());
    assertEquals("p", html.getChildren().get(0).getName());
    assertEquals("p", html.getChildren().get(1).getName());
    assertEquals(expectedFirstP, html.getChildren().get(0).generateChildren());
    assertEquals(expectedSecondP, html.getChildren().get(1).generateChildren());
  }
}

