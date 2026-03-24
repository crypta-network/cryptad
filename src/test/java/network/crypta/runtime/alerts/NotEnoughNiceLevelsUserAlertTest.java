package network.crypta.runtime.alerts;

import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NotEnoughNiceLevelsUserAlertTest {

  @Test
  @DisplayName("title_whenCreated_returnsLocalizedTitle")
  void title_whenCreated_returnsLocalizedTitle() {
    // Arrange
    NotEnoughNiceLevelsUserAlert alert = new NotEnoughNiceLevelsUserAlert();
    String expected = NodeL10n.getBase().getString("NotEnoughNiceLevelsUserAlert.title");

    // Act
    String actual = alert.getTitle();

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  @DisplayName("text_whenCreated_includesAvailableAndRequiredValues")
  void text_whenCreated_includesAvailableAndRequiredValues() {
    // Arrange
    NotEnoughNiceLevelsUserAlert alert = new NotEnoughNiceLevelsUserAlert();
    String[] patterns = new String[] {"available", "required"};
    String[] values =
        new String[] {
          String.valueOf(NativeThread.NATIVE_PRIORITY_RANGE),
          String.valueOf(NativeThread.ENOUGH_NICE_LEVELS)
        };
    String expected =
        NodeL10n.getBase().getString("NotEnoughNiceLevelsUserAlert.content", patterns, values);

    // Act
    String actual = alert.getText();

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  @DisplayName("shortText_whenCreated_returnsLocalizedShortText")
  void shortText_whenCreated_returnsLocalizedShortText() {
    // Arrange
    NotEnoughNiceLevelsUserAlert alert = new NotEnoughNiceLevelsUserAlert();
    String expected = NodeL10n.getBase().getString("NotEnoughNiceLevelsUserAlert.short");

    // Act
    String actual = alert.getShortText();

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  @DisplayName("htmlText_whenCreated_wrapsTextInDiv")
  void htmlText_whenCreated_wrapsTextInDiv() {
    // Arrange
    NotEnoughNiceLevelsUserAlert alert = new NotEnoughNiceLevelsUserAlert();
    String expectedText = alert.getText();

    // Act
    HTMLNode html = alert.getHTMLText();

    // Assert
    assertNotNull(html);
    assertEquals("div", html.getName());
    assertEquals(HTMLEncoder.encode(expectedText), html.generateChildren());
  }

  @Test
  @DisplayName("dismiss_whenCreated_userCanDismiss_unregisterOnDismiss_andHasLabel")
  void dismiss_whenCreated_userCanDismiss_unregisterOnDismiss_andHasLabel() {
    // Arrange
    NotEnoughNiceLevelsUserAlert alert = new NotEnoughNiceLevelsUserAlert();
    String expectedDismissLabel = NodeL10n.getBase().getString("UserAlert.hide");

    // Act & Assert
    assertTrue(alert.userCanDismiss());
    assertTrue(alert.shouldUnregisterOnDismiss());
    assertEquals(expectedDismissLabel, alert.dismissButtonText());
  }

  @Test
  @DisplayName("priority_whenCreated_isWarning")
  void priority_whenCreated_isWarning() {
    // Arrange
    NotEnoughNiceLevelsUserAlert alert = new NotEnoughNiceLevelsUserAlert();

    // Act & Assert
    assertEquals(UserAlert.WARNING, alert.getPriorityClass());
  }

  @Test
  @DisplayName("validity_whenToggled_reflectsState")
  void validity_whenToggled_reflectsState() {
    // Arrange
    NotEnoughNiceLevelsUserAlert alert = new NotEnoughNiceLevelsUserAlert();
    assertTrue(alert.isValid());

    // Act: since the alert is user-dismissible, toggling validity should be honored
    alert.isValid(false);
    boolean afterFalse = alert.isValid();
    alert.isValid(true);
    boolean afterTrue = alert.isValid();

    // Assert
    assertFalse(afterFalse);
    assertTrue(afterTrue);
  }
}
