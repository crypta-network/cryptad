package network.crypta.node.useralerts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PeersOffersUserAlertTest {

  @Mock private Node node;
  @Mock private NodeClientCore core;
  @Mock private UserAlertManager alertManager;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() throws IOException {
    ProgramDirectory programDirectory = new ProgramDirectory();
    programDirectory.move(tempDir.toString());

    when(node.runDir()).thenReturn(programDirectory);
    when(node.getClientCore()).thenReturn(core);
    when(core.getAlerts()).thenReturn(alertManager);
    when(core.getFormPassword()).thenReturn("pw123");
  }

  @Test
  void createAlert_whenPeersOffersHasFrefFiles_registersAlertWithFilenamesInHtml()
      throws IOException {
    // Arrange
    Path offersDir = tempDir.resolve("peers-offers");
    Files.createDirectories(offersDir);
    Files.writeString(offersDir.resolve("friend1.fref"), "", StandardCharsets.UTF_8);
    Files.writeString(offersDir.resolve("note.txt"), "ignore", StandardCharsets.UTF_8);
    Files.createDirectories(offersDir.resolve("nested"));

    ArgumentCaptor<UserAlert> captor = ArgumentCaptor.forClass(UserAlert.class);

    // Act
    PeersOffersUserAlert.createAlert(node);

    // Assert
    verify(alertManager, times(1)).register(captor.capture());
    UserAlert captured = captor.getValue();
    assertNotNull(captured, "registered alert");
    assertTrue(captured.userCanDismiss(), "user can dismiss");
    assertTrue(captured.shouldUnregisterOnDismiss(), "should unregister on dismiss");

    // Title and localization keys should resolve
    assertEquals(
        NodeL10n.getBase().getString("PeersOffersUserAlert.title"),
        captured.getTitle(),
        "localized title");

    // Generated HTML contains the expected elements and values
    HTMLNode html = captured.getHTMLText();
    String htmlStr = html.generate(new StringBuilder()).toString();

    assertTrue(htmlStr.contains("friend1.fref"), "includes .fref filename");
    assertFalse(htmlStr.contains("note.txt"), "excludes non-.fref files");

    assertTrue(htmlStr.contains("form"), "has form tag");
    assertTrue(htmlStr.contains("action=\"/friends/\""), "form action");
    assertTrue(htmlStr.contains("method=\"post\""), "form method");

    assertTrue(htmlStr.contains("name=\"formPassword\""), "hidden formPassword input present");
    assertTrue(htmlStr.contains("value=\"pw123\""), "formPassword value included");
    assertTrue(htmlStr.contains("name=\"peers-offers-files\""), "hidden peers-offers-files input");
    assertTrue(htmlStr.contains("value=\"true\""), "peers-offers-files=true");

    // Submit button
    assertTrue(htmlStr.contains("type=\"submit\""), "submit button present");
    assertTrue(htmlStr.contains("name=\"add\""), "submit button name");
    assertTrue(htmlStr.contains("value=\"Connect\""), "submit button value");

    // Complex nodes add radio groups for trust/visibility
    assertTrue(htmlStr.contains("name=\"trust\""), "trust radios present");
    assertTrue(htmlStr.contains("name=\"visibility\""), "visibility radios present");
  }

  @Test
  void createAlert_whenPeersOffersDirMissing_doesNotRegister() {
    // Arrange: do not create the directory; listFiles() will be null

    // Act
    PeersOffersUserAlert.createAlert(node);

    // Assert
    verify(alertManager, never()).register(any());
  }

  @Test
  void createAlert_whenNoFrefFiles_registersButDoesNotListNames() throws IOException {
    // Arrange: directory exists but contains no .fref files
    Path offersDir = tempDir.resolve("peers-offers");
    Files.createDirectories(offersDir);
    Files.writeString(offersDir.resolve("some.txt"), "x", StandardCharsets.UTF_8);

    ArgumentCaptor<UserAlert> captor = ArgumentCaptor.forClass(UserAlert.class);

    // Act
    PeersOffersUserAlert.createAlert(node);

    // Assert: alert is still registered when directory is non-empty
    verify(alertManager, times(1)).register(captor.capture());
    UserAlert captured = captor.getValue();
    String htmlStr = captured.getHTMLText().generate(new StringBuilder()).toString();
    assertFalse(htmlStr.contains("some.txt"), "non-.fref file names are not shown");
  }

  @Test
  void onDismiss_whenConfigAccepts_setsConfigAndStaysValid() throws IOException {
    // Arrange: create a real config with the expected boolean option
    PersistentConfig cfg = new PersistentConfig(null);
    SubConfig nodeCfg = cfg.createSubConfig("node");
    // Register the boolean option with default=false
    nodeCfg.register("peersOffersDismissed", false, 0, false, true, "short", "long", null);
    // SubConfig registers itself with the owning config in its constructor.
    when(node.getConfig()).thenReturn(cfg);

    // Ensure alert is created so we can capture and invoke onDismiss()
    Path offersDir = tempDir.resolve("peers-offers");
    Files.createDirectories(offersDir);
    Files.writeString(offersDir.resolve("peer.fref"), "", StandardCharsets.UTF_8);

    ArgumentCaptor<UserAlert> captor = ArgumentCaptor.forClass(UserAlert.class);
    PeersOffersUserAlert.createAlert(node);
    verify(alertManager, times(1)).register(captor.capture());
    UserAlert captured = captor.getValue();

    // Act
    captured.onDismiss();

    // Assert: option set and alert remains valid
    assertTrue(nodeCfg.getBoolean("peersOffersDismissed"), "config flag set to true");
    assertTrue(captured.isValid(), "alert remains valid on success");
  }

  @Test
  void onDismiss_whenConfigThrows_setsAlertInvalid()
      throws IOException, InvalidConfigValueException, NodeNeedRestartException {
    // Arrange: mock SubConfig#set to throw and verify alert validity flips to false
    PersistentConfig cfg = org.mockito.Mockito.mock(PersistentConfig.class);
    SubConfig nodeCfg = org.mockito.Mockito.mock(SubConfig.class);
    when(cfg.get("node")).thenReturn(nodeCfg);
    when(node.getConfig()).thenReturn(cfg);
    org.mockito.Mockito.doThrow(new InvalidConfigValueException("bad"))
        .when(nodeCfg)
        .set("peersOffersDismissed", true);

    // Need an alert instance to call onDismiss()
    Path offersDir = tempDir.resolve("peers-offers");
    Files.createDirectories(offersDir);
    Files.writeString(offersDir.resolve("peer.fref"), "", StandardCharsets.UTF_8);

    ArgumentCaptor<UserAlert> captor = ArgumentCaptor.forClass(UserAlert.class);
    PeersOffersUserAlert.createAlert(node);
    verify(alertManager, times(1)).register(captor.capture());
    UserAlert captured = captor.getValue();

    // Precondition
    assertTrue(captured.isValid(), "starts valid");

    // Act
    captured.onDismiss();

    // Assert: becomes invalid on exception
    assertFalse(captured.isValid(), "becomes invalid on config error");
  }
}
