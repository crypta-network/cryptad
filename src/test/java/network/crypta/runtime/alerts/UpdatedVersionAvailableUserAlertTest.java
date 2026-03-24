package network.crypta.runtime.alerts;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UpdatedVersionAvailableUserAlertTest {

  @Mock private NodeUpdateManager updater;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore clientCore;

  @InjectMocks private UpdatedVersionAvailableUserAlert alert;

  @BeforeEach
  void setUp() {
    // Ensure the localization base is initialized (default language/resources)
    new NodeL10n();
    when(updater.getNode()).thenReturn(node);
  }

  @Test
  @DisplayName("title_returnsLocalizedTitle")
  void title_returnsLocalizedTitle() {
    String expected = NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.title");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("shortText_whenNotArmedReady_returnsShortReadyNotArmed")
  void shortText_whenNotArmedReady_returnsShortReadyNotArmed() {
    when(updater.isArmed()).thenReturn(false);
    when(updater.canUpdateNow()).thenReturn(true);

    String expected =
        NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.shortReadyNotArmed");
    assertEquals(expected, alert.getShortText());
  }

  @Test
  @DisplayName("shortText_whenNotArmedNotReady_returnsShortNotReadyNotArmed")
  void shortText_whenNotArmedNotReady_returnsShortNotReadyNotArmed() {
    when(updater.isArmed()).thenReturn(false);
    when(updater.canUpdateNow()).thenReturn(false);

    String expected =
        NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.shortNotReadyNotArmed");
    assertEquals(expected, alert.getShortText());
  }

  @Test
  @DisplayName("shortText_whenArmed_returnsShortArmed")
  void shortText_whenArmed_returnsShortArmed() {
    when(updater.isArmed()).thenReturn(true);

    String expected = NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.shortArmed");
    assertEquals(expected, alert.getShortText());
  }

  @Test
  @DisplayName("text_whenArmed_includesArmedMessageWithoutForm")
  void text_whenArmed_includesArmedMessageWithoutForm() {
    when(updater.isArmed()).thenReturn(true);
    String expectedArmed = NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.armed");

    String text = alert.getText();
    assertTrue(text.contains(expectedArmed), "armed message should be present");
    assertFalse(text.contains("<form"), "No form should be rendered when in final check");
  }

  @Test
  @DisplayName("text_whenCanUpdateNowImmediate_includesDownloadedLabelAndImmediateButton")
  void text_whenCanUpdateNowImmediate_includesDownloadedLabelAndImmediateButton() {
    when(updater.isArmed()).thenReturn(false);
    when(updater.canUpdateNow()).thenReturn(true);
    when(updater.hasNewCorePackage()).thenReturn(true);
    when(updater.newCorePackageVersion()).thenReturn(1234);
    when(updater.newCorePackageVersionLabel()).thenReturn("1.2.3+build123");
    when(updater.canUpdateImmediately()).thenReturn(true);
    when(node.network().updateIsUrgent()).thenReturn(false);

    String downloaded =
        NodeL10n.getBase()
            .getString(
                "UpdatedVersionAvailableUserAlert.downloadedNewJar", "version", "1.2.3+build123");
    String clickNow =
        NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.clickToUpdateNow");
    String button =
        NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.updateNowButton");

    String text = alert.getText();
    assertTrue(text.contains(downloaded), "Should mention downloaded jar version");
    assertTrue(text.contains(clickNow), "Should prompt to update now");
    assertTrue(text.contains("<form"), "Form should be present");
    assertTrue(text.contains("value=\"" + button + "\""), "Button text should be 'Update Now!'");
  }

  @Test
  @DisplayName("text_whenCanUpdateNowASAP_includesASAPPromptAndButton")
  void text_whenCanUpdateNowASAP_includesASAPPromptAndButton() {
    when(updater.isArmed()).thenReturn(false);
    when(updater.canUpdateNow()).thenReturn(true);
    when(updater.hasNewCorePackage()).thenReturn(false);
    when(updater.canUpdateImmediately()).thenReturn(false);
    when(node.network().updateIsUrgent()).thenReturn(false);

    String prompt =
        NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.clickToUpdateASAP");
    String button =
        NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.updateASAPButton");

    String text = alert.getText();
    assertTrue(text.contains(prompt), "Should prompt to update ASAP");
    assertTrue(text.contains("<form"), "Form should be present");
    assertTrue(text.contains("value=\"" + button + "\""), "ASAP button should be present");
  }

  @Test
  @DisplayName("text_whenFetchingFromUOM_includesScriptPathAndQuestion")
  void text_whenFetchingFromUOM_includesScriptPathAndQuestion() throws Exception {
    when(updater.isArmed()).thenReturn(false);
    when(updater.canUpdateNow()).thenReturn(false);
    when(updater.fetchingFromUOM()).thenReturn(true);
    when(updater.fetchingNewCorePackage()).thenReturn(false);
    when(node.network().updateIsUrgent()).thenReturn(false);

    Path nodeDir = Files.createTempDirectory("cryptad-node-test");
    try {
      // Create an update script at top-level so getUpdateScriptName returns the absolute path
      String scriptName = (File.separatorChar == '\\') ? "update.cmd" : "update.sh";
      Path script = nodeDir.resolve(scriptName);
      Files.writeString(script, "echo test");

      when(node.getNodeDir()).thenReturn(nodeDir.toFile());

      String fetching =
          NodeL10n.getBase()
              .getString(
                  "UpdatedVersionAvailableUserAlert.fetchingUOM",
                  "updateScript",
                  script.toFile().toString());
      String question =
          NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.updateASAPQuestion");

      String text = alert.getText();
      assertTrue(text.contains(fetching), "Should include fetching message with script path");
      assertTrue(text.contains(question), "Should ask the ASAP update question");
    } finally {
      // Clean up temp dir using try-with-resources to safely close the stream
      try (Stream<Path> walk = Files.walk(nodeDir)) {
        walk.sorted(Comparator.reverseOrder())
            .forEach(
                p -> {
                  try {
                    Files.deleteIfExists(p);
                  } catch (IOException _) {
                    // best-effort cleanup
                  }
                });
      }
    }
  }

  @Test
  @DisplayName("htmlText_whenFormNeeded_includesHiddenFormPassword")
  void htmlText_whenFormNeeded_includesHiddenFormPassword() {
    when(updater.isArmed()).thenReturn(false);
    when(updater.canUpdateNow()).thenReturn(true);
    when(updater.canUpdateImmediately()).thenReturn(true);
    when(node.network().updateIsUrgent()).thenReturn(false);

    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getFormPassword()).thenReturn("secret-token");

    // Version selection path shouldn't matter for this check; take the fallback branch.
    when(updater.hasNewCorePackage()).thenReturn(false);
    when(updater.fetchingNewCorePackage()).thenReturn(false);
    when(updater.getMainVersion()).thenReturn(999);

    // Capture the version passed into addChangelogLinks
    AtomicLong capturedVersion = new AtomicLong(-1);
    Mockito.doAnswer(
            inv -> {
              capturedVersion.set(inv.getArgument(0, Long.class));
              return null;
            })
        .when(updater)
        .addChangelogLinks(ArgumentMatchers.anyLong(), any(HTMLNode.class));

    HTMLNode nodeHtml = alert.getHTMLText();
    assertNotNull(nodeHtml);

    // Ensure a hidden input with the form password is present
    String rendered = nodeHtml.generate();
    assertTrue(rendered.contains("name=\"formPassword\""));
    assertTrue(rendered.contains("value=\"secret-token\""));

    // Verify changelog links and progress are rendered/called
    assertEquals(999L, capturedVersion.get());
    verify(updater).renderProgress(any(HTMLNode.class));
  }

  @Test
  @DisplayName("htmlText_versionSelection_prefersNewJarThenFetchingThenCurrent")
  void htmlText_versionSelection_prefersNewJarThenFetchingThenCurrent() {
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getFormPassword()).thenReturn("pw");
    when(node.network().updateIsUrgent()).thenReturn(false);

    // Capture the version passed into addChangelogLinks (will be overwritten on each call)
    AtomicLong capturedVersion = new AtomicLong(-1);
    Mockito.doAnswer(
            inv -> {
              capturedVersion.set(inv.getArgument(0, Long.class));
              return null;
            })
        .when(updater)
        .addChangelogLinks(ArgumentMatchers.anyLong(), any(HTMLNode.class));

    // Case 1: hasNewCorePackage -> use newCorePackageVersion
    when(updater.isArmed()).thenReturn(false);
    when(updater.canUpdateNow()).thenReturn(true);
    when(updater.canUpdateImmediately()).thenReturn(true);
    when(updater.hasNewCorePackage()).thenReturn(true);
    when(updater.newCorePackageVersion()).thenReturn(42);
    when(updater.newCorePackageVersionLabel()).thenReturn("42");
    HTMLNode html1 = alert.getHTMLText();
    assertNotNull(html1);
    assertEquals(42L, capturedVersion.get());

    // Case 2: not hasNew, fetchingNewCorePackage -> use fetchingNewCorePackageVersion
    when(updater.hasNewCorePackage()).thenReturn(false);
    when(updater.fetchingNewCorePackage()).thenReturn(true);
    when(updater.fetchingNewCorePackageVersion()).thenReturn(77);
    HTMLNode html2 = alert.getHTMLText();
    assertNotNull(html2);
    assertEquals(77L, capturedVersion.get());

    // Case 3: neither -> fallback to getMainVersion
    when(updater.fetchingNewCorePackage()).thenReturn(false);
    when(updater.getMainVersion()).thenReturn(99);
    HTMLNode html3 = alert.getHTMLText();
    assertNotNull(html3);
    assertEquals(99L, capturedVersion.get());
  }

  @Test
  @DisplayName("priority_whenUrgent_returnsCritical")
  void priority_whenUrgent_returnsCritical() {
    when(updater.getNode()).thenReturn(node);
    when(node.network().updateIsUrgent()).thenReturn(true);
    assertEquals(UserAlert.CRITICAL_ERROR, alert.getPriorityClass());
  }

  @Test
  @DisplayName("priority_whenReadyOrNotArmed_returnsError")
  void priority_whenReadyOrNotArmed_returnsError() {
    when(node.network().updateIsUrgent()).thenReturn(false);
    when(updater.getNode()).thenReturn(node);

    when(updater.canUpdateNow()).thenReturn(true);
    assertEquals(UserAlert.ERROR, alert.getPriorityClass());

    when(updater.canUpdateNow()).thenReturn(false);
    when(updater.isArmed()).thenReturn(false);
    assertEquals(UserAlert.ERROR, alert.getPriorityClass());
  }

  @Test
  @DisplayName("priority_whenArmedAndNotReady_returnsMinor")
  void priority_whenArmedAndNotReady_returnsMinor() {
    when(node.network().updateIsUrgent()).thenReturn(false);
    when(updater.getNode()).thenReturn(node);
    when(updater.canUpdateNow()).thenReturn(false);
    when(updater.isArmed()).thenReturn(true);
    assertEquals(UserAlert.MINOR, alert.getPriorityClass());
  }

  @Test
  @DisplayName("isValid_variousCombinations_followContract")
  void isValid_variousCombinations_followContract() {
    when(updater.isEnabled()).thenReturn(true);
    when(updater.isBlown()).thenReturn(false);

    // One of (fetchingNewCorePackage, hasNewCorePackage, fetchingFromUOM) must be true
    when(updater.fetchingNewCorePackage()).thenReturn(false);
    when(updater.hasNewCorePackage()).thenReturn(true);
    when(updater.fetchingFromUOM()).thenReturn(false);
    assertTrue(alert.isValid());

    // Disabled -> invalid regardless of others
    when(updater.isEnabled()).thenReturn(false);
    assertFalse(alert.isValid());

    // Blown -> invalid
    when(updater.isEnabled()).thenReturn(true);
    when(updater.isBlown()).thenReturn(true);
    assertFalse(alert.isValid());

    // None of the three flags -> invalid
    when(updater.isBlown()).thenReturn(false);
    when(updater.hasNewCorePackage()).thenReturn(false);
    when(updater.fetchingNewCorePackage()).thenReturn(false);
    when(updater.fetchingFromUOM()).thenReturn(false);
    assertFalse(alert.isValid());
  }
}
