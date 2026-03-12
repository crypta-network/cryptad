package network.crypta.node.useralerts;

import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "PointlessArithmeticExpression"})
class UpgradeConnectionSpeedUserAlertTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore clientCore;
  @Mock private UserAlertManager alertManager;

  @Captor private ArgumentCaptor<UserAlert> alertCaptor;

  @BeforeEach
  void setupConfigAndStubs() {
    // Real config/subconfig so getInt(...) returns our registered values deterministically.
    PersistentConfig config = new PersistentConfig(null);
    SubConfig nodeConfig = config.createSubConfig("node");
    // Register only the options we read in the alert under test.
    nodeConfig.register(
        "inputBandwidthLimit",
        4096, // 4 KiB/s
        new Option.Meta(0, false, false, "", ""),
        (network.crypta.support.api.IntCallback) null,
        false);
    nodeConfig.register(
        "outputBandwidthLimit",
        2048, // 2 KiB/s
        new Option.Meta(0, false, false, "", ""),
        (network.crypta.support.api.IntCallback) null,
        false);

    when(node.getConfig()).thenReturn(config);
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alertManager);
    // formPassword is only needed in tests that render the form; stubbed there.
  }

  @Test
  @DisplayName("createAlert registers the alert instance with UserAlertManager")
  void createAlert_registersWithManager() {
    BandwidthLimit recommended =
        new BandwidthLimit(2L * 1024 * 1024, 1L * 1024 * 1024, "desc", false);

    UpgradeConnectionSpeedUserAlert.createAlert(node, recommended);

    verify(alertManager).register(alertCaptor.capture());
    UserAlert captured = alertCaptor.getValue();
    assertNotNull(captured);
    assertInstanceOf(
        UpgradeConnectionSpeedUserAlert.class,
        captured,
        "Registered alert should be an UpgradeConnectionSpeedUserAlert");

    // Basic API characteristics
    assertTrue(captured.userCanDismiss());
    assertTrue(captured.shouldUnregisterOnDismiss());
    // Title uses l10n; English resource contains a concrete translation.
    assertEquals("Upgrade connection speed", captured.getTitle());
  }

  @Test
  @DisplayName("getHTMLText when upgraded shows only success message")
  void getHTMLText_whenUpgradedTrue_showsSuccessOnly() {
    BandwidthLimit recommended =
        new BandwidthLimit(3L * 1024 * 1024, 1L * 1024 * 1024, "desc", false);
    UpgradeConnectionSpeedUserAlert.createAlert(node, recommended);
    verify(alertManager).register(alertCaptor.capture());
    UpgradeConnectionSpeedUserAlert alert =
        (UpgradeConnectionSpeedUserAlert) alertCaptor.getValue();
    alert.setUpgraded(true);

    HTMLNode html = alert.getHTMLText();
    String out = html.generate();

    assertTrue(
        out.contains("Changes were successfully applied."), "Should show upgraded translated text");
    assertFalse(out.contains("<form"), "No form should be present when upgraded");

    // Dismiss button text switches to OK when upgraded, per l10n resources.
    assertEquals("Ok", alert.dismissButtonText());
  }

  @Test
  @DisplayName("getHTMLText shows current limits, form, and recommended values")
  void getHTMLText_whenNotUpgraded_showsDetailsAndForm() {
    long downRecommended = 3L * 1024 * 1024; // 3 MiB
    long upRecommended = 1L * 1024 * 1024; // 1 MiB
    BandwidthLimit recommended = new BandwidthLimit(downRecommended, upRecommended, "desc", false);
    UpgradeConnectionSpeedUserAlert.createAlert(node, recommended);
    verify(alertManager).register(alertCaptor.capture());
    UpgradeConnectionSpeedUserAlert alert =
        (UpgradeConnectionSpeedUserAlert) alertCaptor.getValue();

    when(clientCore.getFormPassword()).thenReturn("pw-secret");
    HTMLNode html = alert.getHTMLText();
    String out = html.generate();

    // Localized paragraph with substitutions for current limits.
    assertTrue(
        out.contains("Upload bandwidth limit " + SizeUtil.formatSize(2048)),
        "Should include current output limit with formatting");
    assertTrue(
        out.contains("Download bandwidth limit " + SizeUtil.formatSize(4096)),
        "Should include current input limit with formatting");

    // Form and fields
    assertTrue(out.contains("<form"), "Form should be present");
    assertTrue(
        out.contains("name=\"upgradeConnectionSpeed\""), "Hidden upgradeConnectionSpeed input");
    assertTrue(out.contains("name=\"formPassword\""), "Hidden formPassword input");
    assertTrue(out.contains("pw-secret"), "Form password value should be present");

    // Recommended values populate the input fields
    assertTrue(
        out.contains("name=\"inputBandwidthLimit\"")
            && out.contains("value=\"" + SizeUtil.formatSize(downRecommended) + "\""),
        "Download/input field should be pre-populated with recommended down limit");
    assertTrue(
        out.contains("name=\"outputBandwidthLimit\"")
            && out.contains("value=\"" + SizeUtil.formatSize(upRecommended) + "\""),
        "Upload/output field should be pre-populated with recommended up limit");

    // Dismiss button uses "No" when not upgraded.
    assertEquals("No", alert.dismissButtonText());
  }

  @Test
  @DisplayName("getHTMLText displays error once and clears it on next render")
  void getHTMLText_errorShownOnce_thenCleared() {
    BandwidthLimit recommended = new BandwidthLimit(1L * 1024 * 1024, 512L * 1024, "desc", false);
    UpgradeConnectionSpeedUserAlert.createAlert(node, recommended);
    verify(alertManager).register(alertCaptor.capture());
    UpgradeConnectionSpeedUserAlert alert =
        (UpgradeConnectionSpeedUserAlert) alertCaptor.getValue();

    when(clientCore.getFormPassword()).thenReturn("pw-secret");
    alert.setError("Invalid value");
    String first = alert.getHTMLText().generate();
    assertTrue(first.contains("Invalid value"), "First render should include error message");

    String second = alert.getHTMLText().generate();
    assertFalse(second.contains("Invalid value"), "Second render should not include prior error");
  }

  // Instance under test is captured from createAlert(..) registration in each case above.
}
