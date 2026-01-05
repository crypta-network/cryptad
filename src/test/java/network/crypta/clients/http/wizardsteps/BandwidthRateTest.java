package network.crypta.clients.http.wizardsteps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeIPDetector;
import network.crypta.pluginmanager.FredPluginBandwidthIndicator;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class BandwidthRateTest {

  private static final String PARAM_BANDWIDTH = "bandwidth";
  private static final String PARAM_CUSTOM_DOWN = "customDown";
  private static final String PARAM_CUSTOM_UP = "customUp";
  private static final String PARAM_PARSE_ERROR = "parseError";
  private static final String PARAM_PARSE_TARGET = "parseTarget";

  private static final String REDIRECT_CUSTOM_PARSE_ERROR_PREFIX =
      "BANDWIDTH_RATE&parseError=true&parseTarget=";
  private static final String MSG_DOWN_BAD = "down bad";
  private static final String MSG_UP_BAD = "up bad";
  private static final String ATTR_CHECKED = "checked=\"checked\"";

  @Mock HTTPRequest request;
  @Mock PageHelper helper;

  private HTMLNode pageContent;

  @BeforeEach
  void setUp() {
    pageContent = new HTMLNode("div");
  }

  @Test
  void postStep_whenCustomLimitsProvidedAndValid_expectSetsDownThenUpAndCompletes() {
    TestableBandwidthRate step = new TestableBandwidthRate();

    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("1000");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("2000");

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name(), next);
    assertTrue(step.wizardComplete, "Wizard must be marked complete on success");
    assertEquals(
        List.of(new SetCall("1000", false), new SetCall("2000", true)), step.setBandwidthCalls);
  }

  @Test
  void postStep_whenCustomDownRejected_expectParseErrorRedirectAndNoWizardComplete() {
    TestableBandwidthRate step = new TestableBandwidthRate();
    step.rejectNextDownSetWithMessage = MSG_DOWN_BAD;

    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("999");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("111");

    String next = step.postStep(request);

    String expected = REDIRECT_CUSTOM_PARSE_ERROR_PREFIX + URLEncoder.encode(MSG_DOWN_BAD, true);
    assertEquals(expected, next);
    assertFalse(step.wizardComplete, "Wizard must not complete when a custom limit is rejected");
    assertEquals(
        List.of(new SetCall("999", false), new SetCall("111", true)), step.setBandwidthCalls);
  }

  @Test
  void postStep_whenCustomUpRejected_expectParseErrorRedirectAndNoWizardComplete() {
    TestableBandwidthRate step = new TestableBandwidthRate();
    step.rejectNextUpSetWithMessage = MSG_UP_BAD;

    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("999");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("111");

    String next = step.postStep(request);

    String expected = REDIRECT_CUSTOM_PARSE_ERROR_PREFIX + URLEncoder.encode(MSG_UP_BAD, true);
    assertEquals(expected, next);
    assertFalse(step.wizardComplete, "Wizard must not complete when a custom limit is rejected");
    assertEquals(
        List.of(new SetCall("999", false), new SetCall("111", true)), step.setBandwidthCalls);
  }

  @Test
  void postStep_whenCustomDownAndUpRejected_expectCombinedParseTargetWithSpaceSeparator() {
    TestableBandwidthRate step = new TestableBandwidthRate();
    step.rejectNextDownSetWithMessage = MSG_DOWN_BAD;
    step.rejectNextUpSetWithMessage = MSG_UP_BAD;

    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("999");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("111");

    String next = step.postStep(request);

    String expectedTarget = MSG_DOWN_BAD + " " + MSG_UP_BAD;
    String expected = REDIRECT_CUSTOM_PARSE_ERROR_PREFIX + URLEncoder.encode(expectedTarget, true);
    assertEquals(expected, next);
    assertFalse(step.wizardComplete, "Wizard must not complete when custom limits are rejected");
    assertEquals(
        List.of(new SetCall("999", false), new SetCall("111", true)), step.setBandwidthCalls);
  }

  @Test
  void postStep_whenPresetSelectedAndValid_expectSetsDownThenUpAndCompletes() {
    TestableBandwidthRate step = new TestableBandwidthRate();

    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("111/222");

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name(), next);
    assertTrue(step.wizardComplete, "Wizard must be marked complete on success");
    assertEquals(
        List.of(new SetCall("111", false), new SetCall("222", true)), step.setBandwidthCalls);
  }

  @Test
  void postStep_whenPresetSelectedButRejected_expectParseErrorRedirectAndNoWizardComplete() {
    TestableBandwidthRate step = new TestableBandwidthRate();
    step.rejectNextUpSetWithMessage = "too low";

    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("111/222");

    String next = step.postStep(request);

    String expected =
        FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_RATE
            + "&parseError=true&parseTarget="
            + URLEncoder.encode("too low", true);
    assertEquals(expected, next);
    assertFalse(step.wizardComplete, "Wizard must not complete when a preset is rejected");
    assertEquals(
        List.of(new SetCall("111", false), new SetCall("222", true)), step.setBandwidthCalls);
  }

  @Test
  void postStep_whenNoPresetAndNoCustom_expectSameStepAndNoWrites() {
    TestableBandwidthRate step = new TestableBandwidthRate();

    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("");

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_RATE.name(), next);
    assertFalse(step.wizardComplete, "Wizard must not complete without selecting a limit");
    assertTrue(step.setBandwidthCalls.isEmpty(), "Should not set bandwidth without a selection");
  }

  @Test
  void postStep_whenOnlyOneCustomFieldProvided_expectSameStepAndNoWrites() {
    TestableBandwidthRate step = new TestableBandwidthRate();

    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("1000");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("");

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_RATE.name(), next);
    assertFalse(step.wizardComplete, "Wizard must not complete with only one custom field");
    assertTrue(
        step.setBandwidthCalls.isEmpty(), "Should not set bandwidth with incomplete custom input");
  }

  @Test
  void postStep_whenPresetHasNoSlash_expectCompletesWithoutSettingBandwidth() {
    TestableBandwidthRate step = new TestableBandwidthRate();

    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_DOWN, 20)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_CUSTOM_UP, 20)).thenReturn("");
    when(request.getPartAsStringFailsafe(PARAM_BANDWIDTH, 100)).thenReturn("not-a-pair");

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name(), next);
    assertTrue(step.wizardComplete, "Wizard must be marked complete when preset is non-empty");
    assertTrue(
        step.setBandwidthCalls.isEmpty(), "Should not set bandwidth if preset lacks delimiter");
  }

  @Test
  void getStep_whenParseErrorParamSet_includesParseTargetInHtml() {
    NodeClientCore core = mock(NodeClientCore.class);
    Config config = mock(Config.class);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeIPDetector ipDetector = mock(NodeIPDetector.class);
    when(core.getNode()).thenReturn(node);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.ipDetector()).thenReturn(ipDetector);
    when(ipDetector.getBandwidthIndicator()).thenReturn(null);

    BandwidthRate step = new TestableBandwidthRate(core, config, null);

    when(helper.getPageContent(anyString())).thenReturn(pageContent);
    stubHelperToAttachInfoboxesAndForms();

    String parseTarget = "bad input";
    when(request.isParameterSet(PARAM_PARSE_ERROR)).thenReturn(true);
    when(request.getParam(PARAM_PARSE_TARGET)).thenReturn(parseTarget);

    step.getStep(request, helper);

    String html = pageContent.generate();
    assertTrue(
        html.contains(HTMLEncoder.encode(parseTarget)),
        "Expected parseTarget to appear in the parse error infobox");
  }

  @Test
  void getStep_whenNoDetectedOrCurrentLimit_expectMaybeDefaultOptionChecked() {
    NodeClientCore core = mock(NodeClientCore.class);
    Config config = mock(Config.class);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeIPDetector ipDetector = mock(NodeIPDetector.class);
    when(core.getNode()).thenReturn(node);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.ipDetector()).thenReturn(ipDetector);
    when(ipDetector.getBandwidthIndicator()).thenReturn(null);

    BandwidthRate step = new TestableBandwidthRate(core, config, null);

    when(helper.getPageContent(anyString())).thenReturn(pageContent);
    stubHelperToAttachInfoboxesAndForms();
    when(request.isParameterSet(anyString())).thenReturn(false);

    step.getStep(request, helper);

    String html = pageContent.generate();

    // The constructor currently marks the "Half VDSL" preset as maybe-default (768 KiB down, 160
    // KiB up).
    assertHtmlHasCheckedBandwidthRadio(html, "786432/163840");
    assertHtmlHasCustomInputs(html);
    assertHtmlHasSubmitInput(html, "back");
    assertHtmlHasSubmitInput(html, "next");
  }

  @Test
  void getStep_whenDetectedBandwidthAvailable_expectDetectedRecommendedOptionChecked() {
    NodeClientCore core = mock(NodeClientCore.class);
    Config config = mock(Config.class);

    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeIPDetector ipDetector = mock(NodeIPDetector.class);
    when(core.getNode()).thenReturn(node);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.ipDetector()).thenReturn(ipDetector);

    FredPluginBandwidthIndicator indicator = mock(FredPluginBandwidthIndicator.class);
    when(ipDetector.getBandwidthIndicator()).thenReturn(indicator);
    when(indicator.getDownstreamMaxBitRate()).thenReturn(8_000_000);
    when(indicator.getUpstreamMaxBitRate()).thenReturn(1_000_000);

    BandwidthRate step = new TestableBandwidthRate(core, config, null);

    when(helper.getPageContent(anyString())).thenReturn(pageContent);
    stubHelperToAttachInfoboxesAndForms();
    when(request.isParameterSet(anyString())).thenReturn(false);

    step.getStep(request, helper);

    String html = pageContent.generate();

    long downBytesPerSecond = 8_000_000L / 8;
    long upBytesPerSecond = 1_000_000L / 8;
    String expectedSelectedValue = (downBytesPerSecond / 2) + "/" + (upBytesPerSecond / 2);
    assertHtmlHasCheckedBandwidthRadio(html, expectedSelectedValue);

    String suggestedLabel = WizardL10n.l10n("autodetectedSuggestedLimit");
    assertTrue(
        html.contains(HTMLEncoder.encode(suggestedLabel)),
        "Expected recommended label to be present for detected bandwidth row");
  }

  private void stubHelperToAttachInfoboxesAndForms() {
    when(helper.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2, HTMLNode.class);
              HTMLNode box = new HTMLNode("div");
              parent.addChild(box);
              return box;
            });

    when(helper.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0, HTMLNode.class);
              HTMLNode form = new HTMLNode("form");
              parent.addChild(form);
              return form;
            });
  }

  private static void assertHtmlHasCheckedBandwidthRadio(String html, String value) {
    Pattern pattern =
        Pattern.compile(
            "(?s)<input\\b"
                + "(?=[^>]*\\btype=\"radio\")"
                + "(?=[^>]*\\bname=\""
                + Pattern.quote(PARAM_BANDWIDTH)
                + "\")"
                + "(?=[^>]*\\bvalue=\""
                + Pattern.quote(HTMLEncoder.encode(value))
                + "\")"
                + "(?=[^>]*\\bchecked=\"checked\")"
                + "[^>]*>");
    assertTrue(
        pattern.matcher(html).find(), "Missing checked radio input name=bandwidth value=" + value);

    assertEquals(1, countCheckedAttributes(html), "Expected exactly one checked bandwidth option");
  }

  private static void assertHtmlHasCustomInputs(String html) {
    assertTrue(
        Pattern.compile(
                "(?s)<input\\b(?=[^>]*\\btype=\"text\")(?=[^>]*\\bname=\""
                    + Pattern.quote(PARAM_CUSTOM_DOWN)
                    + "\")[^>]*>")
            .matcher(html)
            .find(),
        "Missing custom download input");
    assertTrue(
        Pattern.compile(
                "(?s)<input\\b(?=[^>]*\\btype=\"text\")(?=[^>]*\\bname=\""
                    + Pattern.quote(PARAM_CUSTOM_UP)
                    + "\")[^>]*>")
            .matcher(html)
            .find(),
        "Missing custom upload input");
  }

  private static void assertHtmlHasSubmitInput(String html, String name) {
    Pattern pattern =
        Pattern.compile(
            "(?s)<input\\b"
                + "(?=[^>]*\\btype=\"submit\")"
                + "(?=[^>]*\\bname=\""
                + Pattern.quote(name)
                + "\")"
                + "[^>]*>");
    assertTrue(pattern.matcher(html).find(), "Missing submit input name=" + name);
  }

  private static int countCheckedAttributes(String html) {
    Pattern pattern = Pattern.compile(Pattern.quote(ATTR_CHECKED));
    Matcher matcher = pattern.matcher(html);
    int count = 0;
    while (matcher.find()) {
      count++;
    }
    return count;
  }

  private static final class TestableBandwidthRate extends BandwidthRate {
    final List<SetCall> setBandwidthCalls = new ArrayList<>();
    boolean wizardComplete;

    String rejectNextDownSetWithMessage;
    String rejectNextUpSetWithMessage;

    private final BandwidthLimit current;

    TestableBandwidthRate() {
      this(mock(NodeClientCore.class), mock(Config.class), null);
    }

    TestableBandwidthRate(NodeClientCore core, Config config, BandwidthLimit current) {
      super(core, config);
      this.current = current;
    }

    @Override
    protected void setBandwidthLimit(String limit, boolean setOutputLimit)
        throws InvalidConfigValueException {
      setBandwidthCalls.add(new SetCall(limit, setOutputLimit));

      if (!setOutputLimit && rejectNextDownSetWithMessage != null) {
        String message = rejectNextDownSetWithMessage;
        rejectNextDownSetWithMessage = null;
        throw new InvalidConfigValueException(message);
      }

      if (setOutputLimit && rejectNextUpSetWithMessage != null) {
        String message = rejectNextUpSetWithMessage;
        rejectNextUpSetWithMessage = null;
        throw new InvalidConfigValueException(message);
      }
    }

    @Override
    protected void setWizardComplete() {
      wizardComplete = true;
    }

    @Override
    protected BandwidthLimit getCurrentBandwidthLimitsOrNull() {
      return current;
    }
  }

  private record SetCall(String limit, boolean setOutputLimit) {}
}
