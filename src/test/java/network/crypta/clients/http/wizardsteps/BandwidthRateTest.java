package network.crypta.clients.http.wizardsteps;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.runtime.spi.FirstTimeWizardCurrentBandwidthLimits;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
  private static final FirstTimeWizardSnapshot DEFAULT_SNAPSHOT =
      new FirstTimeWizardSnapshot(
          false, "2.00", "1.25", 1L, "10.00", 10L, 10L, 976562L, "49.44", "", "", -1L);

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
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    Config config = mock(Config.class);
    when(wizardPort.snapshot()).thenReturn(DEFAULT_SNAPSHOT);

    BandwidthRate step = new TestableBandwidthRate(wizardPort, config);

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
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    Config config = mock(Config.class);
    when(wizardPort.snapshot()).thenReturn(DEFAULT_SNAPSHOT);

    BandwidthRate step = new TestableBandwidthRate(wizardPort, config);

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
  void getStep_whenSnapshotHasCurrentLimit_expectCurrentOptionRendered() {
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    Config config = mock(Config.class);
    when(wizardPort.snapshot()).thenReturn(snapshotWithCurrentBandwidth());

    BandwidthRate step = new BandwidthRate(wizardPort, config);

    when(helper.getPageContent(anyString())).thenReturn(pageContent);
    stubHelperToAttachInfoboxesAndForms();
    when(request.isParameterSet(anyString())).thenReturn(false);

    step.getStep(request, helper);

    String html = pageContent.generate();
    String expectedCurrentValue = "4096/1024";
    Pattern currentPattern =
        Pattern.compile(
            "(?s)<input\\b"
                + "(?=[^>]*\\btype=\"radio\")"
                + "(?=[^>]*\\bname=\""
                + Pattern.quote(PARAM_BANDWIDTH)
                + "\")"
                + "(?=[^>]*\\bvalue=\""
                + Pattern.quote(HTMLEncoder.encode(expectedCurrentValue))
                + "\")"
                + "[^>]*>");
    assertTrue(
        currentPattern.matcher(html).find(),
        "Missing radio input name=bandwidth value=" + expectedCurrentValue);
    assertTrue(
        html.contains(HTMLEncoder.encode(WizardL10n.l10n("bandwidthCurrent"))),
        "Expected current-bandwidth label to be present");
  }

  @Test
  void getStep_whenDetectedBandwidthAvailable_expectDetectedRecommendedOptionChecked() {
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    Config config = mock(Config.class);
    when(wizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                false, "2.00", "1.25", 1L, "10.00", 10L, 10L, 976562L, "49.44", "1024", "512",
                -1L));

    BandwidthRate step = new TestableBandwidthRate(wizardPort, config);

    when(helper.getPageContent(anyString())).thenReturn(pageContent);
    stubHelperToAttachInfoboxesAndForms();
    when(request.isParameterSet(anyString())).thenReturn(false);

    step.getStep(request, helper);

    String html = pageContent.generate();

    String expectedSelectedValue = (1024L * 1024L) + "/" + (512L * 1024L);
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

    TestableBandwidthRate() {
      this(mock(FirstTimeWizardPort.class), mock(Config.class));
    }

    TestableBandwidthRate(FirstTimeWizardPort wizardPort, Config config) {
      super(wizardPort, config);
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
  }

  private record SetCall(String limit, boolean setOutputLimit) {}

  private static FirstTimeWizardSnapshot snapshotWithCurrentBandwidth() {
    return new FirstTimeWizardSnapshot(
        false,
        "2.00",
        "1.25",
        1L,
        "10.00",
        10L,
        10L,
        10L,
        976562L,
        "49.44",
        "",
        "",
        new FirstTimeWizardCurrentBandwidthLimits(4096L, 1024L),
        -1L);
  }
}
