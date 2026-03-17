package network.crypta.clients.http.wizardsteps;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.DatastoreUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
@SuppressWarnings({"java:S100"})
class BandwidthMonthlyTest {

  private static final String PARAM_CAP_TO = "capTo";
  private static final String PARAM_PARSE_TARGET = "parseTarget";
  private static final String PARAM_PARSE_ERROR = "parseError";
  private static final String PARAM_TOO_LOW = "tooLow";
  private static final String FRAGMENT_PARSE_TARGET = "&parseTarget=";
  private static final FirstTimeWizardSnapshot DEFAULT_SNAPSHOT =
      new FirstTimeWizardSnapshot(
          false,
          "2.00",
          "1.25",
          1L,
          "10.00",
          10L,
          10L,
          976562L,
          String.valueOf(BandwidthLimit.MIN_MONTHLY_LIMIT),
          "",
          "",
          -1L);

  @Mock HTTPRequest request;
  @Mock PageHelper helper;

  private HTMLNode pageContent;

  @BeforeEach
  void setUp() {
    pageContent = new HTMLNode("div");
  }

  @ParameterizedTest
  @CsvSource({"''", "'  '", "'not-a-number'", "'12 34'", "'1_000'"})
  void postStep_whenCapToNotNumeric_expectParseErrorRedirect(String capTo) {
    TestableBandwidthMonthly step = new TestableBandwidthMonthly();

    when(request.getPartAsStringFailsafe(PARAM_CAP_TO, 4096)).thenReturn(capTo);

    String next = step.postStep(request);

    String expected =
        FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_MONTHLY.name()
            + FRAGMENT_PARSE_TARGET
            + URLEncoder.encode(capTo, true)
            + "&parseError=true";
    assertEquals(expected, next);

    assertTrue(step.setBandwidthCalls.isEmpty(), "Should not set bandwidth on parse error");
    assertFalse(step.wizardComplete, "Wizard must not complete on parse error");
  }

  @Test
  void postStep_whenCapToNumericAndLimitSet_expectCompleteAndAppliesDownAndUp() {
    TestableBandwidthMonthly step = new TestableBandwidthMonthly();
    String capTo = "200";

    when(request.getPartAsStringFailsafe(PARAM_CAP_TO, 4096)).thenReturn(capTo);

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name(), next);
    assertTrue(step.wizardComplete, "Wizard must be marked complete on success");

    long bytesPerMonth = Math.round(Double.parseDouble(capTo) * DatastoreUtil.ONE_GIB);
    BandwidthLimit expected = new BandwidthLimit(bytesPerMonth);

    assertEquals(2, step.setBandwidthCalls.size(), "Should set download and upload bandwidth");
    assertEquals(
        new SetCall(Long.toString(expected.downBytes), false), step.setBandwidthCalls.get(0));
    assertEquals(new SetCall(Long.toString(expected.upBytes), true), step.setBandwidthCalls.get(1));
  }

  @Test
  void postStep_whenSettingBandwidthTooLow_expectTooLowRedirectAndNoWizardComplete() {
    TestableBandwidthMonthly step = new TestableBandwidthMonthly();
    step.throwInvalidConfigOnNextSet = true;
    String capTo = "1";

    when(request.getPartAsStringFailsafe(PARAM_CAP_TO, 4096)).thenReturn(capTo);

    String next = step.postStep(request);

    String expected =
        FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_MONTHLY.name()
            + FRAGMENT_PARSE_TARGET
            + URLEncoder.encode(String.valueOf(Double.parseDouble(capTo)), true)
            + "&tooLow=true";
    assertEquals(expected, next);

    assertEquals(1, step.setBandwidthCalls.size(), "Should fail on first bandwidth set");
    assertFalse(step.wizardComplete, "Wizard must not complete when bandwidth is rejected");
  }

  @Test
  void postStep_whenCapToIsNaN_expectTooLowRedirectWithNaNParseTarget() {
    TestableBandwidthMonthly step = new TestableBandwidthMonthly();
    step.throwInvalidConfigOnNextSet = true;
    String capTo = "NaN";

    when(request.getPartAsStringFailsafe(PARAM_CAP_TO, 4096)).thenReturn(capTo);

    String next = step.postStep(request);

    String expected =
        FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_MONTHLY.name()
            + FRAGMENT_PARSE_TARGET
            + URLEncoder.encode(String.valueOf(Double.NaN), true)
            + "&tooLow=true";
    assertEquals(expected, next);
  }

  @Test
  void getStep_whenNoErrorParams_rendersCapsCustomInputAndBackButton() {
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(DEFAULT_SNAPSHOT);
    BandwidthMonthly step = new BandwidthMonthly(wizardPort, mock(Config.class));

    when(helper.getPageContent(anyString())).thenReturn(pageContent);

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

    when(request.getParam(PARAM_PARSE_TARGET)).thenReturn("");
    when(request.isParameterSet(anyString())).thenReturn(false);

    step.getStep(request, helper);

    String html = pageContent.generate();

    long[] expectedCaps =
        new long[] {(long) Math.ceil(BandwidthLimit.MIN_MONTHLY_LIMIT), 100, 150, 250, 500};
    for (long cap : expectedCaps) {
      assertHtmlHasHiddenCapToInput(html, String.valueOf(cap));
      assertTrue(html.contains(cap + " GB"), "Missing display label for cap " + cap);
    }

    assertHtmlHasCapToTextInput(html);
    assertHtmlHasBackSubmitInput(html, NodeL10n.getBase().getString("Toadlet.back"));
  }

  @Test
  void getStep_whenParseErrorParamSet_showsCouldNotParseMessage() {
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(DEFAULT_SNAPSHOT);
    BandwidthMonthly step = new BandwidthMonthly(wizardPort, mock(Config.class));

    when(helper.getPageContent(anyString())).thenReturn(pageContent);

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

    String parseTarget = "abc def";
    when(request.getParam(PARAM_PARSE_TARGET)).thenReturn(parseTarget);
    when(request.isParameterSet(PARAM_PARSE_ERROR)).thenReturn(true);

    step.getStep(request, helper);

    String html = pageContent.generate();
    String expectedMessage = WizardL10n.l10n("bandwidthCouldNotParse", "limit", parseTarget);
    assertTrue(html.contains(HTMLEncoder.encode(expectedMessage)));
  }

  @Test
  void getStep_whenTooLowParamSet_includesUseMinimumFormWithMinimumValue() {
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(DEFAULT_SNAPSHOT);
    BandwidthMonthly step = new BandwidthMonthly(wizardPort, mock(Config.class));

    when(helper.getPageContent(anyString())).thenReturn(pageContent);

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

    when(request.getParam(PARAM_PARSE_TARGET)).thenReturn("1");
    when(request.isParameterSet(PARAM_PARSE_ERROR)).thenReturn(false);
    when(request.isParameterSet(PARAM_TOO_LOW)).thenReturn(true);

    step.getStep(request, helper);

    String html = pageContent.generate();
    assertHtmlHasHiddenCapToInput(html, String.valueOf(BandwidthLimit.MIN_MONTHLY_LIMIT));
    String expectedSubmitLabel = WizardL10n.l10n("bandwidthMonthlyUseMinimum");
    assertTrue(html.contains(HTMLEncoder.encode(expectedSubmitLabel)));
  }

  private static void assertHtmlHasHiddenCapToInput(String html, String value) {
    Pattern pattern =
        Pattern.compile(
            "(?s)<input\\b"
                + "(?=[^>]*\\btype=\"hidden\")"
                + "(?=[^>]*\\bname=\""
                + Pattern.quote(PARAM_CAP_TO)
                + "\")"
                + "(?=[^>]*\\bvalue=\""
                + Pattern.quote(HTMLEncoder.encode(value))
                + "\")"
                + "[^>]*>");
    assertTrue(
        pattern.matcher(html).find(),
        "Missing hidden input name=" + PARAM_CAP_TO + " value=" + value);
  }

  private static void assertHtmlHasCapToTextInput(String html) {
    Pattern pattern =
        Pattern.compile(
            "(?s)<input\\b"
                + "(?=[^>]*\\btype=\"text\")"
                + "(?=[^>]*\\bname=\""
                + Pattern.quote(PARAM_CAP_TO)
                + "\")"
                + "[^>]*>");
    assertTrue(pattern.matcher(html).find(), "Missing text input name=" + PARAM_CAP_TO);
  }

  private static void assertHtmlHasBackSubmitInput(String html, String value) {
    String encodedValue = HTMLEncoder.encode(value);
    Pattern pattern =
        Pattern.compile(
            "(?s)<input\\b"
                + "(?=[^>]*\\btype=\"submit\")"
                + "(?=[^>]*\\bname=\""
                + Pattern.quote("back")
                + "\")"
                + "(?=[^>]*\\bvalue=\""
                + Pattern.quote(encodedValue)
                + "\")"
                + "[^>]*>");
    assertTrue(pattern.matcher(html).find(), "Missing submit input name=back");
  }

  private static final class TestableBandwidthMonthly extends BandwidthMonthly {
    final List<SetCall> setBandwidthCalls = new ArrayList<>();
    boolean wizardComplete;
    boolean throwInvalidConfigOnNextSet;

    TestableBandwidthMonthly() {
      super(mock(FirstTimeWizardPort.class), mock(Config.class));
    }

    @Override
    protected void setBandwidthLimit(String limit, boolean setOutputLimit)
        throws InvalidConfigValueException {
      setBandwidthCalls.add(new SetCall(limit, setOutputLimit));
      if (throwInvalidConfigOnNextSet) {
        throwInvalidConfigOnNextSet = false;
        throw new InvalidConfigValueException("test");
      }
    }

    @Override
    protected void setWizardComplete() {
      wizardComplete = true;
    }
  }

  private record SetCall(String limit, boolean setOutputLimit) {}
}
