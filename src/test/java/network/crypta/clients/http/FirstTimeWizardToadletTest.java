package network.crypta.clients.http;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.EnumMap;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.FirstTimeWizardToadlet.WIZARD_PRESET;
import network.crypta.clients.http.FirstTimeWizardToadlet.WIZARD_STEP;
import network.crypta.clients.http.wizardsteps.Misc;
import network.crypta.clients.http.wizardsteps.PageHelper;
import network.crypta.clients.http.wizardsteps.SecurityNetwork;
import network.crypta.clients.http.wizardsteps.SecurityPhysical;
import network.crypta.clients.http.wizardsteps.Step;
import network.crypta.config.PersistentConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class FirstTimeWizardToadletTest {

  @Mock private HighLevelSimpleClient client;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private FirstTimeWizardPort firstTimeWizardPort;
  @Mock private ToadletContext ctx;

  private PersistentConfig config;

  @BeforeEach
  void setUp() throws Exception {
    config = new PersistentConfig(null);
    when(core.getNode()).thenReturn(node);
    when(ctx.checkFullAccess(any())).thenReturn(true);
  }

  @Test
  void getPreviousStep_withHighPresetAtSecurityNetwork_returnsWelcome() {
    WIZARD_STEP result =
        FirstTimeWizardToadlet.getPreviousStep(WIZARD_STEP.SECURITY_NETWORK, WIZARD_PRESET.HIGH);

    assertEquals(WIZARD_STEP.WELCOME, result);
  }

  @Test
  void handleMethodGET_browserWarningWithIncognitoChrome_redirectsToMisc() throws Exception {
    FirstTimeWizardToadlet toadlet =
        spy(
            new FirstTimeWizardToadlet(
                client,
                config,
                core,
                new FirstTimeWizardToadletRuntimePorts(
                    firstTimeWizardPort, () -> Long.MAX_VALUE, () -> null)));
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam("step", FirstTimeWizardToadlet.WIZARD_STEP.WELCOME.toString()))
        .thenReturn("BROWSER_WARNING");
    when(request.getParam("opennet", "false")).thenReturn("false");
    when(request.getParam("singlestep", "false")).thenReturn("false");
    when(request.getParam("preset")).thenReturn("");
    when(request.isChrome()).thenReturn(true);
    when(request.isIncognito()).thenReturn(true);

    ArgumentCaptor<String> locationCaptor = ArgumentCaptor.forClass(String.class);
    doNothing()
        .when(toadlet)
        .writeTemporaryRedirect(eq(ctx), anyString(), locationCaptor.capture());

    toadlet.handleMethodGET(new URI(FirstTimeWizardToadlet.TOADLET_URL), request, ctx);

    verify(toadlet, times(1))
        .writeTemporaryRedirect(eq(ctx), eq("Skipping unneeded warning"), anyString());
    assertEquals("/wizard/?step=MISC&opennet=false", locationCaptor.getValue());
  }

  @Test
  void handleMethodGET_securityNetworkWithoutOpennet_redirectsToOpenNet() throws Exception {
    FirstTimeWizardToadlet toadlet =
        spy(
            new FirstTimeWizardToadlet(
                client,
                config,
                core,
                new FirstTimeWizardToadletRuntimePorts(
                    firstTimeWizardPort, () -> Long.MAX_VALUE, () -> null)));
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam("step", FirstTimeWizardToadlet.WIZARD_STEP.WELCOME.toString()))
        .thenReturn("SECURITY_NETWORK");
    when(request.getParam("opennet", "false")).thenReturn("false");
    when(request.getParam("singlestep", "false")).thenReturn("false");
    when(request.getParam("preset")).thenReturn("");
    when(request.isParameterSet("opennet")).thenReturn(false);

    ArgumentCaptor<String> locationCaptor = ArgumentCaptor.forClass(String.class);
    doNothing()
        .when(toadlet)
        .writeTemporaryRedirect(eq(ctx), anyString(), locationCaptor.capture());

    toadlet.handleMethodGET(new URI(FirstTimeWizardToadlet.TOADLET_URL), request, ctx);

    verify(toadlet, times(1))
        .writeTemporaryRedirect(eq(ctx), eq("Need opennet choice"), anyString());
    assertEquals("/wizard/?step=OPENNET&opennet=false", locationCaptor.getValue());
  }

  @Test
  void handleMethodPOST_presetLow_setsThreatLevelsAndRedirects() throws Exception {
    FirstTimeWizardToadlet toadlet =
        spy(
            new FirstTimeWizardToadlet(
                client,
                config,
                core,
                new FirstTimeWizardToadletRuntimePorts(
                    firstTimeWizardPort, () -> Long.MAX_VALUE, () -> null)));
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe("step", 20)).thenReturn("WELCOME");
    when(request.getPartAsStringFailsafe("incognito", 5)).thenReturn("0");
    when(request.getPartAsStringFailsafe("preset", 4)).thenReturn("LOW");
    when(request.getPartAsStringFailsafe("opennet", 5)).thenReturn("false");
    when(request.getPartAsStringFailsafe("singlestep", 5)).thenReturn("false");
    when(request.isPartSet("presetLow")).thenReturn(true);
    when(request.isPartSet("presetHigh")).thenReturn(false);
    when(request.isPartSet("presetNone")).thenReturn(false);
    when(request.isPartSet("back")).thenReturn(false);
    when(request.isPartSet("singlestep")).thenReturn(false);

    // Replace side-effecting steps with mocks to verify interactions.
    Misc misc = mock(Misc.class);
    SecurityNetwork securityNetwork = mock(SecurityNetwork.class);
    SecurityPhysical securityPhysical = mock(SecurityPhysical.class);
    setField(toadlet, "stepMISC", misc);
    setField(toadlet, "stepSecurityNetwork", securityNetwork);
    setField(toadlet, "stepSecurityPhysical", securityPhysical);

    ArgumentCaptor<String> locationCaptor = ArgumentCaptor.forClass(String.class);
    doNothing()
        .when(toadlet)
        .writeTemporaryRedirect(eq(ctx), anyString(), locationCaptor.capture());

    toadlet.handleMethodPOST(new URI(FirstTimeWizardToadlet.TOADLET_URL), request, ctx);

    verify(misc).setAutoUpdate(true);
    verify(securityNetwork).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.LOW);
    verify(securityPhysical).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    assertEquals(
        "/wizard/?step=BROWSER_WARNING&incognito=0&preset=LOW&opennet=true",
        locationCaptor.getValue());
  }

  @Test
  void handleMethodPOST_whenStepThrowsIOException_returnsInternalErrorPage() throws Exception {
    FirstTimeWizardToadlet toadlet =
        spy(
            new FirstTimeWizardToadlet(
                client,
                config,
                core,
                new FirstTimeWizardToadletRuntimePorts(
                    firstTimeWizardPort, () -> Long.MAX_VALUE, () -> null)));
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe("step", 20)).thenReturn("MISC");
    when(request.getPartAsStringFailsafe("preset", 4)).thenReturn("");
    when(request.isPartSet(anyString())).thenReturn(false);

    // Force the current step handler to throw.
    EnumMap<WIZARD_STEP, Step> steps = getSteps(toadlet);
    Step failingStep =
        new Step() {
          @Override
          public void getStep(HTTPRequest request, PageHelper helper) {
            // no-op for this test
          }

          @Override
          public String postStep(HTTPRequest request) throws IOException {
            throw new IOException("cantWriteNewMasterKeysFile");
          }
        };
    steps.put(WIZARD_STEP.MISC, failingStep);

    ArgumentCaptor<Integer> codeCaptor = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
    doNothing()
        .when(toadlet)
        .writeHTMLReply(eq(ctx), codeCaptor.capture(), anyString(), bodyCaptor.capture());

    toadlet.handleMethodPOST(new URI(FirstTimeWizardToadlet.TOADLET_URL), request, ctx);

    assertEquals(500, codeCaptor.getValue());
    assertTrue(bodyCaptor.getValue().contains("<html>"));
  }

  @SuppressWarnings("unchecked")
  private EnumMap<WIZARD_STEP, Step> getSteps(FirstTimeWizardToadlet toadlet) {
    try {
      Field field = FirstTimeWizardToadlet.class.getDeclaredField("steps");
      field.setAccessible(true);
      return (EnumMap<WIZARD_STEP, Step>) field.get(toadlet);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }

  private void setField(Object target, String fieldName, Object value) {
    try {
      Field field = FirstTimeWizardToadlet.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }
}
