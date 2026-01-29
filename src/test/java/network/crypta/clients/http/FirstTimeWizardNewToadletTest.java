package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.clients.http.wizardsteps.BandwidthManipulator;
import network.crypta.clients.http.wizardsteps.DatastoreSize;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.ClientEndpoints;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.SecurityLevels;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.pluginmanager.FredPluginBandwidthIndicator;
import network.crypta.pluginmanager.PluginNotFoundException;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.DatastoreUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FirstTimeWizardNewToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private NodeClientCore core;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private SecurityLevels securityLevels;
  @Mock private ToadletContext ctx;
  @Mock private PageMaker pageMaker;
  @Mock private SimpleToadletServer toadletContainer;
  @Mock private Config config;
  @Mock private SubConfig nodeSubConfig;
  @Mock private SubConfig fproxySubConfig;

  @BeforeEach
  void setUp() {
    HTMLNode outer = new HTMLNode("div");
    HTMLNode head = outer.addChild("head");
    HTMLNode content = outer.addChild("div");
    PageNode pageNode = new PageNode(outer, head, content);

    when(core.getNode()).thenReturn(node);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx), any(PageMaker.RenderParameters.class)))
        .thenReturn(pageNode);
    ClientEndpoints endpoints = mock(ClientEndpoints.class);
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getToadletContainer()).thenReturn(toadletContainer);
    when(toadletContainer.getFormPassword()).thenReturn("form-pass");
    lenient().when(config.get("node")).thenReturn(nodeSubConfig);
    lenient().when(config.get("fproxy")).thenReturn(fproxySubConfig);
  }

  @Test
  void path_returnsWizardUrl() {
    FirstTimeWizardNewToadlet toadlet = new TestableFirstTimeWizardNewToadlet(client, core, config);

    assertEquals(FirstTimeWizardNewToadlet.TOADLET_URL, toadlet.path());
  }

  @Test
  void handleMethodGET_whenAccessDenied_returnsEarly() throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, core, config);
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(
        new URI(FirstTimeWizardNewToadlet.TOADLET_URL), mock(HTTPRequest.class), ctx);

    verify(ctx, times(1)).checkFullAccess(toadlet);
    assertFalse(toadlet.htmlWritten);
    assertNull(toadlet.lastModel);
  }

  @Test
  @SuppressWarnings("unchecked")
  void handleMethodGET_whenPhysicalThreatHigh_setsPasswordAlreadySetAndUsesDetectedLimits()
      throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, core, config);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);

    FredPluginBandwidthIndicator bandwidthIndicator = mock(FredPluginBandwidthIndicator.class);
    NodeIPDetector ipDetector = mock(NodeIPDetector.class);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.ipDetector()).thenReturn(ipDetector);
    lenient().when(ipDetector.getBandwidthIndicator()).thenReturn(bandwidthIndicator);

    Option<Long> storeSize = mock(Option.class);
    Option<Long> clientCache = mock(Option.class);
    Option<Long> slashdotCache = mock(Option.class);
    when(storeSize.isDefault()).thenReturn(false);
    when(storeSize.getValue()).thenReturn(2L * DatastoreUtil.ONE_GIB);
    when(clientCache.getValue()).thenReturn(0L);
    when(slashdotCache.getValue()).thenReturn(0L);

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class);
        MockedStatic<BandwidthManipulator> bandwidth = mockStatic(BandwidthManipulator.class);
        MockedStatic<Config> configStatic = mockStatic(Config.class)) {

      BaseL10n base = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);
      when(base.getString(anyString())).thenAnswer(inv -> inv.getArgument(0));
      when(base.getString(anyString(), anyString())).thenAnswer(inv -> inv.getArgument(0));
      when(base.getString(anyString(), any(String[].class), any(String[].class)))
          .thenAnswer(inv -> inv.getArgument(0));

      configStatic.when(() -> Config.longOption(nodeSubConfig, "storeSize")).thenReturn(storeSize);
      configStatic
          .when(() -> Config.longOption(nodeSubConfig, "clientCacheSize"))
          .thenReturn(clientCache);
      configStatic
          .when(() -> Config.longOption(nodeSubConfig, "slashdotCacheSize"))
          .thenReturn(slashdotCache);

      bandwidth
          .when(() -> BandwidthManipulator.detectBandwidthLimits(bandwidthIndicator))
          .thenReturn(new BandwidthLimit(2097152L, 1048576L, "desc", false));

      toadlet.handleMethodGET(
          new URI(FirstTimeWizardNewToadlet.TOADLET_URL), mock(HTTPRequest.class), ctx);
    }

    assertTrue(toadlet.htmlWritten);
    assertNotNull(toadlet.lastModel);
    assertEquals(Boolean.TRUE, toadlet.lastModel.get("isPasswordAlreadySet"));
    assertFalse(toadlet.lastModel.containsKey("setPassword"));
    assertEquals("1024", toadlet.lastModel.get("downloadLimitDetected"));
    assertEquals("512", toadlet.lastModel.get("uploadLimitDetected"));
    assertEquals("form-pass", toadlet.lastModel.get("formPassword"));
  }

  @Test
  void handleMethodPOST_whenValidInput_savesConfigAndRedirects() throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, core, config);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    Map<String, String> parts = new HashMap<>();
    parts.put("knowSomeone", "");
    parts.put("connectToStrangers", "on");
    parts.put("haveMonthlyLimit", "");
    parts.put("downLimit", "20000");
    parts.put("upLimit", "20000");
    parts.put("monthlyLimit", "");
    parts.put("storage", "2");
    parts.put("setPassword", "");
    parts.put("password", "");
    parts.put("confirmPassword", "");
    HTTPRequest request = buildRequest(parts);

    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.ipDetector()).thenReturn(mock(NodeIPDetector.class));

    network.crypta.node.subsystem.NodeStorageSubsystem storage =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeStorageSubsystem.class);
    when(node.storage()).thenReturn(storage);

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class);
        MockedStatic<DatastoreUtil> datastore = mockStatic(DatastoreUtil.class);
        MockedStatic<BandwidthManipulator> bandwidth = mockStatic(BandwidthManipulator.class);
        MockedStatic<DatastoreSize> datastoreSize = mockStatic(DatastoreSize.class)) {

      BaseL10n base = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);
      when(base.getString(anyString())).thenAnswer(inv -> inv.getArgument(0));
      when(base.getString(anyString(), anyString())).thenAnswer(inv -> inv.getArgument(0));
      when(base.getString(anyString(), any(String[].class), any(String[].class)))
          .thenAnswer(inv -> inv.getArgument(0));

      datastore.when(DatastoreUtil::maxDatastoreSize).thenReturn(10L * DatastoreUtil.ONE_GIB);
      datastore.when(() -> DatastoreUtil.autodetectDatastoreSize(core, config)).thenReturn(0L);
      bandwidth
          .when(() -> BandwidthManipulator.detectBandwidthLimits(any()))
          .thenThrow(new PluginNotFoundException("none"));

      toadlet.handleMethodPOST(new URI(FirstTimeWizardNewToadlet.TOADLET_URL), request, ctx);

      datastoreSize.verify(() -> DatastoreSize.setDatastoreSize(eq("2GiB"), eq(config)), times(1));
    }

    verify(nodeSubConfig).set("inputBandwidthLimit", "20000KiB");
    verify(nodeSubConfig).set("outputBandwidthLimit", "20000KiB");
    verify(fproxySubConfig).set("hasCompletedWizard", true);
    verify(securityLevels).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
    verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    verify(storage).setMasterPassword("", true);
    verify(core).storeConfig();
    verify(ctx)
        .sendReplyHeaders(
            eq(302),
            eq("Found"),
            ArgumentMatchers.any(),
            eq("text/html; charset=UTF-8"),
            anyLong());
    assertTrue(toadlet.htmlWritten);
    @SuppressWarnings("unchecked")
    Map<String, String> errors = (Map<String, String>) toadlet.lastModel.get("errors");
    assertTrue(errors.isEmpty());
  }

  @Test
  void handleMethodPOST_whenDownloadBelowMinimum_rendersErrorsInsteadOfRedirect() throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, core, config);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    Map<String, String> parts = new HashMap<>();
    parts.put("haveMonthlyLimit", "");
    parts.put("downLimit", "1");
    parts.put("upLimit", "20000");
    parts.put("monthlyLimit", "");
    parts.put("storage", "2");
    parts.put("setPassword", "");
    parts.put("password", "");
    parts.put("confirmPassword", "");
    HTTPRequest request = buildRequest(parts);

    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.ipDetector()).thenReturn(mock(NodeIPDetector.class));

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class);
        MockedStatic<DatastoreUtil> datastore = mockStatic(DatastoreUtil.class);
        MockedStatic<BandwidthManipulator> bandwidth = mockStatic(BandwidthManipulator.class)) {

      BaseL10n base = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(base);
      when(base.getString(anyString())).thenAnswer(inv -> inv.getArgument(0));
      when(base.getString(anyString(), anyString())).thenAnswer(inv -> inv.getArgument(0));
      when(base.getString(anyString(), any(String[].class), any(String[].class)))
          .thenAnswer(inv -> inv.getArgument(0));

      datastore.when(DatastoreUtil::maxDatastoreSize).thenReturn(10L * DatastoreUtil.ONE_GIB);
      bandwidth
          .when(() -> BandwidthManipulator.detectBandwidthLimits(any()))
          .thenThrow(new PluginNotFoundException("none"));

      toadlet.handleMethodPOST(new URI(FirstTimeWizardNewToadlet.TOADLET_URL), request, ctx);
    }

    assertTrue(toadlet.htmlWritten);
    verify(ctx, never()).sendReplyHeaders(eq(302), anyString(), any(), anyString(), anyLong());
    assertNotNull(toadlet.lastModel);
    @SuppressWarnings("unchecked")
    Map<String, String> errors = (Map<String, String>) toadlet.lastModel.get("errors");
    assertTrue(errors.containsKey("downloadLimitError"));
    verifyNoInteractions(nodeSubConfig, fproxySubConfig);
  }

  private HTTPRequest buildRequest(Map<String, String> parts) {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe(anyString(), anyInt()))
        .thenAnswer(
            invocation -> {
              String key = invocation.getArgument(0, String.class);
              return parts.getOrDefault(key, "");
            });
    return request;
  }

  private static final class TestableFirstTimeWizardNewToadlet extends FirstTimeWizardNewToadlet {
    Map<String, Object> lastModel;
    boolean htmlWritten;

    TestableFirstTimeWizardNewToadlet(
        HighLevelSimpleClient client, NodeClientCore core, Config config) {
      super(client, core, config);
    }

    @Override
    void addChild(
        HTMLNode parent, String templateName, Map<String, Object> model, String l10nPrefix) {
      this.lastModel = model;
      parent.addChild("div", "id", templateName);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      this.htmlWritten = true;
    }

    @Override
    protected void writeTemporaryRedirect(ToadletContext ctx, String msg, String location) {}
  }
}
