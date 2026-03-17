package network.crypta.clients.http;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FirstTimeWizardNewToadletTest {

  private static final FirstTimeWizardSnapshot DEFAULT_SNAPSHOT =
      new FirstTimeWizardSnapshot(
          false,
          "2.00",
          "1.25",
          Fields.parseLong("1.25GiB"),
          "10.00",
          Fields.parseLong("10GiB"),
          10,
          976562,
          "49.44",
          "",
          "");

  @Mock private HighLevelSimpleClient client;
  @Mock private FirstTimeWizardPort wizardPort;
  @Mock private ToadletContext ctx;
  @Mock private PageMaker pageMaker;

  @BeforeEach
  void setUp() {
    HTMLNode outer = new HTMLNode("div");
    HTMLNode head = outer.addChild("head");
    HTMLNode content = outer.addChild("div");
    PageNode pageNode = new PageNode(outer, head, content);

    lenient().when(ctx.getPageMaker()).thenReturn(pageMaker);
    lenient().when(ctx.getFormPassword()).thenReturn("form-pass");
    lenient()
        .when(pageMaker.getPageNode(anyString(), eq(ctx), any(PageMaker.RenderParameters.class)))
        .thenReturn(pageNode);
    lenient().when(wizardPort.snapshot()).thenReturn(DEFAULT_SNAPSHOT);
  }

  @Test
  void path_returnsWizardUrl() {
    FirstTimeWizardNewToadlet toadlet = new TestableFirstTimeWizardNewToadlet(client, wizardPort);

    assertEquals(FirstTimeWizardNewToadlet.TOADLET_URL, toadlet.path());
  }

  @Test
  void handleMethodGET_whenAccessDenied_returnsEarly() throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, wizardPort);
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(
        new URI(FirstTimeWizardNewToadlet.TOADLET_URL), mock(HTTPRequest.class), ctx);

    verify(ctx).checkFullAccess(toadlet);
    verify(wizardPort, never()).snapshot();
    assertFalse(toadlet.htmlWritten);
    assertNull(toadlet.lastModel);
  }

  @Test
  void handleMethodGET_whenSnapshotHasSuggestedValues_populatesModelFromSnapshot()
      throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, wizardPort);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(wizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                true,
                "2.50",
                "1.25",
                Fields.parseLong("1.25GiB"),
                "10.00",
                Fields.parseLong("10GiB"),
                10,
                976562,
                "49.44",
                "1024",
                "512"));

    withMockedNodeL10n(
        () ->
            toadlet.handleMethodGET(
                new URI(FirstTimeWizardNewToadlet.TOADLET_URL), mock(HTTPRequest.class), ctx));

    assertTrue(toadlet.htmlWritten);
    assertNotNull(toadlet.lastModel);
    assertEquals(Boolean.TRUE, toadlet.lastModel.get("isPasswordAlreadySet"));
    assertFalse(toadlet.lastModel.containsKey("setPassword"));
    assertEquals("2.50", toadlet.lastModel.get("storageLimit"));
    assertEquals("1.25", toadlet.lastModel.get("minStorageLimit"));
    assertEquals("49.44", toadlet.lastModel.get("minBandwidthMonthlyLimit"));
    assertEquals("1024", toadlet.lastModel.get("downloadLimit"));
    assertEquals("512", toadlet.lastModel.get("uploadLimit"));
    assertEquals("1024", toadlet.lastModel.get("downloadLimitDetected"));
    assertEquals("512", toadlet.lastModel.get("uploadLimitDetected"));
    assertEquals("form-pass", toadlet.lastModel.get("formPassword"));
  }

  @Test
  void handleMethodPOST_whenValidInput_appliesDetachedSubmissionAndRedirects() throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, wizardPort);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    Map<String, String> parts = new HashMap<>();
    parts.put("knowSomeone", "on");
    parts.put("connectToStrangers", "");
    parts.put("haveMonthlyLimit", "");
    parts.put("downLimit", "20000");
    parts.put("upLimit", "20000");
    parts.put("monthlyLimit", "");
    parts.put("storage", "2");
    parts.put("setPassword", "on");
    parts.put("password", "secret");
    parts.put("confirmPassword", "secret");
    HTTPRequest request = buildRequest(parts);

    withMockedNodeL10n(
        () ->
            toadlet.handleMethodPOST(new URI(FirstTimeWizardNewToadlet.TOADLET_URL), request, ctx));

    verify(wizardPort)
        .applySubmission(
            new FirstTimeWizardSubmission(
                true, false, false, "20000", "20000", "", "2", true, "secret"));
    verify(ctx)
        .sendReplyHeaders(
            eq(302),
            eq("Found"),
            ArgumentMatchers.any(),
            eq("text/html; charset=UTF-8"),
            anyLong());
    assertFalse(toadlet.htmlWritten);
    assertNull(toadlet.lastModel);
  }

  @Test
  void handleMethodPOST_whenDownloadBelowMinimum_rendersErrorsInsteadOfRedirect() throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, wizardPort);
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

    withMockedNodeL10n(
        () ->
            toadlet.handleMethodPOST(new URI(FirstTimeWizardNewToadlet.TOADLET_URL), request, ctx));

    assertTrue(toadlet.htmlWritten);
    verify(ctx, never()).sendReplyHeaders(eq(302), anyString(), any(), anyString(), anyLong());
    verify(wizardPort, never()).applySubmission(any(FirstTimeWizardSubmission.class));
    assertNotNull(toadlet.lastModel);
    @SuppressWarnings("unchecked")
    Map<String, String> errors = (Map<String, String>) toadlet.lastModel.get("errors");
    assertTrue(errors.containsKey("downloadLimitError"));
  }

  @Test
  void handleMethodPOST_whenDownloadExceedsIntBackedConfigRange_rendersErrors() throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, wizardPort);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    Map<String, String> parts = new HashMap<>();
    parts.put("haveMonthlyLimit", "");
    parts.put("downLimit", Integer.toString(Integer.MAX_VALUE / 1024 + 1));
    parts.put("upLimit", "20000");
    parts.put("monthlyLimit", "");
    parts.put("storage", "2");
    parts.put("setPassword", "");
    parts.put("password", "");
    parts.put("confirmPassword", "");
    HTTPRequest request = buildRequest(parts);

    withMockedNodeL10n(
        () ->
            toadlet.handleMethodPOST(new URI(FirstTimeWizardNewToadlet.TOADLET_URL), request, ctx));

    assertTrue(toadlet.htmlWritten);
    verify(ctx, never()).sendReplyHeaders(eq(302), anyString(), any(), anyString(), anyLong());
    verify(wizardPort, never()).applySubmission(any(FirstTimeWizardSubmission.class));
    assertNotNull(toadlet.lastModel);
    @SuppressWarnings("unchecked")
    Map<String, String> errors = (Map<String, String>) toadlet.lastModel.get("errors");
    assertTrue(errors.containsKey("downloadLimitError"));
  }

  @Test
  void handleMethodPOST_whenStorageExceedsExactRoundedCap_rendersErrors() throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, wizardPort);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(wizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                false,
                "1.00",
                "1.00",
                Fields.parseLong("1GiB"),
                "1.24",
                Fields.parseLong("1.235GiB"),
                10,
                976562,
                "49.44",
                "",
                ""));

    Map<String, String> parts = new HashMap<>();
    parts.put("haveMonthlyLimit", "");
    parts.put("downLimit", "20000");
    parts.put("upLimit", "20000");
    parts.put("monthlyLimit", "");
    parts.put("storage", "1.24");
    parts.put("setPassword", "");
    parts.put("password", "");
    parts.put("confirmPassword", "");
    HTTPRequest request = buildRequest(parts);

    withMockedNodeL10n(
        () ->
            toadlet.handleMethodPOST(new URI(FirstTimeWizardNewToadlet.TOADLET_URL), request, ctx));

    assertTrue(toadlet.htmlWritten);
    verify(ctx, never()).sendReplyHeaders(eq(302), anyString(), any(), anyString(), anyLong());
    verify(wizardPort, never()).applySubmission(any(FirstTimeWizardSubmission.class));
    assertNotNull(toadlet.lastModel);
    @SuppressWarnings("unchecked")
    Map<String, String> errors = (Map<String, String>) toadlet.lastModel.get("errors");
    assertTrue(errors.containsKey("storageLimitError"));
  }

  @Test
  void handleMethodPOST_whenMonthlyLimitUsesUnsupportedExponentFormat_rendersErrors()
      throws Exception {
    TestableFirstTimeWizardNewToadlet toadlet =
        new TestableFirstTimeWizardNewToadlet(client, wizardPort);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    Map<String, String> parts = new HashMap<>();
    parts.put("haveMonthlyLimit", "on");
    parts.put("monthlyLimit", "1e8");
    parts.put("storage", "2");
    parts.put("setPassword", "");
    parts.put("password", "");
    parts.put("confirmPassword", "");
    HTTPRequest request = buildRequest(parts);

    withMockedNodeL10n(
        () ->
            toadlet.handleMethodPOST(new URI(FirstTimeWizardNewToadlet.TOADLET_URL), request, ctx));

    assertTrue(toadlet.htmlWritten);
    verify(ctx, never()).sendReplyHeaders(eq(302), anyString(), any(), anyString(), anyLong());
    verify(wizardPort, never()).applySubmission(any(FirstTimeWizardSubmission.class));
    assertNotNull(toadlet.lastModel);
    @SuppressWarnings("unchecked")
    Map<String, String> errors = (Map<String, String>) toadlet.lastModel.get("errors");
    assertTrue(errors.containsKey("bandwidthMonthlyLimitError"));
  }

  private MockedStatic<NodeL10n> mockNodeL10n() {
    MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class);
    BaseL10n base = mock(BaseL10n.class);
    nodeL10n.when(NodeL10n::getBase).thenReturn(base);
    lenient().when(base.getString(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
    lenient()
        .when(base.getString(anyString(), anyString()))
        .thenAnswer(invocation -> invocation.getArgument(1));
    lenient()
        .when(base.getString(anyString(), any(String[].class), any(String[].class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    return nodeL10n;
  }

  private void withMockedNodeL10n(ThrowingAction action) throws Exception {
    try (var _ = mockNodeL10n()) {
      action.run();
    }
  }

  private HTTPRequest buildRequest(Map<String, String> parts) {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe(anyString(), ArgumentMatchers.anyInt()))
        .thenAnswer(
            invocation -> {
              String key = invocation.getArgument(0, String.class);
              return parts.getOrDefault(key, "");
            });
    return request;
  }

  @FunctionalInterface
  private interface ThrowingAction {
    void run() throws Exception;
  }

  private static final class TestableFirstTimeWizardNewToadlet extends FirstTimeWizardNewToadlet {
    Map<String, Object> lastModel;
    boolean htmlWritten;

    TestableFirstTimeWizardNewToadlet(
        HighLevelSimpleClient client, FirstTimeWizardPort wizardPort) {
      super(client, wizardPort);
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
    protected void writeTemporaryRedirect(ToadletContext ctx, String msg, String location) {
      // Intentionally no-op in tests; redirects are asserted via the underlying reply headers.
    }
  }
}
