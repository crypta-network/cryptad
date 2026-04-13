package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FileInsertWizardToadletTest {

  @Mock SecurityLevelsPort securityLevelsPort;

  @Mock ToadletContainer container;

  private FileInsertWizardToadlet toadlet;

  @BeforeEach
  void setUp() throws Exception {
    toadlet =
        createToadlet(new InsertCompatibilityModes(List.of("COMPAT_DEFAULT"), "COMPAT_DEFAULT"));
  }

  @Test
  void path_returnsConfiguredPath() {
    assertEquals(FileInsertWizardToadlet.PATH, toadlet.path());
  }

  @Test
  void constructor_whenRuntimePortsProvided_noLongerNeedsNodeClientCore() {
    assertEquals(1, FileInsertWizardToadlet.class.getDeclaredConstructors().length);
    assertArrayEquals(
        new Class<?>[] {FileInsertWizardToadletRuntimePorts.class},
        FileInsertWizardToadlet.class.getDeclaredConstructors()[0].getParameterTypes());
  }

  @Test
  void isEnabled_whenGatewayDisallowed_returnsFalse() {
    when(container.publicGatewayMode()).thenReturn(true);
    assertFalse(toadlet.isEnabled(null));
  }

  @Test
  void isEnabled_whenGatewayAndFullAccess_returnsTrue() {
    when(container.publicGatewayMode()).thenReturn(true);
    ToadletContext ctx = mock(ToadletContext.class);
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    assertTrue(toadlet.isEnabled(ctx));
  }

  @Test
  void isEnabled_whenNotGateway_returnsTrue() {
    when(container.publicGatewayMode()).thenReturn(false);
    assertTrue(toadlet.isEnabled(null));
  }

  @Test
  void handleMethodGET_whenLowThreat_prefersCanonicalRadio() throws Exception {
    when(container.publicGatewayMode()).thenReturn(false);
    when(securityLevelsPort.snapshot())
        .thenReturn(securitySnapshot(SecurityNetworkThreatLevel.LOW));

    PageHolder holder = new PageHolder();
    PageMaker pageMaker = buildPageMaker(holder);
    CapturingContext ctx = new CapturingContext(pageMaker, true, false);

    toadlet.handleMethodGET(new URI("http://localhost/insertfile/"), mock(HTTPRequest.class), ctx);

    HTMLNode chkInput = findById(holder.page.getContentNode(), "keytypeChk");
    HTMLNode sskInput = findById(holder.page.getContentNode(), "keytypeSsk");

    assertNotNull(chkInput);
    assertNotNull(sskInput);
    assertEquals("checked", chkInput.getAttribute("checked"));
    assertNull(sskInput.getAttribute("checked"));
  }

  @Test
  void handleMethodGET_afterRandomInsert_prefersSskRadio() throws Exception {
    when(container.publicGatewayMode()).thenReturn(false);
    when(securityLevelsPort.snapshot())
        .thenReturn(securitySnapshot(SecurityNetworkThreatLevel.LOW));

    PageHolder holder = new PageHolder();
    PageMaker pageMaker = buildPageMaker(holder);
    CapturingContext ctx = new CapturingContext(pageMaker, true, false);

    toadlet.reportRandomInsert();

    toadlet.handleMethodGET(new URI("http://localhost/insertfile/"), mock(HTTPRequest.class), ctx);

    HTMLNode chkInput = findById(holder.page.getContentNode(), "keytypeChk");
    HTMLNode sskInput = findById(holder.page.getContentNode(), "keytypeSsk");

    assertNotNull(chkInput);
    assertNotNull(sskInput);
    assertNull(chkInput.getAttribute("checked"));
    assertEquals("checked", sskInput.getAttribute("checked"));
  }

  @Test
  void handleMethodGET_whenMaximumThreat_prefersSskRadio() throws Exception {
    when(container.publicGatewayMode()).thenReturn(false);
    when(securityLevelsPort.snapshot())
        .thenReturn(securitySnapshot(SecurityNetworkThreatLevel.MAXIMUM));

    PageHolder holder = new PageHolder();
    PageMaker pageMaker = buildPageMaker(holder);
    CapturingContext ctx = new CapturingContext(pageMaker, true, false);

    toadlet.handleMethodGET(new URI("http://localhost/insertfile/"), mock(HTTPRequest.class), ctx);

    HTMLNode chkInput = findById(holder.page.getContentNode(), "keytypeChk");
    HTMLNode sskInput = findById(holder.page.getContentNode(), "keytypeSsk");

    assertNotNull(chkInput);
    assertNotNull(sskInput);
    assertNull(chkInput.getAttribute("checked"));
    assertEquals("checked", sskInput.getAttribute("checked"));
  }

  @Test
  void handleMethodGET_whenAdvancedModeEnabled_rendersDetachedCompatibilityOptionsInOrder()
      throws Exception {
    toadlet =
        createToadlet(
            new InsertCompatibilityModes(List.of("COMPAT_DEFAULT", "COMPAT_1468"), "COMPAT_1468"));
    when(container.publicGatewayMode()).thenReturn(false);
    when(securityLevelsPort.snapshot())
        .thenReturn(securitySnapshot(SecurityNetworkThreatLevel.LOW));

    PageHolder holder = new PageHolder();
    PageMaker pageMaker = buildPageMaker(holder);
    CapturingContext ctx = new CapturingContext(pageMaker, true, true);

    toadlet.handleMethodGET(new URI("http://localhost/insertfile/"), mock(HTTPRequest.class), ctx);

    HTMLNode select =
        findByNameAndAttribute(holder.page.getContentNode(), "select", "name", "compatibilityMode");
    assertNotNull(select);
    List<HTMLNode> options = select.getChildren();
    assertEquals(
        List.of("COMPAT_DEFAULT", "COMPAT_1468"),
        options.stream().map(option -> option.getAttribute("value")).toList());
    assertNull(options.getFirst().getAttribute("selected"));
    assertEquals("", options.get(1).getAttribute("selected"));
  }

  @Test
  void handleMethodGET_whenPublicGatewayAndNoFullAccess_sendsUnauthorized() throws Exception {
    when(container.publicGatewayMode()).thenReturn(true);

    PageHolder holder = new PageHolder();
    PageMaker pageMaker = buildPageMaker(holder);
    CapturingContext ctx = new CapturingContext(pageMaker, false, false);

    toadlet.handleMethodGET(new URI("http://localhost/insertfile/"), mock(HTTPRequest.class), ctx);

    assertEquals(403, ctx.getStatusCode());
  }

  private FileInsertWizardToadlet createToadlet(InsertCompatibilityModes compatibilityModes)
      throws Exception {
    FileInsertWizardToadlet created =
        new FileInsertWizardToadlet(
            new FileInsertWizardToadletRuntimePorts(securityLevelsPort, compatibilityModes));
    setContainer(created, container);
    return created;
  }

  private static void setContainer(FileInsertWizardToadlet toadlet, ToadletContainer container)
      throws Exception {
    Field field = Toadlet.class.getDeclaredField("container");
    field.setAccessible(true);
    field.set(toadlet, container);
  }

  private static HTMLNode findById(HTMLNode root, String id) {
    if (id.equals(root.getAttribute("id"))) {
      return root;
    }
    for (HTMLNode child : root.getChildren()) {
      HTMLNode found = findById(child, id);
      if (found != null) {
        return found;
      }
    }
    return null;
  }

  private static HTMLNode findByNameAndAttribute(
      HTMLNode root, String name, String attributeName, String attributeValue) {
    if (name.equals(root.getName()) && attributeValue.equals(root.getAttribute(attributeName))) {
      return root;
    }
    for (HTMLNode child : root.getChildren()) {
      HTMLNode found = findByNameAndAttribute(child, name, attributeName, attributeValue);
      if (found != null) {
        return found;
      }
    }
    return null;
  }

  private static SecurityLevelsSnapshot securitySnapshot(SecurityNetworkThreatLevel level) {
    return new SecurityLevelsSnapshot(level, SecurityPhysicalThreatLevel.NORMAL, false, false, "");
  }

  private static final class PageHolder {
    PageNode page;
  }

  private static PageMaker buildPageMaker(PageHolder holder) {
    PageMaker pageMaker = mock(PageMaker.class);
    when(pageMaker.getPageNode(anyString(), any(ToadletContext.class)))
        .thenAnswer(
            _ -> {
              HTMLNode outer = new HTMLNode("div");
              HTMLNode head = new HTMLNode("head");
              HTMLNode content = new HTMLNode("div");
              holder.page = new PageNode(outer, head, content);
              return holder.page;
            });
    when(pageMaker.getInfobox(anyString(), anyString(), anyBoolean()))
        .thenAnswer(
            _ -> {
              HTMLNode outer = new HTMLNode("div");
              HTMLNode content = outer.addChild("div");
              return new InfoboxNode(outer, content);
            });
    when(pageMaker.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              HTMLNode outer = new HTMLNode("div");
              HTMLNode content = outer.addChild("div");
              InfoboxNode node = new InfoboxNode(outer, content);
              parent.addChild(node.getOuterNode());
              return node.getContentNode();
            });
    return pageMaker;
  }

  /**
   * Captures response data while providing just enough context behavior for the toadlet under test.
   */
  private static final class CapturingContext implements ToadletContext {

    private final PageMaker pageMaker;
    private final boolean fullAccess;
    private final boolean advanced;
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private int statusCode = -1;

    CapturingContext(PageMaker pageMaker, boolean fullAccess, boolean advanced) {
      this.pageMaker = pageMaker;
      this.fullAccess = fullAccess;
      this.advanced = advanced;
    }

    @Override
    public void sendReplyHeaders(
        int code, String desc, MultiValueTable<String, String> mvt, String mimeType, long length) {
      this.statusCode = code;
    }

    @Override
    public void sendReplyHeaders(
        int code,
        String desc,
        MultiValueTable<String, String> mvt,
        String mimeType,
        long length,
        boolean forceDisableJavascript) {
      this.statusCode = code;
    }

    @Override
    public void sendReplyHeadersStatic(
        int code,
        String desc,
        MultiValueTable<String, String> mvt,
        String mimeType,
        long length,
        Instant mTime) {
      this.statusCode = code;
    }

    @Override
    public void sendReplyHeadersFProxy(
        int code, String desc, MultiValueTable<String, String> mvt, String mimeType, long length) {
      this.statusCode = code;
    }

    @Override
    public void writeData(byte[] data, int offset, int length) {
      body.write(data, offset, length);
    }

    @Override
    public void forceDisconnect() {
      this.statusCode = -999; // signal forced disconnect for potential assertions
    }

    @Override
    public void writeData(byte[] data) throws IOException {
      body.write(data);
    }

    @Override
    public void writeData(Bucket data) {
      throw new UnsupportedOperationException("Bucket streaming not required in this test stub");
    }

    @Override
    public PageMaker getPageMaker() {
      return pageMaker;
    }

    @Override
    public String getFormPassword() {
      return "";
    }

    @Override
    public boolean checkFormPassword(HTTPRequest request, String redirectTo) {
      return true;
    }

    @Override
    public boolean checkFormPassword(HTTPRequest request) {
      return true;
    }

    @Override
    public boolean hasFormPassword(HTTPRequest request) {
      return true;
    }

    @Override
    public boolean checkFullAccess(Toadlet toadlet) {
      return fullAccess;
    }

    @Override
    public network.crypta.runtime.alerts.UserAlertManager getAlertManager() {
      UserAlertManager manager = mock(UserAlertManager.class);
      when(manager.createSummary()).thenReturn(new HTMLNode("div"));
      when(manager.createSummary(true)).thenReturn(new HTMLNode("div"));
      return manager;
    }

    @Override
    @SuppressWarnings({"TypeParameterUnusedInFormals"})
    public <T extends network.crypta.clients.http.BookmarkManagerHandle> T getBookmarkManager() {
      return null;
    }

    @Override
    public BucketFactory getBucketFactory() {
      return null;
    }

    @Override
    public MultiValueTable<String, String> getHeaders() {
      return new MultiValueTable<>();
    }

    @Override
    public ReceivedCookie getCookie(URI domain, URI path, String name) {
      return null;
    }

    @Override
    public void setCookie(Cookie newCookie) {
      // Intentionally no-op for tests; cookie propagation is irrelevant for current scenarios.
    }

    @Override
    public HTMLNode addFormChild(HTMLNode parentNode, String target, String id) {
      HTMLNode form = new HTMLNode("form");
      form.addAttribute("action", target);
      form.addAttribute("id", id);
      form.addAttribute("name", id);
      parentNode.addChild(form);
      return form;
    }

    @Override
    public boolean isAllowedFullAccess() {
      return fullAccess;
    }

    @Override
    public boolean isAdvancedModeEnabled() {
      return advanced;
    }

    @Override
    public boolean doRobots() {
      return false;
    }

    @Override
    public ToadletContainer getContainer() {
      return null;
    }

    @Override
    public boolean disableProgressPage() {
      return false;
    }

    @Override
    public Toadlet activeToadlet() {
      return null;
    }

    @Override
    public String getUniqueId() {
      return "id";
    }

    @Override
    public URI getUri() {
      return URI.create("http://localhost/");
    }

    @Override
    public RefilterPolicy getReFilterPolicy() {
      return RefilterPolicy.ACCEPT_OLD;
    }

    int getStatusCode() {
      return statusCode;
    }
  }
}
