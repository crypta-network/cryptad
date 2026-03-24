package network.crypta.clients.http;

import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.PageChromeSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PageMakerTest {

  @Mock private HTTPRequest request;
  @Mock private ToadletContainer container;
  @Mock private ToadletContext context;
  @Mock private UserAlertManager alertManager;

  private PageMaker newPageMaker() {
    return new PageMaker(PageMaker.THEME.CRYPTAFORGE);
  }

  @Test
  void filterCSSIdentifier_whenInputContainsInvalidChars_filtersAndPads() {
    String result = PageMaker.filterCSSIdentifier("-1 inv@lid");

    assertEquals("-__inv_lid", result);
  }

  @Test
  void filterCSSIdentifier_whenTooShort_padsToTwoCharacters() {
    assertEquals("a_", PageMaker.filterCSSIdentifier("a"));
    assertEquals("__", PageMaker.filterCSSIdentifier(""));
  }

  @Test
  void filterCSSIdentifier_whenInputContainsClassNameLikeChars_filtersDeterministically() {
    String identifier =
        PageMaker.filterCSSIdentifier(
            "network.crypta.clients.http.PageMakerTest$DummyPlugin-testKey");

    assertEquals("network_crypta_clients_http_PageMakerTest_DummyPlugin-testKey", identifier);
  }

  @Test
  void getInfobox_whenHeaderNull_throwsNullPointer() {
    PageMaker maker = newPageMaker();

    assertThrows(NullPointerException.class, () -> maker.getInfobox((HTMLNode) null, null, false));
  }

  @Test
  void getInfobox_withCategoryTitleAndUnique_setsClassAndId() {
    PageMaker maker = newPageMaker();
    HTMLNode header = new HTMLNode("#", "Header");

    InfoboxNode infobox = maker.getInfobox("warning", header, "box-title", true);

    HTMLNode outer = infobox.getOuterNode();
    assertEquals("div", outer.getName());
    assertEquals("infobox warning", outer.getAttribute("class"));
    assertEquals("box-title", outer.getAttribute("id"));

    assertEquals(2, outer.getChildren().size());
    HTMLNode headerContainer = outer.getChildren().getFirst();
    assertEquals("div", headerContainer.getName());
    assertEquals("infobox-header", headerContainer.getAttribute("class"));
    assertEquals("Header", headerContainer.getChildren().getFirst().getContent());

    HTMLNode content = outer.getChildren().get(1);
    assertSame(infobox.getContentNode(), content);
    assertEquals("div", content.getName());
    assertEquals("infobox-content", content.getAttribute("class"));
  }

  @Test
  void parseMode_whenParamRequestsAdvanced_enablesContainerAdvancedMode() {
    PageMaker maker = newPageMaker();
    when(container.isAdvancedModeEnabled()).thenReturn(false);
    when(request.isParameterSet("fproxyAdvancedMode")).thenReturn(true);
    when(request.getIntParam("fproxyAdvancedMode", PageMaker.MODE_SIMPLE))
        .thenReturn(PageMaker.MODE_ADVANCED);

    int mode = maker.parseMode(request, container);

    assertEquals(PageMaker.MODE_ADVANCED, mode);
    verify(container).setAdvancedMode(true);
  }

  @Test
  void parseMode_whenParamRequestsSimple_disablesContainerAdvancedMode() {
    PageMaker maker = newPageMaker();
    when(container.isAdvancedModeEnabled()).thenReturn(true);
    when(request.isParameterSet("fproxyAdvancedMode")).thenReturn(true);
    when(request.getIntParam("fproxyAdvancedMode", PageMaker.MODE_ADVANCED))
        .thenReturn(PageMaker.MODE_SIMPLE);

    int mode = maker.parseMode(request, container);

    assertEquals(PageMaker.MODE_SIMPLE, mode);
    verify(container).setAdvancedMode(false);
  }

  @Test
  void parseMode_whenParamMissing_keepsContainerState() {
    PageMaker maker = newPageMaker();
    when(container.isAdvancedModeEnabled()).thenReturn(true);
    when(request.isParameterSet("fproxyAdvancedMode")).thenReturn(false);

    int mode = maker.parseMode(request, container);

    assertEquals(PageMaker.MODE_ADVANCED, mode);
    verify(container, never()).setAdvancedMode(anyBoolean());
  }

  @Test
  void advancedMode_whenContainerAlreadyAdvanced_returnsTrue() {
    PageMaker maker = newPageMaker();
    when(container.isAdvancedModeEnabled()).thenReturn(true);
    when(request.isParameterSet("fproxyAdvancedMode")).thenReturn(false);

    assertTrue(maker.advancedMode(request, container));
  }

  @Test
  void createBackLink_whenRefererPresent_usesRefererHref() {
    PageMaker maker = newPageMaker();
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put("referer", "http://example.test/path");
    when(context.getHeaders()).thenReturn(headers);

    HTMLNode link = maker.createBackLink(context, "Back");

    assertEquals("http://example.test/path", link.getAttribute("href"));
    assertEquals("Back", link.getAttribute("title"));
    assertEquals("Back", link.getChildren().getFirst().getContent());
  }

  @Test
  void createBackLink_whenRefererMissing_fallsBackToJavascript() {
    PageMaker maker = newPageMaker();
    when(context.getHeaders()).thenReturn(new MultiValueTable<>());

    HTMLNode link = maker.createBackLink(context, "Return");

    assertEquals("javascript:back()", link.getAttribute("href"));
    assertEquals("Return", link.getChildren().getFirst().getContent());
  }

  @Test
  void setTheme_whenPassedNull_resetsToDefault() {
    PageMaker maker = new PageMaker(PageMaker.THEME.CRYPTAFORGE);

    maker.setTheme(null);

    assertEquals(PageMaker.THEME.getDefault(), maker.getTheme());
  }

  @Test
  void getPageNode_whenPageChromePortMissing_hidesStatusBar() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);

    PageNode page =
        maker.getPageNode(
            "Status",
            context,
            new PageMaker.RenderParameters().renderNavigationLinks(false).renderModeSwitch(false));

    assertFalse(page.generate().contains("statusbar-container"));
  }

  @Test
  void getPageNode_whenPageChromeSnapshotProvided_rendersStatusBarShell() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(true);
    maker.setPageChromePort(
        () ->
            new PageChromeSnapshot(
                SecurityNetworkThreatLevel.HIGH,
                SecurityPhysicalThreatLevel.MAXIMUM,
                4,
                2,
                2,
                5,
                true,
                10));

    PageNode page =
        maker.getPageNode(
            "Status",
            context,
            new PageMaker.RenderParameters().renderNavigationLinks(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("statusbar-container"));
    assertTrue(html.contains("statusbar-seclevels"));
    assertTrue(html.contains("progressbar-peers"));
    assertTrue(html.contains("/seclevels/"));
    assertTrue(html.contains("4 / 10"));
  }

  @Test
  void renderParameters_togglesAreImmutable() {
    PageMaker.RenderParameters defaults = new PageMaker.RenderParameters();

    PageMaker.RenderParameters withoutNav = defaults.renderNavigationLinks(false);
    PageMaker.RenderParameters withoutStatus = defaults.renderStatus(false);
    PageMaker.RenderParameters withoutModeSwitch = defaults.renderModeSwitch(false);

    assertTrue(defaults.isRenderNavigationLinks());
    assertTrue(defaults.isRenderStatus());
    assertTrue(defaults.isRenderModeSwitch());

    assertFalse(withoutNav.isRenderNavigationLinks());
    assertTrue(withoutNav.isRenderStatus());
    assertTrue(withoutNav.isRenderModeSwitch());

    assertTrue(withoutStatus.isRenderNavigationLinks());
    assertFalse(withoutStatus.isRenderStatus());
    assertTrue(withoutStatus.isRenderModeSwitch());

    assertTrue(withoutModeSwitch.isRenderNavigationLinks());
    assertTrue(withoutModeSwitch.isRenderStatus());
    assertFalse(withoutModeSwitch.isRenderModeSwitch());
  }

  @Test
  void addNavigationLink_whenMenuMissing_throwsNullPointer() {
    PageMaker maker = newPageMaker();

    assertThrows(
        NullPointerException.class,
        () -> maker.addNavigationLink("missing", "/path", "name", "title", false, null));
  }

  private void stubPageRenderingContext(boolean renderStatusBar) {
    when(context.isAllowedFullAccess()).thenReturn(true);
    when(context.getContainer()).thenReturn(container);
    when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    when(container.sendAllThemes()).thenReturn(false);
    when(context.activeToadlet()).thenReturn(null);
    if (renderStatusBar) {
      when(context.getAlertManager()).thenReturn(alertManager);
      when(alertManager.createSummary(true)).thenReturn(null);
    }
  }
}
