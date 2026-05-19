package network.crypta.clients.http;

import java.net.URI;
import network.crypta.clients.http.utils.ClientSideLocalizationScript;
import network.crypta.platform.webshell.routes.WebShellPaths;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
  void
      getPageNode_whenJavascriptEnabledAndPageChromeSnapshotProvided_rendersShellSecurityAndLegacyLanguageLinks() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(true);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    maker.setPageChromePort(PageMakerTest::statusSnapshot);

    PageNode page =
        maker.getPageNode(
            "Status",
            context,
            new PageMaker.RenderParameters().renderNavigationLinks(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("statusbar-container"));
    assertTrue(html.contains("statusbar-seclevels"));
    assertTrue(html.contains("progressbar-peers"));
    assertTrue(html.contains("/config/node#l10n"));
    assertTrue(html.contains(WebShellPaths.SHELL_ROOT + "#security"));
    assertFalse(html.contains(WebShellPaths.SHELL_ROOT + "#config"));
    assertFalse(html.contains("/seclevels/"));
    assertTrue(html.contains("4 / 10"));
  }

  @Test
  void getPageNode_whenJavascriptDisabledAndPageChromeSnapshotProvided_rendersLegacyChromeLinks() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(true);
    maker.setPageChromePort(PageMakerTest::statusSnapshot);

    PageNode page =
        maker.getPageNode(
            "Status",
            context,
            new PageMaker.RenderParameters().renderNavigationLinks(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("statusbar-seclevels"));
    assertTrue(html.contains("/config/node#l10n"));
    assertTrue(html.contains(SecurityLevelsToadlet.PATH));
    assertFalse(html.contains(WebShellPaths.SHELL_ROOT + "#config"));
    assertFalse(html.contains(WebShellPaths.SHELL_ROOT + "#security"));
  }

  @Test
  void getPageNode_whenWebPushingEnabled_injectsSharedLocalizationScriptAndRequestId() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    when(container.isFProxyWebPushingEnabled()).thenReturn(true);
    when(context.getUniqueId()).thenReturn("req-push");

    PageNode page =
        maker.getPageNode(
            "Push",
            context,
            new PageMaker.RenderParameters().renderNavigationLinks(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("/static/freenetjs/freenetjs.nocache.js"));
    assertTrue(html.contains("id=\"requestId\""));
    assertTrue(html.contains("value=\"req-push\""));
    assertTrue(html.contains(ClientSideLocalizationScript.getClientSideLocalizationScript()));
  }

  @Test
  void getPageNode_whenRequestUriIsReplacedButActiveToadletIsInfrastructure_skipsNotice() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    Toadlet directoryBrowser = mock(Toadlet.class);
    when(directoryBrowser.path()).thenReturn(LocalDirectoryToadlet.basePath());
    when(context.activeToadlet()).thenReturn(directoryBrowser);
    lenient().when(context.getUri()).thenReturn(URI.create(LegacyHttpPaths.CONFIG_PATH));

    PageNode page =
        maker.getPageNode(
            "Directory",
            context,
            new PageMaker.RenderParameters().renderNavigationLinks(false).renderModeSwitch(false));

    String html = page.generate();

    assertFalse(html.contains("legacy-admin-retirement-notice"));
    assertFalse(html.contains("Web Shell config"));
  }

  @Test
  void getPageNode_whenActiveToadletMissingAndRequestUriIsReplaced_rendersNotice() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    when(context.getUri()).thenReturn(URI.create(SecurityLevelsToadlet.PATH));

    PageNode page =
        maker.getPageNode(
            "Security",
            context,
            new PageMaker.RenderParameters().renderNavigationLinks(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("legacy-admin-retirement-notice"));
    assertTrue(html.contains("Web Shell security"));
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

  @Test
  void getPageNode_whenFullAccessCategoryHasNoVisibleLinks_rendersCategoryRoot() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    maker.addNavigationCategory(
        WebShellPaths.SHELL_ROOT + "#peers",
        "FProxyToadlet.categoryFriends",
        "FProxyToadlet.categoryTitleFriends");

    PageNode page =
        maker.getPageNode(
            "Navigation",
            context,
            new PageMaker.RenderParameters().renderStatus(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("href=\"" + WebShellPaths.SHELL_ROOT + "#peers\""));
  }

  @Test
  void getPageNode_whenCategoryPrimaryLinkDisabled_rendersFallbackCategoryRoot() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    maker.addNavigationCategory(
        WebShellPaths.SHELL_ROOT + "#peers",
        "FProxyToadlet.categoryFriends",
        "FProxyToadlet.categoryTitleFriends",
        LegacyHttpPaths.FRIENDS_PATH,
        ignored -> false);

    PageNode page =
        maker.getPageNode(
            "Navigation",
            context,
            new PageMaker.RenderParameters().renderStatus(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("href=\"" + LegacyHttpPaths.FRIENDS_PATH + "\""));
    assertFalse(html.contains("href=\"" + WebShellPaths.SHELL_ROOT + "#peers\""));
  }

  @Test
  void getPageNode_whenCategoryPrimaryLinkDisabledWithoutFallback_rendersPrimaryCategoryRoot() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    maker.addNavigationCategory(
        WebShellPaths.SHELL_ROOT + "#peers",
        "FProxyToadlet.categoryFriends",
        "FProxyToadlet.categoryTitleFriends",
        null,
        ignored -> false);

    PageNode page =
        maker.getPageNode(
            "Navigation",
            context,
            new PageMaker.RenderParameters().renderStatus(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("href=\"" + WebShellPaths.SHELL_ROOT + "#peers\""));
  }

  @Test
  void getPageNode_whenCategoryRootDisabledButChildVisible_suppressesRootAnchor() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    maker.addNavigationCategory(
        "/apps/queue-manager/",
        "FProxyToadlet.categoryQueue",
        "FProxyToadlet.categoryTitleQueue",
        null,
        false,
        ignored -> false,
        ignored -> false);
    maker.addNavigationLink(
        "FProxyToadlet.categoryQueue",
        "/filterfile/",
        "ContentFilterToadlet.filterFile",
        "ContentFilterToadlet.filterFileTitle",
        false,
        null);

    PageNode page =
        maker.getPageNode(
            "Navigation",
            context,
            new PageMaker.RenderParameters().renderStatus(false).renderModeSwitch(false));

    String html = page.generate();

    assertFalse(html.contains("href=\"/apps/queue-manager/\""));
    assertTrue(html.contains("href=\"/filterfile/\""));
  }

  @Test
  void getPageNode_whenNonFullUserHasVisibleChild_keepsFullOnlyCategoryRootClickable() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    when(context.isAllowedFullAccess()).thenReturn(false);
    maker.addNavigationCategory(
        "/", "FProxyToadlet.categoryBrowsing", "FProxyToadlet.categoryTitleBrowsing");
    maker.addNavigationLink(
        "FProxyToadlet.categoryBrowsing",
        "/welcome/",
        "WelcomeToadlet.name",
        "WelcomeToadlet.title",
        false,
        null);

    PageNode page =
        maker.getPageNode(
            "Navigation",
            context,
            new PageMaker.RenderParameters().renderStatus(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("href=\"/\""));
    assertTrue(html.contains("href=\"/welcome/\""));
  }

  @Test
  void getPageNode_whenNonFullFullOnlyCategoryHasNoVisibleLinks_hidesCategoryRoot() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    when(context.isAllowedFullAccess()).thenReturn(false);
    maker.addNavigationCategory(
        WebShellPaths.SHELL_ROOT + "#peers",
        "FProxyToadlet.categoryFriends",
        "FProxyToadlet.categoryTitleFriends");

    PageNode page =
        maker.getPageNode(
            "Navigation",
            context,
            new PageMaker.RenderParameters().renderStatus(false).renderModeSwitch(false));

    String html = page.generate();

    assertFalse(html.contains("href=\"" + WebShellPaths.SHELL_ROOT + "#peers\""));
  }

  @Test
  void getPageNode_whenNonFullCategoryFallbackIsAllowed_rendersFallbackCategoryRoot() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    when(context.isAllowedFullAccess()).thenReturn(false);
    maker.addNavigationCategory(
        "/apps/queue-manager/",
        "FProxyToadlet.categoryQueue",
        "FProxyToadlet.categoryTitleQueue",
        QueueToadlet.PATH_DOWNLOADS,
        false,
        ignored -> false);

    PageNode page =
        maker.getPageNode(
            "Navigation",
            context,
            new PageMaker.RenderParameters().renderStatus(false).renderModeSwitch(false));

    String html = page.generate();

    assertTrue(html.contains("href=\"" + QueueToadlet.PATH_DOWNLOADS + "\""));
    assertFalse(html.contains("href=\"/apps/queue-manager/\""));
  }

  @Test
  void getPageNode_whenNonFullCategoryFallbackIsDisabled_hidesCategoryRoot() {
    PageMaker maker = newPageMaker();
    stubPageRenderingContext(false);
    when(context.isAllowedFullAccess()).thenReturn(false);
    maker.addNavigationCategory(
        "/apps/queue-manager/",
        "FProxyToadlet.categoryQueue",
        "FProxyToadlet.categoryTitleQueue",
        QueueToadlet.PATH_DOWNLOADS,
        false,
        ignored -> false,
        ignored -> false);

    PageNode page =
        maker.getPageNode(
            "Navigation",
            context,
            new PageMaker.RenderParameters().renderStatus(false).renderModeSwitch(false));

    String html = page.generate();

    assertFalse(html.contains("href=\"" + QueueToadlet.PATH_DOWNLOADS + "\""));
    assertFalse(html.contains("href=\"/apps/queue-manager/\""));
  }

  private static PageChromeSnapshot statusSnapshot() {
    return new PageChromeSnapshot(
        SecurityNetworkThreatLevel.HIGH, SecurityPhysicalThreatLevel.MAXIMUM, 4, 2, 2, 5, true, 10);
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
