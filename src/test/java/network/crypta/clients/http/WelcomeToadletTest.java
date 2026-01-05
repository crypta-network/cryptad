package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class WelcomeToadletTest {

  @Mock private HighLevelSimpleClient client;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  private WelcomeToadlet toadlet;

  private String originalUserDir;

  @BeforeEach
  void setUp() {
    toadlet = new WelcomeToadlet(client, node);
    originalUserDir = System.getProperty("user.dir");
  }

  @AfterEach
  void tearDown() {
    if (originalUserDir != null) {
      System.setProperty("user.dir", originalUserDir);
    }
  }

  @Test
  void allowPOSTWithoutPassword_alwaysTrue() {
    assertTrue(toadlet.allowPOSTWithoutPassword());
  }

  @Test
  void showSearchBox_whenLibraryPluginLoaded_returnsTrue() {
    PluginManager pluginManager = mock(PluginManager.class);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);
    when(pluginManager.isPluginLoaded("plugins.Library.Main")).thenReturn(true);

    assertTrue(toadlet.showSearchBox());
  }

  @Test
  void showSearchBox_whenPluginNotLoaded_returnsFalse() {
    PluginManager pluginManager = mock(PluginManager.class);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);
    when(pluginManager.isPluginLoaded("plugins.Library.Main")).thenReturn(false);

    assertFalse(toadlet.showSearchBox());
  }

  @Test
  void showSearchBoxLoading_whenNoPluginManager_returnsTrue() {
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(null);

    assertTrue(toadlet.showSearchBoxLoading());
  }

  @Test
  void showSearchBoxLoading_whenLibraryLoading_returnsTrue() {
    PluginManager pluginManager = mock(PluginManager.class);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);
    when(pluginManager.isPluginLoaded("plugins.Library.Main")).thenReturn(false);
    when(pluginManager.isPluginLoadedOrLoadingOrWantLoad("Library")).thenReturn(true);

    assertTrue(toadlet.showSearchBoxLoading());
  }

  @Test
  void showSearchBoxLoading_whenLibraryAlreadyLoaded_returnsFalse() {
    PluginManager pluginManager = mock(PluginManager.class);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);
    when(pluginManager.isPluginLoaded("plugins.Library.Main")).thenReturn(true);

    assertFalse(toadlet.showSearchBoxLoading());
  }

  @Test
  void path_returnsRootSlash() {
    assertEquals(WelcomeToadlet.ROOT_PATH, toadlet.path());
  }

  @Test
  void redirectToRoot_sends302LocationRoot() throws Exception {
    ToadletContext ctx = mock(ToadletContext.class);

    toadlet.redirectToRoot(ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), eq(null), eq(0L));

    MultiValueTable<String, String> headers = headersCaptor.getValue();
    assertEquals("/", headers.getFirst("Location"));
  }

  @Test
  void sendRestartingPageInner_addsMetaRefreshAndContent() {
    ToadletContext ctx = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    HTMLNode outer = new HTMLNode("html");
    HTMLNode head = outer.addChild("head");
    HTMLNode content = outer.addChild("body");
    PageNode pageNode = new PageNode(outer, head, content);

    when(pageMaker.getInfobox(anyString(), anyString(), eq(content), anyString(), eq(true)))
        .thenReturn(new HTMLNode("div"));

    when(pageMaker.getPageNode(eq("Node Restart"), eq(ctx), any(RenderParameters.class)))
        .thenReturn(pageNode);

    HTMLNode result = WelcomeToadlet.sendRestartingPageInner(ctx);

    Optional<HTMLNode> metaNode =
        head.getChildren().stream().filter(child -> "meta".equals(child.getName())).findFirst();
    assertTrue(metaNode.isPresent(), "Meta refresh tag should be added");
    assertEquals("refresh", metaNode.get().getAttribute("http-equiv"));
    assertEquals("20; url=", metaNode.get().getAttribute("content"));

    assertFalse(result.getChildren().isEmpty(), "Page should contain body content");
  }

  @Test
  void maybeDisplayWrapperLogfile_readsLogWhenPresent() throws Exception {
    Path logFile = Path.of(System.getProperty("user.dir"), "wrapper.log");
    boolean existed = Files.exists(logFile);
    byte[] previous = existed ? Files.readAllBytes(logFile) : new byte[0];
    Files.writeString(logFile, "first line\nsecond line\n");

    ToadletContext ctx = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infobox = new HTMLNode("div");

    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), anyString(), anyBoolean()))
        .thenReturn(infobox);

    try {
      WelcomeToadlet.maybeDisplayWrapperLogfile(ctx, contentNode);

      verify(pageMaker)
          .getInfobox(anyString(), anyString(), eq(contentNode), anyString(), eq(true));
      assertFalse(infobox.getChildren().isEmpty(), "Infobox should contain log lines");
    } finally {
      if (existed) {
        Files.write(logFile, previous);
      } else {
        Files.deleteIfExists(logFile);
      }
    }
  }

  @Test
  void maybeDisplayWrapperLogfile_noInteractionWhenMissingFile() {
    Path missingDir = Path.of(originalUserDir).resolve("build/nonexistent");
    System.setProperty("user.dir", missingDir.toString());

    ToadletContext ctx = mock(ToadletContext.class);

    WelcomeToadlet.maybeDisplayWrapperLogfile(ctx, new HTMLNode("div"));

    verifyNoInteractions(ctx);
  }
}
