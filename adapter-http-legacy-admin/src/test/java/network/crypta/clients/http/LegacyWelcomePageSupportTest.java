package network.crypta.clients.http;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class LegacyWelcomePageSupportTest {

  private String originalUserDir;

  @BeforeEach
  void setUp() {
    originalUserDir = System.getProperty("user.dir");
  }

  @AfterEach
  void tearDown() {
    System.setProperty("user.dir", originalUserDir);
  }

  @Test
  void sendRestartingPageInner_whenCalled_addsMetaRefreshAndContent() {
    ToadletContext ctx = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    HTMLNode outerNode = new HTMLNode("html");
    HTMLNode headNode = outerNode.addChild("head");
    HTMLNode contentNode = outerNode.addChild("body");
    PageNode pageNode = new PageNode(outerNode, headNode, contentNode);

    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), anyString(), eq(true)))
        .thenReturn(new HTMLNode("div"));
    when(pageMaker.getPageNode(eq("Node Restart"), eq(ctx), any(RenderParameters.class)))
        .thenReturn(pageNode);

    HTMLNode result = LegacyWelcomePageSupport.sendRestartingPageInner(ctx);

    Optional<HTMLNode> metaNode =
        headNode.getChildren().stream().filter(child -> "meta".equals(child.getName())).findFirst();
    assertTrue(metaNode.isPresent());
    assertEquals("refresh", metaNode.orElseThrow().getAttribute("http-equiv"));
    assertEquals("20; url=", metaNode.orElseThrow().getAttribute("content"));
    verify(pageMaker)
        .getInfobox(
            eq("infobox-information"),
            anyString(),
            eq(contentNode),
            eq("shutdown-progressing"),
            eq(true));
    assertFalse(result.getChildren().isEmpty());
  }

  @Test
  void maybeDisplayWrapperLogfile_whenLogPresent_readsTailIntoInfobox() throws Exception {
    Path logFile = Path.of(originalUserDir, "wrapper.log");
    boolean existed = Files.exists(logFile);
    byte[] previous = existed ? Files.readAllBytes(logFile) : new byte[0];
    Files.writeString(logFile, "first line\nsecond line\n");

    ToadletContext ctx = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infobox = new HTMLNode("div");

    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), anyString(), eq(true)))
        .thenReturn(infobox);

    try {
      LegacyWelcomePageSupport.maybeDisplayWrapperLogfile(ctx, contentNode);

      verify(pageMaker)
          .getInfobox(anyString(), anyString(), eq(contentNode), anyString(), eq(true));
      assertTrue(infobox.generate().contains("first line"));
      assertTrue(infobox.generate().contains("second line"));
    } finally {
      if (existed) {
        Files.write(logFile, previous);
      } else {
        Files.deleteIfExists(logFile);
      }
    }
  }

  @Test
  void maybeDisplayWrapperLogfile_whenFileMissing_skipsPageMaker() {
    Path missingDir = Path.of(originalUserDir).resolve("build/nonexistent");
    System.setProperty("user.dir", missingDir.toString());
    ToadletContext ctx = mock(ToadletContext.class);

    LegacyWelcomePageSupport.maybeDisplayWrapperLogfile(ctx, new HTMLNode("div"));

    verifyNoInteractions(ctx);
  }
}
