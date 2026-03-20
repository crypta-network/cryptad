package network.crypta.clients.http;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LocalDirectoryConfigToadletTest {

  @Mock private TransferAccessPort transferAccess;
  @Mock private HighLevelSimpleClient highLevelSimpleClient;

  private static final String POST_TO = "/config";

  private LocalDirectoryConfigToadlet createToadlet() {
    return new LocalDirectoryConfigToadlet(transferAccess, highLevelSimpleClient, POST_TO);
  }

  @Test
  void path_whenCalled_returnsBasePathPlusPostTo() {
    LocalDirectoryConfigToadlet toadlet = createToadlet();

    String result = toadlet.path();

    assertEquals(LocalDirectoryToadlet.basePath() + POST_TO, result);
  }

  @Test
  void startingDir_whenCalled_returnsUserHomeProperty() {
    LocalDirectoryConfigToadlet toadlet = createToadlet();

    String result = toadlet.startingDir();

    assertEquals(System.getProperty("user.home"), result);
  }

  @Test
  void allowedDir_whenCalledWithAnyFile_returnsTrue() {
    LocalDirectoryConfigToadlet toadlet = createToadlet();

    boolean result = toadlet.allowedDir(new File("/not/relevant"));

    assertTrue(result);
  }

  @Test
  void createSelectDirectoryButton_whenCalled_addsSubmitHiddenAndPersistenceNodes() {
    LocalDirectoryConfigToadlet toadlet = createToadlet();
    HTMLNode formNode = new HTMLNode("form");
    HTMLNode persistence = new HTMLNode("div", "id", "persist");
    String path = "/tmp/dir";

    toadlet.createSelectDirectoryButton(formNode, path, persistence);

    List<HTMLNode> children = formNode.getChildren();
    assertEquals(3, children.size());

    HTMLNode submit = children.getFirst();
    assertEquals("input", submit.getName());
    assertEquals("submit", submit.getAttribute("type"));
    assertEquals(LocalFileBrowserToadlet.SELECT_DIR, submit.getAttribute("name"));
    assertEquals(
        NodeL10n.getBase().getString("ConfigToadlet.selectDirectory"),
        submit.getAttribute("value"));

    HTMLNode hidden = children.get(1);
    assertEquals("input", hidden.getName());
    assertEquals("hidden", hidden.getAttribute("type"));
    assertEquals(toadlet.filenameField(), hidden.getAttribute("name"));
    assertEquals(path, hidden.getAttribute("value"));

    assertSame(persistence, children.get(2));
  }

  @Test
  void persistenceFields_whenCalled_removesPathAndFormPassword() {
    LocalDirectoryConfigToadlet toadlet = createToadlet();
    Map<String, String> params = new HashMap<>();
    params.put("path", "/tmp");
    params.put("formPassword", "secret");
    params.put("keep", "value");

    Map<String, String> result = toadlet.persistenceFields(params);

    assertSame(params, result);
    assertFalse(result.containsKey("path"));
    assertFalse(result.containsKey("formPassword"));
    assertEquals("value", result.get("keep"));
  }
}
