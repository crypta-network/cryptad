package network.crypta.clients.http;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LocalFileFilterToadletTest {

  @Mock private TransferAccessPort transferAccess;

  private LocalFileFilterToadlet toadlet;

  @BeforeEach
  void setUp() {
    lenient().doCallRealMethod().when(transferAccess).defaultUploadDir();
    toadlet = new LocalFileFilterToadlet(transferAccess);
  }

  @Test
  void path_whenCalled_returnsFilterBrowsePath() {
    String result = toadlet.path();

    assertEquals(LocalFileFilterToadlet.BROWSE_PATH, result);
  }

  @Test
  void postTo_whenCalled_returnsContentFilterPath() {
    String result = toadlet.postTo();

    assertEquals(ContentFilterToadlet.CONTENT_FILTER_PATH, result);
  }

  @ParameterizedTest
  @CsvSource({"/tmp/upload,true", "/var/forbidden,false"})
  void allowedDir_whenDelegatesToCore_returnsCoreDecision(String rawPath, boolean allowed) {
    File path = new File(rawPath);
    when(transferAccess.allowUploadFrom(path)).thenReturn(allowed);

    boolean result = toadlet.allowedDir(path);

    assertEquals(allowed, result);
    verify(transferAccess).allowUploadFrom(path);
  }

  @Test
  void createSelectFileButton_whenInvoked_addsExpectedInputs() {
    HTMLNode parent = new HTMLNode("div");
    HTMLNode persistence = new HTMLNode("span");
    String absolutePath = "/some/file.txt";

    toadlet.createSelectFileButton(parent, absolutePath, persistence);

    List<HTMLNode> children = parent.getChildren();
    assertEquals(3, children.size());

    HTMLNode submitInput = children.getFirst();
    assertEquals("input", submitInput.getName());
    assertEquals("submit", submitInput.getAttribute("type"));
    assertEquals(LocalFileBrowserToadlet.SELECT_FILE, submitInput.getAttribute("name"));
    assertEquals(ContentFilterToadlet.l10n("selectFile"), submitInput.getAttribute("value"));

    HTMLNode hiddenInput = children.get(1);
    assertEquals("input", hiddenInput.getName());
    assertEquals("hidden", hiddenInput.getAttribute("type"));
    assertEquals("filename", hiddenInput.getAttribute("name"));
    assertEquals(absolutePath, hiddenInput.getAttribute("value"));

    HTMLNode persistenceChild = children.get(2);
    assertSame(persistence, persistenceChild);
  }

  @Test
  void createSelectDirectoryButton_whenInvoked_doesNothing() {
    HTMLNode parent = new HTMLNode("div");
    HTMLNode persistence = new HTMLNode("span");

    toadlet.createSelectDirectoryButton(parent, "/any", persistence);

    assertTrue(parent.getChildren().isEmpty());
  }

  @Test
  void persistenceFields_whenProvidedMap_filtersExpectedEntries() {
    Map<String, String> input = new HashMap<>();
    input.put("filter-operation", "sanitize");
    input.put("result-handling", null);
    input.put("mime-type", "text/plain");
    input.put("unrelated", "ignored");

    Map<String, String> result = toadlet.persistenceFields(input);

    Map<String, String> expected = new HashMap<>();
    expected.put("filter-operation", "sanitize");
    expected.put("mime-type", "text/plain");

    assertEquals(expected, result);
  }

  @Test
  void startingDir_whenAllowedDirsEmpty_returnsUserHome() {
    when(transferAccess.allowedUploadDirs()).thenReturn(new File[0]);

    String result = toadlet.startingDir();

    assertEquals(System.getProperty("user.home"), result);
  }

  @Test
  void startingDir_whenAllowedDirsConfigured_returnsFirstPath() {
    File first = new File("/path/one");
    when(transferAccess.allowedUploadDirs()).thenReturn(new File[] {first, new File("/path/two")});

    String result = toadlet.startingDir();

    assertEquals(first.getAbsolutePath(), result);
  }

  @Test
  void startingDir_whenUploadDirsAllowAll_returnsUserHome() {
    when(transferAccess.allowedUploadDirs()).thenReturn(new File[] {new File("all")});

    String result = toadlet.startingDir();

    assertEquals(System.getProperty("user.home"), result);
  }
}
