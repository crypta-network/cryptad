package network.crypta.clients.http;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LocalDownloadDirectoryToadletTest {

  @Mock NodeClientCore core;
  @Mock HighLevelSimpleClient client;

  private LocalDownloadDirectoryToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new LocalDownloadDirectoryToadlet(core, client, "/post");
  }

  @ParameterizedTest
  @MethodSource("startingDirScenarios")
  void startingDir_selectsExpectedDefault(File[] allowedDirs, File downloadsDir, String expected) {
    when(core.getAllowedDownloadDirs()).thenReturn(allowedDirs);
    if (allowedDirs.length == 0
        || (allowedDirs.length == 1 && "all".equals(allowedDirs[0].toString()))) {
      when(core.getDownloadsDir()).thenReturn(downloadsDir);
    }

    String result = toadlet.startingDir();

    assertEquals(expected, result);
  }

  private static Stream<Arguments> startingDirScenarios() {
    return Stream.of(
        Arguments.of(
            new File[] {new File("all")},
            new File("/downloads"),
            new File("/downloads").getAbsolutePath()),
        Arguments.of(
            new File[] {}, new File("/downloads"), new File("/downloads").getAbsolutePath()),
        Arguments.of(
            new File[] {new File("/allowed/path"), new File("/other")},
            new File("/downloads"),
            new File("/allowed/path").getAbsolutePath()));
  }

  @Test
  void allowedDir_delegatesToCore() {
    File target = new File("/tmp/downloads");
    when(core.allowDownloadTo(target)).thenReturn(true);

    boolean allowed = toadlet.allowedDir(target);

    assertTrue(allowed);
    verify(core).allowDownloadTo(target);
  }

  @Test
  void filenameField_returnsPath() {
    assertEquals("path", toadlet.filenameField());
  }

  @Test
  void createSelectDirectoryButton_buildsSubmitAndHiddenInputs() {
    HTMLNode form = new HTMLNode("form");
    HTMLNode persist = new HTMLNode("span");
    String chosenPath = "/destination";

    toadlet.createSelectDirectoryButton(form, chosenPath, persist);

    assertEquals(3, form.getChildren().size());

    HTMLNode submit = form.getChildren().getFirst();
    assertEquals("submit", submit.getAttribute("type"));
    assertEquals(LocalFileBrowserToadlet.SELECT_DIR, submit.getAttribute("name"));
    assertEquals(
        NodeL10n.getBase().getString("QueueToadlet.download"), submit.getAttribute("value"));

    HTMLNode hidden = form.getChildren().get(1);
    assertEquals("hidden", hidden.getAttribute("type"));
    assertEquals("path", hidden.getAttribute("name"));
    assertEquals(chosenPath, hidden.getAttribute("value"));

    assertSame(persist, form.getChildren().get(2));
  }

  @Test
  void persistenceFields_whenBulkDownloads_presentSetsInsertAndTarget() {
    Map<String, String> requestFields = new HashMap<>();
    requestFields.put("bulkDownloads", "bulk");
    requestFields.put("filterData", "filters");

    Map<String, String> result = toadlet.persistenceFields(requestFields);

    assertEquals("bulk", result.get("bulkDownloads"));
    assertEquals("1", result.get("insert"));
    assertEquals("disk", result.get("target"));
    assertEquals("filters", result.get("filterData"));
    assertEquals(4, result.size());
  }

  @Test
  void persistenceFields_whenKey_presentSetsDownloadAndReturnType() {
    Map<String, String> requestFields = new HashMap<>();
    requestFields.put("key", "CHK@foo");
    requestFields.put("filterData", "filters");

    Map<String, String> result = toadlet.persistenceFields(requestFields);

    assertEquals("CHK@foo", result.get("key"));
    assertEquals("1", result.get("download"));
    assertEquals("disk", result.get("return-type"));
    assertEquals("filters", result.get("filterData"));
    assertEquals(4, result.size());
  }

  @Test
  void persistenceFields_whenOnlyFilterData_presentPreservesIt() {
    Map<String, String> requestFields = new HashMap<>();
    requestFields.put("filterData", "keepme");

    Map<String, String> result = toadlet.persistenceFields(requestFields);

    assertEquals(1, result.size());
    assertEquals("keepme", result.get("filterData"));
  }

  @Test
  void persistenceFields_whenBulkAndKey_prefersBulkBranch() {
    Map<String, String> requestFields = new HashMap<>();
    requestFields.put("bulkDownloads", "bulk");
    requestFields.put("key", "CHK@foo");

    Map<String, String> result = toadlet.persistenceFields(requestFields);

    assertTrue(result.containsKey("bulkDownloads"));
    assertTrue(result.containsKey("insert"));
    assertTrue(result.containsKey("target"));
    assertFalse(result.containsKey("download"));
    assertFalse(result.containsKey("return-type"));
  }
}
