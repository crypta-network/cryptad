package network.crypta.clients.fcp;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.support.api.ManifestElement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
class ClientPutDirManifestSupportTest {
  @TempDir Path tempDir;

  @Test
  void buildDiskManifest_whenDirectoryContainsNestedFiles_returnsManifestTree() throws Exception {
    Files.writeString(tempDir.resolve("root.txt"), "root");
    Path nestedDir = Files.createDirectory(tempDir.resolve("subdir"));
    Files.writeString(nestedDir.resolve("child.txt"), "child");

    Map<String, Object> manifest =
        ClientPutDirManifestSupport.buildDiskManifest(tempDir.toFile(), false, false);

    Object rootValue = manifest.get("root.txt");
    assertInstanceOf(ManifestElement.class, rootValue);
    ManifestElement rootElement = (ManifestElement) rootValue;
    assertEquals("root.txt", rootElement.getName());
    assertEquals("root.txt", rootElement.fullName);

    Object subdirValue = manifest.get("subdir");
    assertInstanceOf(Map.class, subdirValue);
    @SuppressWarnings("unchecked")
    Map<String, Object> subdir = (Map<String, Object>) subdirValue;
    ManifestElement nestedElement = (ManifestElement) subdir.get("child.txt");
    assertNotNull(nestedElement);
    assertEquals("child.txt", nestedElement.getName());
    assertEquals("subdir/child.txt", nestedElement.fullName);
  }

  @Test
  void freeManifest_whenManifestContainsNestedElements_freesAllEntries() {
    ManifestElement rootElement = mock(ManifestElement.class);
    ManifestElement nestedElement = mock(ManifestElement.class);
    Map<String, Object> nested = new LinkedHashMap<>();
    nested.put("child", nestedElement);
    Map<String, Object> manifest = new HashMap<>();
    manifest.put("root", rootElement);
    manifest.put("subdir", nested);

    ClientPutDirManifestSupport.freeManifest(manifest);

    verify(rootElement).freeData();
    verify(nestedElement).freeData();
  }

  @Test
  void buildDiskManifest_whenHiddenFilesExcluded_skipsHiddenEntries() throws Exception {
    Files.writeString(tempDir.resolve(".hidden.txt"), "secret");
    Files.writeString(tempDir.resolve("visible.txt"), "visible");

    Map<String, Object> manifest =
        ClientPutDirManifestSupport.buildDiskManifest(tempDir.toFile(), false, false);

    assertEquals(1, manifest.size());
    assertNotNull(manifest.get("visible.txt"));
    assertNull(manifest.get(".hidden.txt"));
  }

  @Test
  void buildDiskManifest_whenHiddenFilesIncluded_keepsHiddenEntries() throws Exception {
    Files.writeString(tempDir.resolve(".hidden.txt"), "secret");

    Map<String, Object> manifest =
        ClientPutDirManifestSupport.buildDiskManifest(tempDir.toFile(), false, true);

    Object hiddenValue = manifest.get(".hidden.txt");
    assertInstanceOf(ManifestElement.class, hiddenValue);
    ManifestElement hiddenElement = (ManifestElement) hiddenValue;
    assertEquals(".hidden.txt", hiddenElement.getName());
    assertEquals(".hidden.txt", hiddenElement.fullName);
  }

  @Test
  void buildDiskManifest_whenPathIsNotDirectory_throwsIllegalArgumentException() throws Exception {
    Path file = Files.writeString(tempDir.resolve("plain.txt"), "data");
    File nonDirectory = file.toFile();

    assertThrows(
        IllegalArgumentException.class,
        () -> ClientPutDirManifestSupport.buildDiskManifest(nonDirectory, false, false));
  }
}
