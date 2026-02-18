package network.crypta.pluginmanager;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import network.crypta.pluginmanager.PluginManager.PluginProgress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // JUnit-style names: method_whenCondition_expectOutcome
class PluginDownLoaderFileTest {

  @TempDir Path tempDir;

  private static final String PLUGIN_JAR_NAME = "MyPlugin.jar";

  @Test
  void checkSource_whenValidPath_expectFileWithMatchingPath() {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();
    String source = tempDir.resolve("plugin.jar").toString();

    File file = downloader.checkSource(source);

    assertNotNull(file);
    assertEquals(new File(source).getPath(), file.getPath());
  }

  @Test
  void checkSource_whenNullSource_expectNullPointerException() {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();

    assertThrows(NullPointerException.class, () -> downloader.checkSource(null));
  }

  @ParameterizedTest
  @MethodSource("pluginNameCases")
  void getPluginName_whenCalled_expectDerivedName(String source, String expectedName)
      throws Exception {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();

    String name = downloader.getPluginName(source);

    assertEquals(expectedName, name);
  }

  static Stream<Arguments> pluginNameCases() {
    return Stream.of(
        Arguments.of("/plugins/" + PLUGIN_JAR_NAME, PLUGIN_JAR_NAME),
        Arguments.of("C:\\\\plugins\\\\" + PLUGIN_JAR_NAME, PLUGIN_JAR_NAME),
        Arguments.of(PLUGIN_JAR_NAME, PLUGIN_JAR_NAME),
        Arguments.of("trailingSlash/", ""),
        Arguments.of("trailingBackslash\\\\", ""));
  }

  @Test
  void getPluginName_whenNullSource_expectNullPointerException() {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();

    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> downloader.getPluginName(null));
  }

  @Test
  void setSource_whenCalled_expectStoredSourceAndReturnedName() throws Exception {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();
    String source = tempDir.resolve("stored-plugin.jar").toString();

    String name = downloader.setSource(source);

    assertEquals("stored-plugin.jar", name);
    assertEquals(new File(source).getPath(), downloader.getSource().getPath());
  }

  @Test
  void getInputStream_whenSourceNotSet_expectNullPointerException() {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();
    PluginProgress progress = mock(PluginProgress.class);

    assertThrows(NullPointerException.class, () -> downloader.getInputStream(progress));
  }

  @Test
  void getInputStream_whenSourceMissing_expectFileNotFoundException() throws Exception {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();
    Path missingFile = tempDir.resolve("missing-plugin.jar");
    downloader.setSource(missingFile.toString());
    PluginProgress progress = mock(PluginProgress.class);

    assertThrows(FileNotFoundException.class, () -> downloader.getInputStream(progress));
  }

  @Test
  void getInputStream_whenSourceExists_expectStreamReadsBytes() throws Exception {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();
    byte[] payload = new byte[] {0x01, 0x02, 0x03, 0x04};
    Path pluginFile = tempDir.resolve("plugin.jar");
    Files.write(pluginFile, payload);
    downloader.setSource(pluginFile.toString());
    PluginProgress progress = mock(PluginProgress.class);

    byte[] read;
    try (InputStream in = downloader.getInputStream(progress)) {
      read = in.readAllBytes();
    }

    assertArrayEquals(payload, read);
  }

  @Test
  void getSHA1sum_whenCalled_expectNull() {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();

    assertNull(downloader.getSHA1sum());
  }

  @Test
  void tryCancel_whenCalled_expectNoException() {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();

    assertDoesNotThrow(downloader::tryCancel);
  }

  @Test
  void isCachingProhibited_whenCalled_expectTrue() {
    PluginDownLoaderFile downloader = new PluginDownLoaderFile();

    assertTrue(downloader.isCachingProhibited());
  }
}
