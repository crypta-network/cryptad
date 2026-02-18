package network.crypta.pluginmanager;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // JUnit-style names: method_whenCondition_expectOutcome
class PluginDownLoaderURLTest {

  @TempDir Path tempDir;

  private static final String HTTP_PLUGIN_JAR_URL = "http://example.com/plugins/MyPlugin.jar";
  private static final String HTTP_PLUGIN_DOT_URL_URL = "http://example.com/plugins/MyPlugin.url";
  private static final URI HTTP_BASE_URI = URI.create("http://example.com/base");
  private static final String HEADER_LOCATION = "Location";

  @Test
  void checkSource_whenValidHttpUrl_expectUrlReturned() throws Exception {
    PluginDownLoaderURL downloader = new PluginDownLoaderURL();

    URL url = downloader.checkSource(HTTP_PLUGIN_JAR_URL);

    assertEquals(HTTP_PLUGIN_JAR_URL, url.toString());
  }

  @Test
  void checkSource_whenExistingFilePathWithoutScheme_expectPluginNotFoundWithCause()
      throws Exception {
    PluginDownLoaderURL downloader = new PluginDownLoaderURL();
    Path existingFile = Files.createFile(tempDir.resolve("existing-plugin.jar"));
    String source = existingFile.toString();

    PluginNotFoundException ex =
        assertThrows(PluginNotFoundException.class, () -> downloader.checkSource(source));

    assertEquals("could not build plugin url for " + source, ex.getMessage());
    assertInstanceOf(MalformedURLException.class, ex.getCause());
  }

  @Test
  void checkSource_whenMissingFilePathWithoutScheme_expectFileNotFoundMessage() throws Exception {
    PluginDownLoaderURL downloader = new PluginDownLoaderURL();
    String source = createMissingFilePathThatMatchesRootCheck();

    PluginNotFoundException ex =
        assertThrows(PluginNotFoundException.class, () -> downloader.checkSource(source));

    assertEquals("File not found: " + source, ex.getMessage());
    assertNull(ex.getCause());
  }

  @ParameterizedTest
  @MethodSource("pluginNameCases")
  void getPluginName_whenCalled_expectDerivedName(String source, String expectedName) {
    PluginDownLoaderURL downloader = new PluginDownLoaderURL();

    String name = downloader.getPluginName(source);

    assertEquals(expectedName, name);
  }

  static Stream<Arguments> pluginNameCases() {
    return Stream.of(
        Arguments.of(HTTP_PLUGIN_JAR_URL, "MyPlugin.jar"),
        Arguments.of(HTTP_PLUGIN_DOT_URL_URL, "MyPlugin"),
        Arguments.of("MyPlugin.url", "MyPlugin"),
        Arguments.of(".url", ""),
        Arguments.of("noSlash", "noSlash"),
        Arguments.of("trailingSlash/", ""));
  }

  @Test
  void getSHA1sum_whenCalled_expectNull() {
    PluginDownLoaderURL downloader = new PluginDownLoaderURL();

    assertNull(downloader.getSHA1sum());
  }

  @Test
  void tryCancel_whenCalled_expectNoException() {
    PluginDownLoaderURL downloader = new PluginDownLoaderURL();

    assertDoesNotThrow(downloader::tryCancel);
  }

  @Test
  void getInputStream_whenSourceIsFileUrl_expectReadsBytes() throws Exception {
    PluginDownLoaderURL downloader = new PluginDownLoaderURL();
    byte[] expectedBytes = "plugin-bytes".getBytes(StandardCharsets.UTF_8);

    Path file = tempDir.resolve("plugin.jar");
    Files.write(file, expectedBytes);
    downloader.setSource(file.toUri().toString());

    try (InputStream in = downloader.getInputStream(null)) {
      assertArrayEquals(expectedBytes, in.readAllBytes());
    }
  }

  @Test
  void openConnectionCheckRedirects_whenHttpNotRedirect_expectReturnsStreamAndDisablesRedirects()
      throws Exception {
    HttpURLConnection http = mock(HttpURLConnection.class);
    byte[] expectedBytes = "ok".getBytes(StandardCharsets.UTF_8);
    when(http.getInputStream()).thenReturn(new ByteArrayInputStream(expectedBytes));
    when(http.getResponseCode()).thenReturn(200);

    try (InputStream in = PluginDownLoaderURL.openConnectionCheckRedirects(http)) {
      assertEquals("ok", new String(in.readAllBytes(), StandardCharsets.UTF_8));
    }

    verify(http).setInstanceFollowRedirects(false);
    verify(http).getResponseCode();
    verify(http, never()).disconnect();
  }

  @Test
  void openConnectionCheckRedirects_whenRealHttpNotRedirect_expectStreamRemainsReadable()
      throws Exception {
    byte[] expectedBytes = "ok".getBytes(StandardCharsets.UTF_8);

    HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/plugin.jar",
        exchange -> {
          exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
          exchange.sendResponseHeaders(200, expectedBytes.length);
          exchange.getResponseBody().write(expectedBytes);
          exchange.close();
        });
    server.start();

    try {
      URL url =
          URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/plugin.jar").toURL();
      try (InputStream in =
          PluginDownLoaderURL.openConnectionCheckRedirects(url.openConnection())) {
        assertArrayEquals(expectedBytes, in.readAllBytes());
      }
    } finally {
      server.stop(0);
    }
  }

  @Test
  void openConnectionCheckRedirects_whenHttpRedirectWithNullLocation_expectSecurityException()
      throws Exception {
    HttpURLConnection http = mock(HttpURLConnection.class);
    when(http.getResponseCode()).thenReturn(302);
    when(http.getURL()).thenReturn(URL.of(HTTP_BASE_URI, null));
    when(http.getHeaderField(HEADER_LOCATION)).thenReturn(null);

    try (InputStream body = new ByteArrayInputStream(new byte[] {1})) {
      when(http.getInputStream()).thenReturn(body);

      //noinspection resource
      assertThrows(
          SecurityException.class, () -> PluginDownLoaderURL.openConnectionCheckRedirects(http));
    }

    verify(http).disconnect();
  }

  @Test
  void openConnectionCheckRedirects_whenHttpRedirectToDisallowedProtocol_expectSecurityException()
      throws Exception {
    HttpURLConnection http = mock(HttpURLConnection.class);
    when(http.getResponseCode()).thenReturn(302);
    when(http.getURL()).thenReturn(URL.of(HTTP_BASE_URI, null));
    when(http.getHeaderField(HEADER_LOCATION)).thenReturn("file:/tmp/not-allowed");

    try (InputStream body = new ByteArrayInputStream(new byte[] {1})) {
      when(http.getInputStream()).thenReturn(body);

      //noinspection resource
      assertThrows(
          SecurityException.class, () -> PluginDownLoaderURL.openConnectionCheckRedirects(http));
    }

    verify(http).disconnect();
  }

  @Test
  void
      openConnectionCheckRedirects_whenHttpRedirectWithMalformedLocation_expectMalformedURLException()
          throws Exception {
    HttpURLConnection http = mock(HttpURLConnection.class);
    when(http.getResponseCode()).thenReturn(302);
    when(http.getURL()).thenReturn(URL.of(HTTP_BASE_URI, null));
    when(http.getHeaderField(HEADER_LOCATION)).thenReturn("http://example.com/space here");

    MalformedURLException ex;
    try (InputStream body = new ByteArrayInputStream(new byte[] {1})) {
      when(http.getInputStream()).thenReturn(body);

      //noinspection resource
      ex =
          assertThrows(
              MalformedURLException.class,
              () -> PluginDownLoaderURL.openConnectionCheckRedirects(http));
    }

    assertNotNull(ex.getMessage());
    assertFalse(ex.getMessage().isBlank());
  }

  private String createMissingFilePathThatMatchesRootCheck() throws IOException {
    String source = tempDir.resolve("missing-plugin.jar").toString();

    File[] roots = File.listRoots();
    for (File root : roots) {
      String rootName = root.getName();
      if (!rootName.isEmpty()) {
        source = rootName + "PluginDownLoaderURLTest-missing-plugin.jar";
        break;
      }
    }

    // Ensure we really point at something missing, deterministically.
    int attempt = 0;
    String base = source;
    while (new File(source).exists() && attempt < 10) {
      attempt++;
      source = base + "-" + attempt;
    }
    if (new File(source).exists()) {
      throw new IOException("Unable to find a missing file path for test setup: " + source);
    }
    return source;
  }
}
