package network.crypta.clients.http;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LegacyHttpBrowseBoundaryTest {
  private static final String MODULE_NAME = "adapter-http-legacy-browse";
  private static final Path ROOT_HTTP_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "clients", "http");
  private static final Path ADAPTER_HTTP_MAIN_JAVA =
      Path.of(
          "adapter-http-legacy-admin",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "clients",
          "http");
  private static final Path BROWSE_HTTP_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "http");
  private static final Path BROWSE_BUILD_FILE = Path.of(MODULE_NAME, "build.gradle.kts");
  private static final Path ADAPTER_BUILD_FILE =
      Path.of("adapter-http-legacy-admin", "build.gradle.kts");
  private static final Path BROWSE_OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Path ADAPTER_OWNERSHIP_METADATA =
      Path.of("adapter-http-legacy-admin", "gradle", "owned-output-patterns.txt");
  private static final List<String> MOVED_TOP_LEVEL_FILES =
      List.of(
          "BookmarkEditorToadlet.java",
          "BookmarkEditorToadletRuntimePorts.java",
          "BrowserTestToadlet.java",
          "ContentFilterToadlet.java",
          "DecodeToadlet.java",
          "ExternalLinkToadlet.java",
          "FProxyFetchCriteria.java",
          "FProxyFetchInProgress.java",
          "FProxyFetchListener.java",
          "FProxyFetchProgressCounts.java",
          "FProxyFetchResult.java",
          "FProxyFetchSnapshotInfo.java",
          "FProxyFetchTracker.java",
          "FProxyFetchWaiter.java",
          "FProxyRuntimeSupport.java",
          "FProxyToadlet.java",
          "HTTPRangeException.java",
          "ImageCreatorToadlet.java",
          "InsertFreesiteToadlet.java",
          "LegacyFProxyAjaxPushRouteRegistrar.java",
          "LegacyFProxyBrowseRouteRegistrar.java",
          "LocalFileFilterToadlet.java",
          "RssSniffer.java",
          "WelcomeToadlet.java",
          "WelcomeToadletRuntimePorts.java");
  private static final List<String> MOVED_PACKAGE_DIRS =
      List.of("ajaxpush", "bookmark", "complexhtmlnodes", "filter", "updateableelements");

  @Test
  void mainSourceLayout_whenCheckingBrowseOwnership_expectBrowseLeafOwnsPackageTree()
      throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(BROWSE_HTTP_MAIN_JAVA)),
        ":adapter-http-legacy-browse must own network/crypta/clients/http main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_HTTP_MAIN_JAVA)),
        "Root project must not re-own network/crypta/clients/http main sources");

    for (String fileName : MOVED_TOP_LEVEL_FILES) {
      assertTrue(
          Files.exists(repoRoot.resolve(BROWSE_HTTP_MAIN_JAVA.resolve(fileName))),
          ":adapter-http-legacy-browse must own moved browse file " + fileName);
      assertFalse(
          Files.exists(repoRoot.resolve(ADAPTER_HTTP_MAIN_JAVA.resolve(fileName))),
          ":adapter-http-legacy-admin must not own moved browse file " + fileName);
    }

    for (String packageDir : MOVED_PACKAGE_DIRS) {
      assertTrue(
          hasJavaSources(repoRoot.resolve(BROWSE_HTTP_MAIN_JAVA.resolve(packageDir))),
          ":adapter-http-legacy-browse must own moved browse package " + packageDir);
      assertFalse(
          hasJavaSources(repoRoot.resolve(ADAPTER_HTTP_MAIN_JAVA.resolve(packageDir))),
          ":adapter-http-legacy-admin must not own moved browse package " + packageDir);
    }
  }

  @Test
  void buildWiring_whenCheckingBrowseOwnership_expectBrowseLeafDeclaredAndAdminDetached()
      throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String browseBuild = Files.readString(repoRoot.resolve(BROWSE_BUILD_FILE));
    String adminBuild = Files.readString(repoRoot.resolve(ADAPTER_BUILD_FILE));
    Set<String> browseMetadataPatterns =
        readOwnershipPatterns(repoRoot.resolve(BROWSE_OWNERSHIP_METADATA));
    Set<String> adminMetadataPatterns =
        readOwnershipPatterns(repoRoot.resolve(ADAPTER_OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":adapter-http-legacy-browse\""));
    assertTrue(build.contains("project(\":adapter-http-legacy-browse\")"));
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(BROWSE_BUILD_FILE)),
        ":adapter-http-legacy-browse must declare build.gradle.kts");
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(BROWSE_OWNERSHIP_METADATA)),
        ":adapter-http-legacy-browse must declare owned-output-patterns.txt");
    assertTrue(
        browseBuild.contains("project(\":adapter-http-legacy-admin\")"),
        ":adapter-http-legacy-browse must depend on :adapter-http-legacy-admin");
    assertFalse(
        adminBuild.contains("project(\":adapter-http-legacy-browse\")"),
        ":adapter-http-legacy-admin must not depend on :adapter-http-legacy-browse");

    for (String fileName : MOVED_TOP_LEVEL_FILES) {
      String pattern = "network/crypta/clients/http/" + fileName.replace(".java", "*.class");
      assertTrue(
          browseMetadataPatterns.contains(pattern),
          ":adapter-http-legacy-browse must own " + pattern);
      assertFalse(
          adminMetadataPatterns.contains(pattern),
          ":adapter-http-legacy-admin must not own " + pattern);
    }
    for (String packageDir : MOVED_PACKAGE_DIRS) {
      String pattern = "network/crypta/clients/http/" + packageDir + "/**";
      assertTrue(
          browseMetadataPatterns.contains(pattern),
          ":adapter-http-legacy-browse must own " + pattern);
      assertFalse(
          adminMetadataPatterns.contains(pattern),
          ":adapter-http-legacy-admin must not own " + pattern);
    }
  }

  private static boolean isTrackedJavaSource(Path path) {
    String fileName = fileNameOrThrow(path);
    return fileName.endsWith(".java") && !fileName.startsWith("._");
  }

  private static Set<String> readOwnershipPatterns(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .filter(line -> !line.isEmpty())
          .filter(line -> !line.startsWith("#"))
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static boolean hasJavaSources(Path root) throws IOException {
    if (!Files.exists(root)) {
      return false;
    }
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .anyMatch(LegacyHttpBrowseBoundaryTest::isTrackedJavaSource);
    }
  }

  private static String fileNameOrThrow(Path path) {
    Path fileName = path.getFileName();
    if (fileName == null) {
      throw new IllegalArgumentException("Java source path must have a file name: " + path);
    }
    return fileName.toString();
  }

  private static Path repoRoot() throws IOException {
    Path path = Path.of("");
    Path directory = path.toAbsolutePath().normalize();
    while (directory != null && !Files.isRegularFile(directory.resolve("settings.gradle.kts"))) {
      directory = directory.getParent();
    }
    if (directory == null) {
      throw new IllegalStateException(
          "Could not locate the repo root from " + path.toAbsolutePath());
    }
    return directory.toRealPath();
  }
}
