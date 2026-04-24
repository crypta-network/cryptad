package network.crypta.platform.sdk.js;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptaPlatformSdkBoundaryTest {
  private static final String MODULE_NAME = "platform-sdk-js";
  private static final Path ROOT_SDK_RESOURCE_PACKAGE =
      Path.of("src", "main", "resources", "network", "crypta", "platform", "sdk", "js");
  private static final Path SDK_RESOURCE_PACKAGE =
      Path.of(MODULE_NAME)
          .resolve(
              Path.of("src", "main", "resources", "network", "crypta", "platform", "sdk", "js"));
  private static final Path SDK_SCRIPT = SDK_RESOURCE_PACKAGE.resolve("crypta-platform.js");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");

  @Test
  void mainResourceLayout_whenCheckingSdkOwnership_expectLeafOwnsBrowserSdk() throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isRegularFile(repoRoot.resolve(SDK_SCRIPT)),
        ":platform-sdk-js must own the browser SDK resource.");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_SDK_RESOURCE_PACKAGE)),
        "Root project must not own network/crypta/platform/sdk/js resources.");
  }

  @Test
  void buildWiring_whenCheckingLeafMetadata_expectOwnedOutputPatternDeclared() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String metadata = Files.readString(repoRoot.resolve(OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":platform-sdk-js\""));
    assertTrue(build.contains("project(\":platform-sdk-js\")"));
    assertTrue(metadata.contains("network/crypta/platform/sdk/js/**"));
  }

  private static Path repoRoot() throws IOException {
    Path path = Path.of("");
    Path directory = path.toAbsolutePath().normalize();
    while (directory != null && !Files.isRegularFile(directory.resolve("settings.gradle.kts"))) {
      directory = directory.getParent();
    }
    assertNotNull(directory, "Could not locate the repo root from " + path.toAbsolutePath());
    return directory.toRealPath();
  }
}
