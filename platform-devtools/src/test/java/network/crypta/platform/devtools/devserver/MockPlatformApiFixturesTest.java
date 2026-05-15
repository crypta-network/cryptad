package network.crypta.platform.devtools.devserver;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.platform.appdist.AppDistributionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class MockPlatformApiFixturesTest {
  @TempDir private Path tempDir;

  @Test
  void appsCurrent_whenFixtureMissing_expectDefaultWithEscapedAppPlaceholders() throws Exception {
    Files.createDirectories(tempDir);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Name \"One\"", "0.1\\beta");

    String json = fixtures.appsCurrent();

    assertTrue(json.contains("\"appId\":\"sample-app\""));
    assertTrue(json.contains("\"name\":\"Name \\\"One\\\"\""));
    assertTrue(json.contains("\"version\":\"0.1\\\\beta\""));
  }

  @Test
  void node_whenFixtureContainsAbsoluteUnixPath_expectRejected() throws Exception {
    Files.writeString(
        tempDir.resolve("node.json"),
        "{\"path\":\"/Users/alice/private/node.json\"}",
        StandardCharsets.UTF_8);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Sample App", "0.1.0");

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, fixtures::node);

    assertTrue(exception.getMessage().contains("fixture output contains an absolute local path"));
  }

  @Test
  void queue_whenFixtureDirectoryIsSymlink_expectRejected() throws Exception {
    Path realFixtureDir = tempDir.resolve("fixtures");
    Path linkedFixtureDir = tempDir.resolve("linked-fixtures");
    Files.createDirectories(realFixtureDir);
    try {
      Files.createSymbolicLink(linkedFixtureDir, realFixtureDir);
    } catch (UnsupportedOperationException | SecurityException exception) {
      org.junit.jupiter.api.Assumptions.assumeTrue(
          false, "symlink creation unavailable: " + exception.getMessage());
    }
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(linkedFixtureDir, "sample-app", "Sample App", "0.1.0");

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, fixtures::queue);

    assertTrue(exception.getMessage().contains("fixture directory must be a real directory"));
    assertFalse(Files.exists(realFixtureDir.resolve("queue.json")));
  }
}
