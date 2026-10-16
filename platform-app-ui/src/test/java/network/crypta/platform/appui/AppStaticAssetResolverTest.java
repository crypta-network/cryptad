package network.crypta.platform.appui;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.abort;

@SuppressWarnings("java:S100")
class AppStaticAssetResolverTest {
  @TempDir private Path tempDir;

  private final AppStaticAssetResolver resolver = new AppStaticAssetResolver();

  @Test
  void resolve_whenAncestorIsSymlink_expectBundleAsset() throws Exception {
    Path parent = Files.createDirectory(tempDir.resolve("installed"));
    Path root = Files.createDirectory(parent.resolve("demo-app"));
    Files.writeString(root.resolve("index.html"), "<html></html>");
    Path linkedParent = createSymlink(tempDir.resolve("linked-installed"), parent);

    AppStaticAsset asset =
        resolver.resolve(linkedParent.resolve("demo-app"), "index.html").orElseThrow();

    assertEquals("index.html", asset.relativePath());
    assertEquals("<html></html>", Files.readString(asset.path()));
  }

  @Test
  void resolve_whenBundleRootIsSymlink_expectBadRequest() throws Exception {
    Path root = Files.createDirectory(tempDir.resolve("demo-app"));
    Files.writeString(root.resolve("index.html"), "<html></html>");
    Path linkedRoot = createSymlink(tempDir.resolve("linked-app"), root);

    AppStaticAssetException exception =
        assertThrows(
            AppStaticAssetException.class, () -> resolver.resolve(linkedRoot, "index.html"));

    assertEquals(400, exception.statusCode());
  }

  @Test
  void resolve_whenAssetDirectoryIsSymlinkWithinBundle_expectBadRequest() throws Exception {
    Path root = Files.createDirectory(tempDir.resolve("demo-app"));
    Path assets = Files.createDirectory(root.resolve("assets"));
    Files.writeString(assets.resolve("index.html"), "<html></html>");
    createSymlink(root.resolve("static"), assets);

    AppStaticAssetException exception =
        assertThrows(
            AppStaticAssetException.class, () -> resolver.resolve(root, "static/index.html"));

    assertEquals(400, exception.statusCode());
  }

  private static Path createSymlink(Path link, Path target) throws IOException {
    try {
      return Files.createSymbolicLink(link, target);
    } catch (UnsupportedOperationException | IOException exception) {
      return abort("symbolic links are unavailable: " + exception.getMessage());
    }
  }
}
