package network.crypta.platform.designsystem;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class DesignSystemAssetsTest {
  @TempDir private Path tempDir;

  @Test
  void list_whenCalled_expectDeterministicCanonicalAssets() throws Exception {
    List<DesignSystemAsset> assets = DesignSystemAssets.list();

    assertEquals(
        List.of("crypta-ui-tokens.css", "crypta-ui.css", "crypta-ui-components.js"),
        assets.stream().map(DesignSystemAsset::name).toList());
    assertEquals(
        List.of(
            "static/crypta-ui/crypta-ui-tokens.css",
            "static/crypta-ui/crypta-ui.css",
            "static/crypta-ui/crypta-ui-components.js"),
        assets.stream().map(DesignSystemAsset::bundlePath).toList());
    for (DesignSystemAsset asset : assets) {
      assertFalse(asset.bundlePath().contains(".."));
      assertFalse(asset.bundlePath().startsWith("/"));
      assertTrue(asset.sizeBytes() > 0);
      assertEquals(64, asset.sha256Hex().length());
      assertEquals(asset.sha256Hex(), sha256Hex(asset.resourcePath()));
    }
  }

  @Test
  void copyIntoBundle_whenDestinationIsRealDirectory_expectAssetsCopied() throws Exception {
    Path bundleRoot = tempDir.resolve("bundle");
    Files.createDirectory(bundleRoot);

    List<DesignSystemAsset> copied = DesignSystemAssets.copyIntoBundle(bundleRoot);

    assertEquals(DesignSystemAssets.list(), copied);
    for (DesignSystemAsset asset : copied) {
      Path target = bundleRoot.resolve(asset.bundlePath());
      assertTrue(Files.isRegularFile(target));
      assertEquals(asset.sizeBytes(), Files.size(target));
      assertEquals(asset.sha256Hex(), sha256Hex(Files.readAllBytes(target)));
    }
    String css =
        Files.readString(
            bundleRoot.resolve("static/crypta-ui/crypta-ui.css"), StandardCharsets.UTF_8);
    assertTrue(css.contains(".cr-app"));
    assertTrue(css.contains(".cr-button--primary"));
  }

  @Test
  void copyIntoBundle_whenCanonicalFileAlreadyExists_expectCanonicalBytesReplaceIt()
      throws Exception {
    Path bundleRoot = tempDir.resolve("bundle");
    Path stylesheet = bundleRoot.resolve("static/crypta-ui/crypta-ui.css");
    Files.createDirectories(stylesheet.getParent());
    Files.writeString(stylesheet, "modified", StandardCharsets.UTF_8);

    List<DesignSystemAsset> copied = DesignSystemAssets.copyIntoBundle(bundleRoot);

    DesignSystemAsset cssAsset =
        copied.stream()
            .filter(asset -> asset.name().equals("crypta-ui.css"))
            .findFirst()
            .orElseThrow();
    String css = Files.readString(stylesheet, StandardCharsets.UTF_8);
    assertEquals(cssAsset.sizeBytes(), Files.size(stylesheet));
    assertEquals(cssAsset.sha256Hex(), sha256Hex(Files.readAllBytes(stylesheet)));
    assertTrue(css.contains(".cr-app"));
    assertFalse(css.contains("modified"));
  }

  @Test
  void copyIntoBundle_whenRootIsSymlink_expectFailure() throws Exception {
    Path target = tempDir.resolve("target");
    Path symlink = tempDir.resolve("bundle-link");
    Files.createDirectory(target);
    Assumptions.assumeTrue(canCreateSymlink(symlink, target));

    IOException exception =
        assertThrows(IOException.class, () -> DesignSystemAssets.copyIntoBundle(symlink));

    assertTrue(exception.getMessage().contains("bundle root must not be a symbolic link"));
  }

  @Test
  void copyIntoBundle_whenAssetDestinationIsSymlink_expectFailure() throws Exception {
    Path bundleRoot = tempDir.resolve("bundle");
    Path external = tempDir.resolve("external.css");
    Files.createDirectories(bundleRoot.resolve("static/crypta-ui"));
    Files.writeString(external, "external", StandardCharsets.UTF_8);
    Path symlink = bundleRoot.resolve("static/crypta-ui/crypta-ui.css");
    Assumptions.assumeTrue(canCreateSymlink(symlink, external));

    IOException exception =
        assertThrows(IOException.class, () -> DesignSystemAssets.copyIntoBundle(bundleRoot));

    assertTrue(exception.getMessage().contains("must not be a symbolic link"));
    assertEquals("external", Files.readString(external, StandardCharsets.UTF_8));
  }

  @Test
  void copyIntoBundle_whenStaticDirectoryIsSymlink_expectFailure() throws Exception {
    Path bundleRoot = tempDir.resolve("bundle");
    Path externalStatic = tempDir.resolve("external-static");
    Files.createDirectory(bundleRoot);
    Files.createDirectory(externalStatic);
    Path symlink = bundleRoot.resolve("static");
    Assumptions.assumeTrue(canCreateSymlink(symlink, externalStatic));

    IOException exception =
        assertThrows(IOException.class, () -> DesignSystemAssets.copyIntoBundle(bundleRoot));

    assertTrue(exception.getMessage().contains("must not be a symbolic link"));
    assertFalse(Files.exists(externalStatic.resolve("crypta-ui")));
  }

  private static boolean canCreateSymlink(Path symlink, Path target) {
    try {
      Files.createSymbolicLink(symlink, target);
      return true;
    } catch (UnsupportedOperationException | IOException | SecurityException _) {
      return false;
    }
  }

  private static String sha256Hex(String resourcePath) throws Exception {
    try (var input = DesignSystemAssetsTest.class.getResourceAsStream(resourcePath)) {
      assert input != null;
      return sha256Hex(input.readAllBytes());
    }
  }

  private static String sha256Hex(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
}
