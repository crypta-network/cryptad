package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("java:S100")
class NativeDeployerTest {

  @Test
  void getLocalResourcePath_whenResourceExists_returnsExtractedFile(@TempDir Path tempDir)
      throws IOException {
    Path resourceDir = tempDir.resolve("resources");
    Files.createDirectories(resourceDir);
    Path resourcePath = resourceDir.resolve("libfile.bin");
    byte[] expected = "native-bytes".getBytes(StandardCharsets.UTF_8);
    Files.write(resourcePath, expected);

    try (URLClassLoader cl = new URLClassLoader(new URL[] {tempDir.toUri().toURL()})) {
      String extractedPath = NativeDeployer.getLocalResourcePath(cl, "resources/libfile.bin");

      assertNotNull(extractedPath);
      byte[] actual = Files.readAllBytes(Path.of(extractedPath));
      assertArrayEquals(expected, actual);
    }
  }

  @Test
  void getLocalResourcePath_whenResourceMissing_returnsNull(@TempDir Path tempDir)
      throws IOException {
    try (URLClassLoader cl = new URLClassLoader(new URL[] {tempDir.toUri().toURL()})) {
      String extractedPath = NativeDeployer.getLocalResourcePath(cl, "missing.bin");

      assertNull(extractedPath);
    }
  }

  @Test
  void getLibraryPath_whenMatchingOsArchAndResourcePresent_extractsLibrary(@TempDir Path tempDir)
      throws IOException {
    Path nativeDir = tempDir.resolve("native");
    Files.createDirectories(nativeDir);
    Path nativeFile = nativeDir.resolve("libmatched.bin");
    byte[] expected = "matching-native".getBytes(StandardCharsets.UTF_8);
    Files.write(nativeFile, expected);

    Path propertiesDir = tempDir.resolve("lib");
    Files.createDirectories(propertiesDir);
    Path propertiesFile = propertiesDir.resolve("native.properties");
    String propertiesContent =
        "com.onionnetworks.native.keys=lib1\n"
            + "com.onionnetworks.native.lib1.name=testlib\n"
            + "com.onionnetworks.native.lib1.osarch="
            + NativeDeployer.OS_ARCH
            + "\n"
            + "com.onionnetworks.native.lib1.path=native/libmatched.bin\n";
    Files.writeString(propertiesFile, propertiesContent, StandardCharsets.ISO_8859_1);

    try (URLClassLoader cl = new URLClassLoader(new URL[] {tempDir.toUri().toURL()})) {
      String extractedPath = NativeDeployer.getLibraryPath(cl, "testlib");

      assertNotNull(extractedPath);
      byte[] actual = Files.readAllBytes(Path.of(extractedPath));
      assertArrayEquals(expected, actual);
    }
  }

  @Test
  void getLibraryPath_whenNoOsArchMatch_returnsNull(@TempDir Path tempDir) throws IOException {
    Path propertiesDir = tempDir.resolve("lib");
    Files.createDirectories(propertiesDir);
    Path propertiesFile = propertiesDir.resolve("native.properties");
    String propertiesContent =
        """
        com.onionnetworks.native.keys=lib1
        com.onionnetworks.native.lib1.name=testlib
        com.onionnetworks.native.lib1.osarch=other-arch
        com.onionnetworks.native.lib1.path=native/libmatched.bin
        """;
    Files.writeString(propertiesFile, propertiesContent, StandardCharsets.ISO_8859_1);

    try (URLClassLoader cl = new URLClassLoader(new URL[] {tempDir.toUri().toURL()})) {
      String extractedPath = NativeDeployer.getLibraryPath(cl, "testlib");

      assertNull(extractedPath);
    }
  }

  @Test
  void getLibraryPath_whenResourceMissing_returnsNull(@TempDir Path tempDir) throws IOException {
    Path propertiesDir = tempDir.resolve("lib");
    Files.createDirectories(propertiesDir);
    Path propertiesFile = propertiesDir.resolve("native.properties");
    String propertiesContent =
        "com.onionnetworks.native.keys=lib1\n"
            + "com.onionnetworks.native.lib1.name=testlib\n"
            + "com.onionnetworks.native.lib1.osarch="
            + NativeDeployer.OS_ARCH
            + "\n"
            + "com.onionnetworks.native.lib1.path=native/missing.bin\n";
    Files.writeString(propertiesFile, propertiesContent, StandardCharsets.ISO_8859_1);

    try (URLClassLoader cl = new URLClassLoader(new URL[] {tempDir.toUri().toURL()})) {
      String extractedPath = NativeDeployer.getLibraryPath(cl, "testlib");

      assertNull(extractedPath);
    }
  }
}
