package com.jthemedetecor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExecutableResolverTest {
  @TempDir Path tempDir;

  @Test
  void resolveFromPath_whenExecutableIsInNonStandardDirectory_expectResolvedPath()
      throws IOException {
    Path customPrefix = Files.createDirectories(tempDir.resolve("nix-profile").resolve("bin"));
    Path executable = Files.writeString(customPrefix.resolve("gsettings"), "#!/bin/sh\n");

    assertTrue(executable.toFile().setExecutable(true));

    String path =
        String.join(
            File.pathSeparator, tempDir.resolve("missing").toString(), customPrefix.toString());

    assertEquals(
        executable.toAbsolutePath().toString(),
        ExecutableResolver.resolveFromPath("gsettings", path));
  }

  @Test
  void resolveFirstFromPath_whenOnlyFallbackExecutableExists_expectResolvedPath()
      throws IOException {
    Path customPrefix = Files.createDirectories(tempDir.resolve("plasma").resolve("bin"));
    Path executable = Files.writeString(customPrefix.resolve("kreadconfig5"), "#!/bin/sh\n");

    assertTrue(executable.toFile().setExecutable(true));

    assertEquals(
        executable.toAbsolutePath().toString(),
        ExecutableResolver.resolveFirstFromPath(
            java.util.List.of("kreadconfig6", "kreadconfig5"), customPrefix.toString()));
  }

  @Test
  void resolveFromPath_whenPathBlank_expectBareExecutableName() throws IOException {
    assertEquals("gsettings", ExecutableResolver.resolveFromPath("gsettings", " "));
  }

  @Test
  void resolveCandidatesFromPath_whenPathBlank_expectBareExecutableNamesPreserved()
      throws IOException {
    assertEquals(
        List.of("kreadconfig6", "kreadconfig5"),
        ExecutableResolver.resolveCandidatesFromPath(List.of("kreadconfig6", "kreadconfig5"), ""));
  }
}
