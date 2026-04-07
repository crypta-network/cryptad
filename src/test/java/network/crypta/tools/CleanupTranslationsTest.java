package network.crypta.tools;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CleanupTranslationsTest {

  @TempDir Path tempDir;

  @Test
  void main_whenTranslationHasOrphanedKey_removesLineAndRewritesFile()
      throws IOException, InterruptedException {
    // Arrange
    Path l10nDir = createL10nDir(tempDir);
    writeEnglishKeys(l10nDir, List.of("known", "another"));
    Path translation = l10nDir.resolve("crypta.l10n.fr.properties");
    writeL10nFile(
        translation,
        List.of("known=Bonjour", "orphaned=ShouldBeRemoved", "another=Au revoir", "End"));

    // Act
    ProcessResult result = runCleanupTranslations(tempDir);

    // Assert
    assertEquals(0, result.exitCode());
    assertTrue(
        result.stderr().contains("Orphaned string: \"orphaned\""),
        "Expected orphaned key to be reported on stderr");
    assertTrue(
        result.stdout().contains("Rewritten"),
        "Expected rewritten message on stdout, got: " + result.stdout());
    assertTrue(
        result.stdout().contains("crypta.l10n.fr.properties"),
        "Expected rewritten file name on stdout, got: " + result.stdout());

    String rewritten = Files.readString(translation, StandardCharsets.UTF_8);
    assertEquals(
        String.join("\n", List.of("known=Bonjour", "another=Au revoir", "End", "")),
        rewritten,
        "Expected orphaned line to be removed and file to remain newline-terminated");
  }

  @Test
  void main_whenNoOrphanedKeys_expectNoRewrite() throws IOException, InterruptedException {
    // Arrange
    Path l10nDir = createL10nDir(tempDir);
    writeEnglishKeys(l10nDir, List.of("onlyKey"));
    Path translation = l10nDir.resolve("crypta.l10n.de.properties");
    writeL10nFile(translation, List.of("onlyKey=Hallo", "End"));
    String before = Files.readString(translation, StandardCharsets.UTF_8);

    // Act
    ProcessResult result = runCleanupTranslations(tempDir);

    // Assert
    assertEquals(0, result.exitCode());
    assertFalse(result.stdout().contains("Rewritten"), "Expected no rewrite output when unchanged");
    assertEquals(before, Files.readString(translation, StandardCharsets.UTF_8));
  }

  @Test
  void main_whenNonTranslationFileInvalid_expectIgnoredAndStillSucceeds()
      throws IOException, InterruptedException {
    // Arrange
    Path l10nDir = createL10nDir(tempDir);
    writeEnglishKeys(l10nDir, List.of("k"));
    writeL10nFile(l10nDir.resolve("crypta.l10n.es.properties"), List.of("k=Hola", "End"));
    // Does not start with "crypta.l10n.", and does not end with "End" either; should be ignored.
    writeUtf8File(l10nDir.resolve("crypta.1l0n.en.properties"), List.of("noEndHere"));

    // Act
    ProcessResult result = runCleanupTranslations(tempDir);

    // Assert
    assertEquals(0, result.exitCode());
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("malformedTranslationCases")
  void main_whenTranslationMalformed_expectExitCodeAndMessage(
      String caseName, List<String> lines, int expectedExitCode, String expectedStderrSubstring)
      throws IOException, InterruptedException {
    // Arrange
    Path l10nDir = createL10nDir(tempDir);
    writeEnglishKeys(l10nDir, List.of("k"));
    writeL10nFile(l10nDir.resolve("crypta.l10n.bad.properties"), lines);

    // Act
    ProcessResult result = runCleanupTranslations(tempDir);

    // Assert
    assertEquals(expectedExitCode, result.exitCode(), "Unexpected exit code for: " + caseName);
    assertTrue(
        result.stderr().contains(expectedStderrSubstring),
        "Expected stderr to contain: " + expectedStderrSubstring);
  }

  private static Stream<Arguments> malformedTranslationCases() {
    return Stream.of(
        Arguments.of(
            "missing End triggers exit code 4", List.of("k=v"), 4, "File does not end in End:"),
        Arguments.of(
            "line without equals triggers exit code 1",
            List.of("ThisIsNotEnd", "End"),
            1,
            "Line with no equals"),
        Arguments.of(
            "content after End triggers exit code 2",
            List.of("k=v", "End", "TrailingContent"),
            2,
            "Content after End:"));
  }

  private static Path createL10nDir(Path root) throws IOException {
    Path l10nDir = root.resolve("src").resolve("freenet").resolve("l10n");
    Files.createDirectories(l10nDir);
    return l10nDir;
  }

  private static void writeEnglishKeys(Path l10nDir, List<String> keys) throws IOException {
    Path english = l10nDir.resolve("crypta.l10n.en.properties");
    java.util.ArrayList<String> lines = new java.util.ArrayList<>();
    for (String key : keys) {
      lines.add(key + "=EN");
    }
    lines.add("End");
    writeL10nFile(english, lines);
  }

  private static void writeL10nFile(Path file, List<String> lines) throws IOException {
    writeUtf8File(file, lines);
  }

  private static void writeUtf8File(Path file, List<String> lines) throws IOException {
    String content = String.join("\n", lines) + "\n";
    Path parent = file.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Files.writeString(file, content, StandardCharsets.UTF_8);
  }

  private static ProcessResult runCleanupTranslations(Path workingDir) throws IOException {
    StringWriter stdoutBuffer = new StringWriter();
    StringWriter stderrBuffer = new StringWriter();
    PrintWriter stdout = new PrintWriter(stdoutBuffer, true);
    PrintWriter stderr = new PrintWriter(stderrBuffer, true);

    int exitCode = CleanupTranslations.run(workingDir.toFile(), stdout, stderr);

    return new ProcessResult(exitCode, stdoutBuffer.toString(), stderrBuffer.toString());
  }

  private record ProcessResult(int exitCode, String stdout, String stderr) {}
}
