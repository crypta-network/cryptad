package network.crypta.runtime.spi;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class RuntimeSpiJdkOnlyBoundaryTest {
  private static final Pattern IMPORT_PATTERN =
      Pattern.compile("^import(?:\\s+static)?\\s+([^;]+);$");

  @Test
  void runtimeSpiMainSources_whenScanningImports_expectJdkOnlyImports() throws IOException {
    Path mainJava = Path.of("src", "main", "java");
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : findJavaSources(mainJava)) {
      for (String line : Files.readAllLines(sourceFile)) {
        Matcher matcher = IMPORT_PATTERN.matcher(line);
        if (matcher.matches() && !matcher.group(1).startsWith("java.")) {
          violations.add(sourceFile + " -> " + matcher.group(1));
        }
      }
    }

    assertTrue(
        violations.isEmpty(),
        "runtime-spi main sources must remain JDK-only imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> stream = Files.walk(root)) {
      return stream.filter(path -> path.toString().endsWith(".java")).sorted().toList();
    }
  }
}
