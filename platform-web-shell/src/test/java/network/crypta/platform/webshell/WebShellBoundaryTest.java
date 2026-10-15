package network.crypta.platform.webshell;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class WebShellBoundaryTest {
  private static final String MODULE_NAME = "platform-web-shell";
  private static final Path ROOT_WEB_SHELL_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "platform", "webshell");
  private static final Path WEB_SHELL_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "platform", "webshell");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Set<String> FORBIDDEN_IMPORT_PREFIXES =
      Set.of(
          "network.crypta.clients.",
          "network.crypta.runtime.",
          "network.crypta.node.",
          "network.crypta.client.",
          "network.crypta.platform.api.",
          "network.crypta.platform.apphost.",
          "network.crypta.launcher.");

  @Test
  void mainSourceLayout_whenCheckingLeafOwnership_expectLeafOwnsPackageTree() throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(WEB_SHELL_MAIN_JAVA)),
        ":platform-web-shell must own network/crypta/platform/webshell main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_WEB_SHELL_MAIN_JAVA)),
        "Root project must not own network/crypta/platform/webshell main sources");
  }

  @Test
  void buildWiring_whenCheckingLeafMetadata_expectOwnedOutputPatternDeclared() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String metadata = Files.readString(repoRoot.resolve(OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":platform-web-shell\""));
    assertTrue(build.contains("project(\":platform-web-shell\")"));
    assertTrue(metadata.contains("network/crypta/platform/webshell/**"));
  }

  @Test
  void mainSources_whenScanningImports_expectNoRuntimeOrAdapterImports() throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();
    Path mainJava = repoRoot.resolve(Path.of(MODULE_NAME, "src", "main", "java"));

    for (Path sourceFile : findJavaSources(mainJava)) {
      Set<String> imports = readForbiddenImports(sourceFile);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        ":platform-web-shell main sources must stay free of runtime, adapter, client, node, and "
            + "Platform API implementation imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void mainSources_whenScanningProductionPackages_expectPackageInfoInEveryPackage()
      throws IOException {
    Path repoRoot = repoRoot();
    Path mainJava = repoRoot.resolve(Path.of(MODULE_NAME, "src", "main", "java"));
    Set<Path> productionPackages = new TreeSet<>(Comparator.comparing(Path::toString));

    assertTrue(
        Files.isDirectory(repoRoot.resolve(WEB_SHELL_MAIN_JAVA)),
        ":platform-web-shell main Java tree must exist");

    for (Path sourceFile : findJavaSources(mainJava)) {
      String fileName = fileNameOrThrow(sourceFile);
      if (fileName.equals("package-info.java") || fileName.equals("module-info.java")) {
        continue;
      }
      productionPackages.add(parentOrThrow(sourceFile));
    }

    for (Path packagePath : productionPackages) {
      assertTrue(
          Files.isRegularFile(packagePath.resolve("package-info.java")),
          "Missing package-info.java for " + repoRoot.relativize(packagePath));
    }
  }

  @Test
  void selectedSourceRoster_whenHistoryPollutesExport_expectOnlyDeclaredSources(
      @TempDir Path temporary) throws IOException {
    Path fixture = Files.createDirectory(temporary.toRealPath().resolve("owned root é"));
    Path main =
        Files.createDirectories(fixture.resolve(Path.of(MODULE_NAME, "src", "main", "java")));
    Path active = Files.writeString(main.resolve("Active.java"), "class Active {}\n");
    String activeName = fixture.relativize(active).toString().replace('\\', '/');
    Path roster = Files.writeString(fixture.resolve("main-java-sources.txt"), activeName + "\n");
    List<Path> clean = findJavaSources(fixture, main, roster);
    Path history = Files.createDirectory(main.resolve(".stversions"));
    Path archived = Files.writeString(history.resolve("Archived.java"), "class Archived {}\n");

    assertEquals(List.of(active), clean);
    assertEquals(clean, findJavaSources(fixture, main, roster));

    String declaredHistory = fixture.relativize(archived).toString().replace('\\', '/');
    Files.writeString(roster, activeName + "\n" + declaredHistory + "\n");
    List<Path> explicitlySelected = findJavaSources(fixture, main, roster);
    assertEquals(2, explicitlySelected.size());
    assertTrue(
        explicitlySelected.contains(archived), "A declared member must not silently disappear");
  }

  @Test
  void selectedSourceRoster_whenMemberUnsafeMissingOrDuplicated_expectRejected(
      @TempDir Path temporary) throws IOException {
    Path fixture = temporary.toRealPath();
    Path main =
        Files.createDirectories(fixture.resolve(Path.of(MODULE_NAME, "src", "main", "java")));
    Path active = Files.writeString(main.resolve("Active.java"), "class Active {}\n");
    String activeName = fixture.relativize(active).toString().replace('\\', '/');
    Path roster = fixture.resolve("main-java-sources.txt");

    for (String selected :
        List.of(
            "../Escape.java",
            "/outside.java",
            "C:/outside.java",
            "C:\\outside.java",
            "\\\\server\\share\\outside.java",
            activeName + "\n" + activeName,
            MODULE_NAME + "/src/main/java/Missing.java")) {
      Files.writeString(roster, selected + "\n");
      assertThrows(IOException.class, () -> findJavaSources(fixture, main, roster));
    }
    assertThrows(
        IOException.class,
        () -> findJavaSources(fixture, main, fixture.resolve("missing-roster.txt")));
  }

  @Test
  void selectedSourceRoster_whenSourceOrRosterIsLinked_expectRejected(@TempDir Path temporary)
      throws IOException {
    Path fixture = temporary.toRealPath();
    Path main =
        Files.createDirectories(fixture.resolve(Path.of(MODULE_NAME, "src", "main", "java")));
    Path actual = Files.writeString(fixture.resolve("Actual.java"), "class Actual {}\n");
    Path linked = main.resolve("Linked.java");
    try {
      Files.createSymbolicLink(linked, actual);
    } catch (UnsupportedOperationException _) {
      org.junit.jupiter.api.Assumptions.abort("filesystem-provider-symbolic-links-unsupported");
    }
    String selected = fixture.relativize(linked).toString().replace('\\', '/');
    Path roster = Files.writeString(fixture.resolve("main-java-sources.txt"), selected + "\n");

    assertThrows(IOException.class, () -> findJavaSources(fixture, main, roster));

    Files.delete(linked);
    Files.writeString(linked, "class Linked {}\n");
    Path actualPackage = Files.createDirectory(fixture.resolve("actual-package"));
    Files.writeString(actualPackage.resolve("Source.java"), "class Source {}\n");
    Path linkedPackage = Files.createSymbolicLink(main.resolve("linkedpackage"), actualPackage);
    String ancestorMember =
        fixture.relativize(linkedPackage.resolve("Source.java")).toString().replace('\\', '/');
    Files.writeString(roster, ancestorMember + "\n");
    assertThrows(IOException.class, () -> findJavaSources(fixture, main, roster));

    Files.writeString(roster, selected + "\n");
    Path actualRoster = Files.move(roster, fixture.resolve("actual-roster.txt"));
    Files.createSymbolicLink(roster, actualRoster);
    assertThrows(IOException.class, () -> findJavaSources(fixture, main, roster));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    String selected = System.getProperty("cryptad.test.mainJavaSourceRoster");
    if (selected == null || selected.isBlank()) {
      throw new IOException("Run boundary tests with the Gradle wrapper source roster");
    }
    return findJavaSources(repoRoot(), root, Path.of(selected));
  }

  private static List<Path> findJavaSources(Path repository, Path root, Path roster)
      throws IOException {
    repository = repository.toAbsolutePath().normalize();
    root = root.toAbsolutePath().normalize();
    requirePlainPath(repository, true);
    requirePlainPath(root, true);
    requirePlainPath(roster, false);
    if (!root.startsWith(repository)) {
      throw new IOException("Source directory is outside the selected repository");
    }
    var before = Files.readAttributes(roster, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (before.size() > 4 * 1024 * 1024) {
      throw new IOException("Source roster exceeds its byte limit");
    }
    byte[] raw;
    try (var input = Files.newInputStream(roster, LinkOption.NOFOLLOW_LINKS)) {
      raw = input.readNBytes(4 * 1024 * 1024 + 1);
    }
    var after = Files.readAttributes(roster, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (raw.length != before.size()
        || before.size() != after.size()
        || !java.util.Objects.equals(before.fileKey(), after.fileKey())
        || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
      throw new IOException("Source roster changed while reading");
    }
    String[] names =
        StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(raw)).toString().split("\n", -1);
    if (names.length > 30001) {
      throw new IOException("Source roster exceeds its source limit");
    }
    String prefix = repository.relativize(root).toString().replace('\\', '/') + "/";
    List<Path> selected = new ArrayList<>();
    Set<String> seen = new TreeSet<>();
    for (int index = 0; index < names.length; index++) {
      String name = names[index];
      if (name.isEmpty() && index == names.length - 1) {
        continue;
      }
      if (name.isEmpty()
          || name.startsWith("/")
          || name.contains("\\")
          || name.contains(":")
          || name.codePoints().anyMatch(value -> value < 32 || value == 127)
          || java.util.Arrays.stream(name.split("/", -1))
              .anyMatch(part -> part.isEmpty() || part.equals(".") || part.equals(".."))
          || !name.endsWith(".java")
          || !seen.add(name)
          || seen.size() > 30000) {
        throw new IOException("Source roster contains an unsafe or duplicate member");
      }
      Path member = repository.resolve(name);
      requirePlainPath(member, false);
      if (name.startsWith(prefix)) {
        selected.add(member);
      }
    }
    if (selected.isEmpty()) {
      throw new IOException("Source roster has no sources for the owning module");
    }
    selected.sort(Comparator.comparing(Path::toString));
    return List.copyOf(selected);
  }

  private static void requirePlainPath(Path path, boolean directory) throws IOException {
    Path absolute = path.toAbsolutePath().normalize();
    for (Path current = absolute; current != null; current = current.getParent()) {
      if (Files.isSymbolicLink(current)) {
        throw new IOException("Source roster paths must not contain links");
      }
    }
    if (!absolute.equals(absolute.toRealPath())
        || (directory
            ? !Files.isDirectory(absolute, LinkOption.NOFOLLOW_LINKS)
            : !Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS))) {
      throw new IOException("Source roster path has an unexpected type or alias");
    }
  }

  private static Set<String> readForbiddenImports(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .filter(line -> line.startsWith("import "))
          .map(WebShellBoundaryTest::extractImportTarget)
          .filter(importTarget -> !importTarget.isEmpty())
          .filter(WebShellBoundaryTest::isForbiddenImport)
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static Path parentOrThrow(Path path) {
    Path parent = path.getParent();
    assertNotNull(parent, "Java source path must have a parent: " + path);
    return parent;
  }

  private static String fileNameOrThrow(Path path) {
    Path fileName = path.getFileName();
    assertNotNull(fileName, "Java source path must have a file name: " + path);
    return fileName.toString();
  }

  private static String extractImportTarget(String line) {
    String importTarget = line.substring("import ".length()).trim();
    if (importTarget.startsWith("static ")) {
      importTarget = importTarget.substring("static ".length()).trim();
    }
    return importTarget.endsWith(";")
        ? importTarget.substring(0, importTarget.length() - 1)
        : importTarget;
  }

  private static boolean isForbiddenImport(String importTarget) {
    return FORBIDDEN_IMPORT_PREFIXES.stream().anyMatch(importTarget::startsWith);
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
