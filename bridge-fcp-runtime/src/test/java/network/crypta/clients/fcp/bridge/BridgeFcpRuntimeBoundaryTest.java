package network.crypta.clients.fcp.bridge;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class BridgeFcpRuntimeBoundaryTest {
  private static final String MODULE_NAME = "bridge-fcp-runtime";
  private static final Path ROOT_BRIDGE_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "clients", "fcp", "bridge");
  private static final Path ADAPTER_BRIDGE_MAIN_JAVA =
      Path.of(
          "adapter-fcp", "src", "main", "java", "network", "crypta", "clients", "fcp", "bridge");
  private static final Path BRIDGE_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "fcp", "bridge");
  private static final Path BRIDGE_BUILD_FILE = Path.of(MODULE_NAME, "build.gradle.kts");
  private static final Path ADAPTER_BUILD_FILE = Path.of("adapter-fcp", "build.gradle.kts");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Path ADAPTER_OWNERSHIP_METADATA =
      Path.of("adapter-fcp", "gradle", "owned-output-patterns.txt");

  @Test
  void mainSourceLayout_whenCheckingBridgeOwnership_expectLeafOwnsPackageTree() throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(BRIDGE_MAIN_JAVA)),
        ":bridge-fcp-runtime must own network/crypta/clients/fcp/bridge main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_BRIDGE_MAIN_JAVA)),
        "Root project must not own network/crypta/clients/fcp/bridge main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ADAPTER_BRIDGE_MAIN_JAVA)),
        ":adapter-fcp must not own network/crypta/clients/fcp/bridge main sources");
  }

  @Test
  void buildWiring_whenCheckingLeafMetadata_expectLeafDeclaredAndOwned() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String bridgeBuild = Files.readString(repoRoot.resolve(BRIDGE_BUILD_FILE));
    String adapterBuild = Files.readString(repoRoot.resolve(ADAPTER_BUILD_FILE));
    Set<String> metadataPatterns = readOwnershipPatterns(repoRoot.resolve(OWNERSHIP_METADATA));
    Set<String> adapterMetadataPatterns =
        readOwnershipPatterns(repoRoot.resolve(ADAPTER_OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":adapter-fcp\""));
    assertTrue(settings.contains("\":bridge-fcp-runtime\""));
    assertTrue(build.contains("project(\":adapter-fcp\")"));
    assertTrue(build.contains("project(\":bridge-fcp-runtime\")"));
    assertTrue(
        containsDirectProjectDependency(bridgeBuild, ":adapter-fcp"),
        ":bridge-fcp-runtime must depend on :adapter-fcp");
    assertTrue(
        containsDirectProjectDependency(bridgeBuild, ":runtime-node"),
        ":bridge-fcp-runtime must remain the concrete runtime-binding owner for FCP");
    assertFalse(
        containsDirectProjectDependency(adapterBuild, ":runtime-node"),
        ":adapter-fcp must not depend on :runtime-node");
    assertTrue(metadataPatterns.contains("network/crypta/clients/fcp/bridge/**"));
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(OWNERSHIP_METADATA)),
        ":bridge-fcp-runtime must declare owned-output-patterns.txt");
    assertTrue(adapterMetadataPatterns.contains("network/crypta/clients/fcp/*"));
    assertFalse(
        adapterMetadataPatterns.contains("network/crypta/clients/fcp/bridge/**"),
        ":adapter-fcp must not claim network/crypta/clients/fcp/bridge/**");
  }

  @Test
  void mainSources_whenScanningProductionPackages_expectPackageInfoInEveryPackage()
      throws IOException {
    Path repoRoot = repoRoot();
    Path bridgeMain = repoRoot.resolve(Path.of(MODULE_NAME, "src", "main", "java"));
    Set<Path> productionPackages = new TreeSet<>(Comparator.comparing(Path::toString));
    List<String> missingPackageInfos = new ArrayList<>();

    assertTrue(Files.isDirectory(bridgeMain), ":bridge-fcp-runtime main Java tree must exist");

    for (Path sourceFile : findJavaSources(bridgeMain)) {
      String fileName = fileNameOrThrow(sourceFile);
      if (fileName.equals("package-info.java") || fileName.equals("module-info.java")) {
        continue;
      }
      productionPackages.add(parentOrThrow(sourceFile));
    }

    for (Path packagePath : productionPackages) {
      if (!Files.isRegularFile(packagePath.resolve("package-info.java"))) {
        missingPackageInfos.add(repoRoot.relativize(packagePath).toString());
      }
    }

    assertTrue(
        missingPackageInfos.isEmpty(),
        "Every :bridge-fcp-runtime main package with production Java files must declare "
            + "package-info.java."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), missingPackageInfos));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(BridgeFcpRuntimeBoundaryTest::isTrackedJavaSource)
          .sorted(Comparator.comparing(Path::toString))
          .toList();
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

  private static boolean containsDirectProjectDependency(String buildScript, String modulePath) {
    String uncommentedScript = stripCommentsPreservingStrings(buildScript);
    for (DependencyBlock dependencyBlock : extractDependencyBlocks(uncommentedScript)) {
      Matcher invocationMatcher =
          Pattern.compile("\\bproject\\s*\\(").matcher(dependencyBlock.content());

      while (invocationMatcher.find()) {
        int openParen = dependencyBlock.content().indexOf('(', invocationMatcher.start());
        int closeParen = findMatchingParenthesis(dependencyBlock.content(), openParen);
        if (closeParen == -1) {
          continue;
        }
        String invocationArgs = dependencyBlock.content().substring(openParen + 1, closeParen);
        String pathExpression = extractProjectPathExpression(invocationArgs);
        if (pathExpression == null) {
          continue;
        }
        int invocationStartInScript = dependencyBlock.bodyStartIndex() + invocationMatcher.start();
        String resolvedPath =
            resolveStringExpression(
                stripEnclosingParentheses(pathExpression),
                uncommentedScript.substring(0, invocationStartInScript),
                dependencyBlock.content().substring(0, invocationMatcher.start()),
                new java.util.HashSet<>());
        if (modulePath.equals(resolvedPath)) {
          return true;
        }
      }
    }
    return false;
  }

  private record DependencyBlock(String content, int bodyStartIndex) {}

  private static List<DependencyBlock> extractDependencyBlocks(String script) {
    List<DependencyBlock> blocks = new ArrayList<>();
    Matcher dependenciesMatcher = Pattern.compile("\\bdependencies\\s*\\{").matcher(script);

    while (dependenciesMatcher.find()) {
      int openBrace = script.indexOf('{', dependenciesMatcher.start());
      int closeBrace = findMatchingBrace(script, openBrace);
      if (closeBrace == -1) {
        continue;
      }
      blocks.add(new DependencyBlock(script.substring(openBrace + 1, closeBrace), openBrace + 1));
    }

    return blocks;
  }

  private static String extractProjectPathExpression(String invocationArgs) {
    String trimmedArgs = stripEnclosingParentheses(invocationArgs.trim());
    if (trimmedArgs.startsWith("mapOf")) {
      int openParen = trimmedArgs.indexOf('(');
      if (openParen == -1) {
        return null;
      }
      int closeParen = findMatchingParenthesis(trimmedArgs, openParen);
      if (closeParen == -1) {
        return null;
      }
      String mapArgs = trimmedArgs.substring(openParen + 1, closeParen);
      for (String entry : splitTopLevel(mapArgs, ',')) {
        Matcher pathEntryMatcher =
            Pattern.compile("^\\s*\"path\"\\s*to\\s*(.+)$", Pattern.DOTALL).matcher(entry);
        if (pathEntryMatcher.matches()) {
          return pathEntryMatcher.group(1).trim();
        }
      }
      return null;
    }

    for (String argument : splitTopLevel(trimmedArgs, ',')) {
      int equalsIndex = findTopLevelEquals(argument);
      if (equalsIndex == -1) {
        continue;
      }
      String leftSide = argument.substring(0, equalsIndex).trim();
      if (leftSide.equals("path")) {
        return argument.substring(equalsIndex + 1).trim();
      }
    }

    return trimmedArgs;
  }

  private static String resolveStringExpression(
      String expression,
      String scriptPrefix,
      String dependencyScopePrefix,
      Set<String> visitedIdentifiers) {
    String trimmedExpression = stripEnclosingParentheses(expression.trim());
    if (trimmedExpression.isEmpty()) {
      return null;
    }

    if (trimmedExpression.startsWith("\"\"\"") && trimmedExpression.endsWith("\"\"\"")) {
      return resolveKotlinStringLiteral(
          trimmedExpression.substring(3, trimmedExpression.length() - 3),
          scriptPrefix,
          dependencyScopePrefix,
          visitedIdentifiers,
          true);
    }

    if (trimmedExpression.startsWith("\"") && trimmedExpression.endsWith("\"")) {
      return resolveKotlinStringLiteral(
          trimmedExpression.substring(1, trimmedExpression.length() - 1),
          scriptPrefix,
          dependencyScopePrefix,
          visitedIdentifiers,
          false);
    }

    List<String> concatenatedParts = splitTopLevel(trimmedExpression, '+');
    if (concatenatedParts.size() > 1) {
      StringBuilder resolved = new StringBuilder();
      for (String part : concatenatedParts) {
        String resolvedPart =
            resolveStringExpression(part, scriptPrefix, dependencyScopePrefix, visitedIdentifiers);
        if (resolvedPart == null) {
          return null;
        }
        resolved.append(resolvedPart);
      }
      return resolved.toString();
    }

    if (trimmedExpression.matches("[A-Za-z_][A-Za-z0-9_]*")
        && visitedIdentifiers.add(trimmedExpression)) {
      String assignedExpression =
          resolveIdentifierAssignment(trimmedExpression, dependencyScopePrefix, scriptPrefix);
      if (assignedExpression != null) {
        return resolveStringExpression(
            assignedExpression, scriptPrefix, dependencyScopePrefix, visitedIdentifiers);
      }
    }

    return null;
  }

  private static String resolveKotlinStringLiteral(
      String literalBody,
      String scriptPrefix,
      String dependencyScopePrefix,
      Set<String> visitedIdentifiers,
      boolean rawString) {
    StringBuilder resolved = new StringBuilder();

    for (int index = 0; index < literalBody.length(); index++) {
      char current = literalBody.charAt(index);
      char previous = index > 0 ? literalBody.charAt(index - 1) : 0;

      if (current != '$' || (!rawString && previous == '\\')) {
        resolved.append(current);
        continue;
      }

      if (index + 1 >= literalBody.length()) {
        resolved.append(current);
        continue;
      }

      char next = literalBody.charAt(index + 1);
      if (next == '{') {
        int templateEnd = findMatchingTemplateBrace(literalBody, index + 1);
        if (templateEnd == -1) {
          return null;
        }
        String templateExpression = literalBody.substring(index + 2, templateEnd);
        String resolvedTemplate =
            resolveStringExpression(
                templateExpression, scriptPrefix, dependencyScopePrefix, visitedIdentifiers);
        if (resolvedTemplate == null) {
          return null;
        }
        resolved.append(resolvedTemplate);
        index = templateEnd;
        continue;
      }

      if (Character.isJavaIdentifierStart(next)) {
        int identifierEnd = index + 2;
        while (identifierEnd < literalBody.length()
            && Character.isJavaIdentifierPart(literalBody.charAt(identifierEnd))) {
          identifierEnd++;
        }
        String identifier = literalBody.substring(index + 1, identifierEnd);
        String resolvedIdentifier =
            resolveStringExpression(
                identifier, scriptPrefix, dependencyScopePrefix, visitedIdentifiers);
        if (resolvedIdentifier == null) {
          return null;
        }
        resolved.append(resolvedIdentifier);
        index = identifierEnd - 1;
        continue;
      }

      resolved.append(current);
    }

    return resolved.toString();
  }

  private static String resolveIdentifierAssignment(
      String identifier, String dependencyScopePrefix, String scriptPrefix) {
    String localAssignment = findLastAssignmentInScope(identifier, dependencyScopePrefix);
    if (localAssignment != null) {
      return localAssignment;
    }
    return findLastAssignmentInScope(identifier, extractTopLevelScopePrefix(scriptPrefix));
  }

  private static String findLastAssignmentInScope(String identifier, String scopePrefix) {
    Matcher declarationMatcher =
        Pattern.compile(
                "(?m)^\\s*(?:val|var)\\s+"
                    + Pattern.quote(identifier)
                    + "(?:\\s*:\\s*[^=\\n]+)?\\s*=")
            .matcher(scopePrefix);
    int lastExpressionStart = -1;
    while (declarationMatcher.find()) {
      lastExpressionStart = declarationMatcher.end();
    }
    if (lastExpressionStart == -1) {
      return null;
    }

    int expressionEnd = findExpressionEnd(scopePrefix, lastExpressionStart);
    return scopePrefix.substring(lastExpressionStart, expressionEnd).trim();
  }

  private static String extractTopLevelScopePrefix(String text) {
    StringBuilder scopeText = new StringBuilder(text.length());
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = 0; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        scopeText.append(depth == 0 ? current : ' ');
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        scopeText.append(depth == 0 ? current : ' ');
        continue;
      }

      if (current == '{') {
        scopeText.append(' ');
        depth++;
        continue;
      }

      if (current == '}') {
        depth = Math.max(0, depth - 1);
        scopeText.append(' ');
        continue;
      }

      if (depth == 0) {
        scopeText.append(current);
      } else {
        scopeText.append(current == '\n' ? '\n' : ' ');
      }
    }

    return scopeText.toString();
  }

  private static int findExpressionEnd(String text, int expressionStart) {
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;
    boolean sawNonWhitespace = false;

    for (int index = expressionStart; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > expressionStart ? text.charAt(index - 1) : 0;

      if (inString) {
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        sawNonWhitespace = true;
        continue;
      }

      if (current == '(' || current == '[' || current == '{') {
        depth++;
      } else if (current == ')' || current == ']' || current == '}') {
        depth--;
      } else if (current == ';' && depth == 0 && sawNonWhitespace) {
        return index;
      } else if (current == '\n' && depth == 0 && sawNonWhitespace) {
        String expressionSoFar = text.substring(expressionStart, index);
        if (!continuesExpression(expressionSoFar)) {
          return index;
        }
      }

      if (!Character.isWhitespace(current)) {
        sawNonWhitespace = true;
      }
    }

    return text.length();
  }

  private static int findMatchingTemplateBrace(String text, int openBrace) {
    return findMatchingCurlyBrace(text, openBrace);
  }

  private static int findMatchingBrace(String text, int openBrace) {
    return findMatchingCurlyBrace(text, openBrace);
  }

  private static int findMatchingCurlyBrace(String text, int openBrace) {
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = openBrace; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        continue;
      }

      if (current == '{') {
        depth++;
      } else if (current == '}') {
        depth--;
        if (depth == 0) {
          return index;
        }
      }
    }

    return -1;
  }

  private static String stripCommentsPreservingStrings(String text) {
    StringBuilder stripped = new StringBuilder(text.length());
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = 0; index < text.length(); index++) {
      char current = text.charAt(index);
      char next = index + 1 < text.length() ? text.charAt(index + 1) : 0;
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        stripped.append(current);
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        stripped.append(current);
        continue;
      }

      if (current == '/' && next == '/') {
        index += 2;
        while (index < text.length() && text.charAt(index) != '\n') {
          index++;
        }
        if (index < text.length()) {
          stripped.append('\n');
        }
        continue;
      }

      if (current == '/' && next == '*') {
        index += 2;
        while (index + 1 < text.length()
            && !(text.charAt(index) == '*' && text.charAt(index + 1) == '/')) {
          if (text.charAt(index) == '\n') {
            stripped.append('\n');
          }
          index++;
        }
        index++;
        continue;
      }

      stripped.append(current);
    }

    return stripped.toString();
  }

  private static boolean continuesExpression(String expressionSoFar) {
    String trimmed = expressionSoFar.trim();
    if (trimmed.isEmpty()) {
      return true;
    }

    return trimmed.endsWith("+")
        || trimmed.endsWith("-")
        || trimmed.endsWith("*")
        || trimmed.endsWith("/")
        || trimmed.endsWith("%")
        || trimmed.endsWith("&&")
        || trimmed.endsWith("||")
        || trimmed.endsWith("?:")
        || trimmed.endsWith("?.")
        || trimmed.endsWith("..")
        || trimmed.endsWith(",")
        || trimmed.endsWith("(")
        || trimmed.endsWith("[")
        || trimmed.endsWith("{")
        || trimmed.endsWith("to");
  }

  private static String stripEnclosingParentheses(String expression) {
    String trimmed = expression.trim();
    while (trimmed.startsWith("(")
        && trimmed.endsWith(")")
        && findMatchingParenthesis(trimmed, 0) == trimmed.length() - 1) {
      trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
    }
    return trimmed;
  }

  private static List<String> splitTopLevel(String text, char delimiter) {
    List<String> parts = new ArrayList<>();
    int segmentStart = 0;
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = 0; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        continue;
      }

      if (current == '(') {
        depth++;
      } else if (current == ')') {
        depth--;
      } else if (current == delimiter && depth == 0) {
        parts.add(text.substring(segmentStart, index).trim());
        segmentStart = index + 1;
      }
    }

    parts.add(text.substring(segmentStart).trim());
    return parts;
  }

  private static int findTopLevelEquals(String text) {
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = 0; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        continue;
      }

      if (current == '(') {
        depth++;
      } else if (current == ')') {
        depth--;
      } else if (current == '=' && depth == 0) {
        return index;
      }
    }

    return -1;
  }

  private static int findMatchingParenthesis(String text, int openParen) {
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = openParen; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        continue;
      }

      if (current == '(') {
        depth++;
      } else if (current == ')') {
        depth--;
        if (depth == 0) {
          return index;
        }
      }
    }

    return -1;
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
