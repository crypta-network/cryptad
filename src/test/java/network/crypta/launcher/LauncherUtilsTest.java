package network.crypta.launcher;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static network.crypta.launcher.LauncherUtils.CRYPTAD_PATH_ENV;
import static network.crypta.launcher.LauncherUtils.buildCryptadCommand;
import static network.crypta.launcher.LauncherUtils.computeWrapperFilePath;
import static network.crypta.launcher.LauncherUtils.computeWrapperLogPath;
import static network.crypta.launcher.LauncherUtils.findCryptadJarInClassPath;
import static network.crypta.launcher.LauncherUtils.findOnPath;
import static network.crypta.launcher.LauncherUtils.guessWrapperConfPathForCryptadScript;
import static network.crypta.launcher.LauncherUtils.loadAppIconImage;
import static network.crypta.launcher.LauncherUtils.parseFProxyPortFromLine;
import static network.crypta.launcher.LauncherUtils.parseWrapperProperties;
import static network.crypta.launcher.LauncherUtils.resolveCryptadPath;
import static network.crypta.launcher.LauncherUtils.resolveCryptadPathWithEnv;
import static network.crypta.launcher.LauncherUtils.scanWrapperConfPath;
import static network.crypta.launcher.LauncherUtils.shellQuote;
import static network.crypta.launcher.LauncherUtils.upsertWrapperProperty;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

@SuppressWarnings({"java:S100"})
class LauncherUtilsTest {
  private static final String CLASS_PATH_KEY = "java.class.path";
  private static final String COMMENT_LINE = "# comment";
  private static final String WRAPPER_LOGFILE_OLD = "wrapper.logfile=old.log";
  private static final String WRAPPER_WORKDIR_LINE = "wrapper.working.dir=..";
  private static final String CONF_PATH = "/opt/cryptad/conf/wrapper.conf";

  private String originalCp;

  @AfterEach
  void restoreClassPath() {
    if (originalCp != null) {
      System.setProperty(CLASS_PATH_KEY, originalCp);
    }
  }

  @ParameterizedTest
  @MethodSource("fproxyLineSamples")
  void parseFProxyPortFromLine_whenMatching_expectParsedPort(String line, int expected) {
    Integer actual = parseFProxyPortFromLine(line);
    assertEquals(expected, actual);
  }

  @ParameterizedTest
  @CsvSource({
    "Nothing to see here",
    "Starting service on port abc",
    "Starting FProxy on 127.0.0.1:9"
  })
  void parseFProxyPortFromLine_whenNoMatch_expectNull(String line) {
    Integer actual = parseFProxyPortFromLine(line);
    assertNull(actual);
  }

  @Test
  void parseWrapperProperties_whenMixedLines_expectKeyValueMap() {
    List<String> lines =
        List.of(
            COMMENT_LINE,
            "",
            " wrapper.logfile = ../logs/wrapper.log ",
            "wrapper.logfile=./override.log",
            "wrapper.working.dir = ..");

    Map<String, String> props = parseWrapperProperties(lines);

    assertEquals("./override.log", props.get("wrapper.logfile"));
    assertEquals("..", props.get("wrapper.working.dir"));
  }

  @Test
  void upsertWrapperProperty_whenKeyExists_expectFirstOccurrenceReplaced() {
    List<String> lines =
        List.of(
            COMMENT_LINE, WRAPPER_LOGFILE_OLD, "wrapper.logfile=second.log", WRAPPER_WORKDIR_LINE);

    List<String> updated = upsertWrapperProperty(lines, "wrapper.logfile", "new.log");

    assertEquals(
        List.of(
            COMMENT_LINE,
            "wrapper.logfile=new.log",
            "wrapper.logfile=second.log",
            WRAPPER_WORKDIR_LINE),
        updated);
  }

  @Test
  void upsertWrapperProperty_whenMissing_expectAppended() {
    List<String> updated =
        upsertWrapperProperty(List.of(WRAPPER_LOGFILE_OLD), "wrapper.working.dir", "..");
    assertEquals(List.of(WRAPPER_LOGFILE_OLD, WRAPPER_WORKDIR_LINE), updated);
  }

  @Test
  void computeWrapperLogPath_whenRelative_expectResolvedAgainstConfDir() {
    Path actual = computeWrapperLogPath(Paths.get(CONF_PATH), "../logs/wrapper.log");
    assertEquals(Paths.get("/opt/cryptad/logs/wrapper.log"), actual);
  }

  @Test
  void computeWrapperLogPath_whenAbsolute_expectReturnedAsIs() {
    Path actual = computeWrapperLogPath(Paths.get(CONF_PATH), "/var/log/cryptad/wrapper.log");
    assertEquals(Paths.get("/var/log/cryptad/wrapper.log"), actual);
  }

  @Test
  void computeWrapperFilePath_whenRelativeAndWorkingDirRelative_expectResolvedAgainstConfDir() {
    Path actual = computeWrapperFilePath(Paths.get(CONF_PATH), "Cryptad.anchor", "..");
    assertEquals(Paths.get("/opt/cryptad/Cryptad.anchor"), actual);
  }

  @Test
  void computeWrapperFilePath_whenRelativeAndWorkingDirAbsolute_expectResolvedAgainstWorkingDir() {
    Path actual =
        computeWrapperFilePath(Paths.get(CONF_PATH), "Cryptad.anchor", "/var/lib/cryptad");
    assertEquals(Paths.get("/var/lib/cryptad/Cryptad.anchor"), actual);
  }

  @Test
  void computeWrapperFilePath_whenAbsoluteSpec_expectReturnedAsIs() {
    Path actual =
        computeWrapperFilePath(Paths.get(CONF_PATH), "/var/lib/cryptad/cryptad.anchor", "..");
    assertEquals(Paths.get("/var/lib/cryptad/cryptad.anchor"), actual);
  }

  @Test
  void computeWrapperFilePath_whenBlankSpec_expectNull() {
    Path actual = computeWrapperFilePath(Paths.get(CONF_PATH), "  ", "..");
    assertNull(actual);
  }

  @Test
  void scanWrapperConfPath_whenConfAssignmentPresent_expectParsedPath() {
    Path actual = scanWrapperConfPath(List.of("CONF=\"" + CONF_PATH + "\""));
    assertEquals(Paths.get(CONF_PATH), actual);
  }

  @Test
  void scanWrapperConfPath_whenCFlagPresent_expectParsedPath() {
    Path actual = scanWrapperConfPath(List.of("exec wrapper -c \"" + CONF_PATH + "\""));
    assertEquals(Paths.get(CONF_PATH), actual);
  }

  @Test
  void scanWrapperConfPath_whenNotPresent_expectNull() {
    assertNull(scanWrapperConfPath(List.of("echo nothing here")));
  }

  @Test
  void guessWrapperConfPathForCryptadScript_whenDefaultExists_expectDefault(@TempDir Path tempDir)
      throws Exception {
    Path binDir = Files.createDirectories(tempDir.resolve("bin"));
    Path confDir = Files.createDirectories(tempDir.resolve("conf"));
    Path defaultConf = Files.createFile(confDir.resolve("wrapper.conf"));
    Path script = Files.createFile(binDir.resolve("cryptad"));
    Files.writeString(script, "CONF=\"/tmp/other.conf\"\n");

    Path actual = guessWrapperConfPathForCryptadScript(script);
    assertEquals(defaultConf.normalize(), actual);
  }

  @Test
  void guessWrapperConfPathForCryptadScript_whenScriptOverrides_expectParsedPath(
      @TempDir Path tempDir) throws Exception {
    Path binDir = Files.createDirectories(tempDir.resolve("bin"));
    Path script = Files.createFile(binDir.resolve("cryptad"));
    Path overridePath = tempDir.resolve("alt/wrapper.conf");
    Files.writeString(script, "CONF=\"" + overridePath + "\"\n");

    Path actual = guessWrapperConfPathForCryptadScript(script);
    assertEquals(overridePath.normalize(), actual);
  }

  @Test
  void guessWrapperConfPathForCryptadScript_whenScriptMissing_expectDefault(@TempDir Path tempDir)
      throws Exception {
    Path binDir = Files.createDirectories(tempDir.resolve("bin"));
    Path script = binDir.resolve("cryptad");
    Path expected = binDir.resolve("../conf/wrapper.conf").normalize();

    Path actual = guessWrapperConfPathForCryptadScript(script);
    assertEquals(expected, actual);
  }

  @Test
  void resolveCryptadPathWithEnv_whenAbsoluteOverride_expectNormalized(@TempDir Path tempDir)
      throws Exception {
    Path override = Files.createFile(tempDir.resolve("cryptad"));

    Path resolved =
        resolveCryptadPathWithEnv(
            tempDir, Map.of(CRYPTAD_PATH_ENV, override.toFile().getAbsolutePath()));

    assertEquals(override.normalize(), resolved.normalize());
  }

  @Test
  void resolveCryptadPathWithEnv_whenRelativeOverride_expectResolvedAgainstCwd(
      @TempDir Path tempDir) throws Exception {
    String rel = "rel/bin/cryptad";
    Path target = tempDir.resolve(rel);
    Path targetParent = target.getParent();
    assertNotNull(targetParent);
    Files.createDirectories(targetParent);
    Files.createFile(target);

    Path resolved = resolveCryptadPathWithEnv(tempDir, Map.of(CRYPTAD_PATH_ENV, rel));

    assertEquals(target.normalize(), resolved.normalize());
  }

  @Test
  void resolveCryptadPath_whenJarSiblingBinExists_expectBinScript(@TempDir Path tempDir)
      throws Exception {
    assumeFalse(new AppEnv().isWindows());
    originalCp = System.getProperty(CLASS_PATH_KEY);

    Path lib = Files.createDirectories(tempDir.resolve("lib"));
    Path bin = Files.createDirectories(tempDir.resolve("bin"));
    Path jar = Files.createFile(lib.resolve("cryptad.jar"));
    File script = Files.createFile(bin.resolve("cryptad")).toFile();
    assertTrue(script.setExecutable(true));
    System.setProperty(CLASS_PATH_KEY, jar.toString());

    Path resolved = resolveCryptadPath(Paths.get("/does/not/matter"));

    assertEquals(script.toPath().normalize(), resolved.normalize());
  }

  @Test
  void resolveCryptadPath_whenJarSameDirExists_expectLocalScript(@TempDir Path tempDir)
      throws Exception {
    assumeFalse(new AppEnv().isWindows());
    originalCp = System.getProperty(CLASS_PATH_KEY);

    Path lib = Files.createDirectories(tempDir.resolve("lib"));
    Path jar = Files.createFile(lib.resolve("cryptad.jar"));
    File script = Files.createFile(lib.resolve("cryptad")).toFile();
    assertTrue(script.setExecutable(true));
    System.setProperty(CLASS_PATH_KEY, jar.toString());

    Path resolved = resolveCryptadPath(Paths.get("/irrelevant"));

    assertEquals(script.toPath().normalize(), resolved.normalize());
  }

  @Test
  void resolveCryptadPath_whenJarMissing_expectCwdFallback(@TempDir Path tempDir) throws Exception {
    assumeFalse(new AppEnv().isWindows());
    originalCp = System.getProperty(CLASS_PATH_KEY);

    Path bin = Files.createDirectories(tempDir.resolve("bin"));
    File script = Files.createFile(bin.resolve("cryptad")).toFile();
    assertTrue(script.setExecutable(true));
    System.setProperty(CLASS_PATH_KEY, Paths.get("/no/jar/here").toString());

    Path resolved = resolveCryptadPath(tempDir);

    assertEquals(script.toPath().normalize(), resolved.normalize());
  }

  @ParameterizedTest
  @MethodSource("classPathJarSamples")
  void findCryptadJarInClassPath_whenMatches_expectPath(String classPath, Path expected) {
    Path actual = findCryptadJarInClassPath(classPath);
    assertEquals(expected != null ? expected.normalize() : null, actual);
  }

  @Test
  void shellQuote_whenEmpty_expectTwoQuotes() {
    assertEquals("''", shellQuote(""));
  }

  @Test
  void shellQuote_whenContainsSingleQuote_expectEscaped() {
    assertEquals("'a'\"'\"'b'", shellQuote("a'b"));
  }

  @Test
  void findOnPath_whenExecutablePresent_expectResolvedPath() {
    String expected = findExecutableOnPathForSh();
    String actual = findOnPath("sh");
    assertEquals(expected, actual);
  }

  @Test
  void buildCryptadCommand_whenScriptAvailable_expectUsesScript(@TempDir Path tempDir) {
    AppEnv env = new AppEnv();
    Path cryptadPath = tempDir.resolve("cryptad");
    String script = findOnPath("script");

    List<String> actual = buildCryptadCommand(cryptadPath);

    if (env.isWindows() || script == null) {
      assertEquals(List.of(cryptadPath.toString()), actual);
    } else if (env.isLinux()) {
      assertEquals(
          List.of(script, "-q", "-c", "exec " + shellQuote(cryptadPath.toString()), "/dev/null"),
          actual);
    } else {
      assertEquals(List.of(script, "-q", "/dev/null", cryptadPath.toString()), actual);
    }
  }

  @Test
  void loadAppIconImage_whenFallbackPresent_expectImage() {
    assertNotNull(loadAppIconImage());
  }

  private String findExecutableOnPathForSh() {
    String path = System.getenv("PATH");
    if (path == null) {
      return null;
    }
    var separatorPattern =
        java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(File.pathSeparator));
    for (String dir : separatorPattern.split(path, 0)) {
      try {
        Path candidate = Paths.get(dir).resolve("sh");
        if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
          return candidate.toString();
        }
      } catch (Exception _) {
        // ignore malformed path segments
      }
    }
    return null;
  }

  static Stream<Arguments> classPathJarSamples() throws Exception {
    Path tempDir = Files.createTempDirectory("cp-jar-test-");
    Path cryptadJar = Files.createFile(tempDir.resolve("cryptad-1.jar"));
    Path otherJar = Files.createFile(tempDir.resolve("other.jar"));
    String sep = File.pathSeparator;

    return Stream.of(
        Arguments.of(otherJar + sep + cryptadJar, cryptadJar),
        Arguments.of(otherJar + sep + "/no/such/jar", null),
        Arguments.of("", null));
  }

  static Stream<Arguments> fproxyLineSamples() {
    return Stream.of(
        Arguments.of("Starting FProxy on 127.0.0.1:8888", 8888),
        Arguments.of("Starting FProxy on 127.0.0.1, [::1]:8080", 8080),
        Arguments.of("... Starting FProxy on [::1]:12345 ready", 12345));
  }
}
