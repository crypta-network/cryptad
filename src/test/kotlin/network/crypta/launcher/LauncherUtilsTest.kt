@file:Suppress("java:S100", "kotlin:S100")

package network.crypta.launcher

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.stream.Stream
import kotlin.io.path.createDirectories
import kotlin.io.path.createFile
import network.crypta.fs.AppEnv
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.MethodSource

@Suppress("java:S100", "kotlin:S100")
@SuppressWarnings("java:S100")
class LauncherUtilsTest {
  private var originalCp: String? = null

  @AfterEach
  fun restoreClassPath() {
    val cp = originalCp
    if (cp != null) {
      System.setProperty(CLASS_PATH_KEY, cp)
    }
  }

  @ParameterizedTest
  @MethodSource("fproxyLineSamples")
  fun parseFProxyPortFromLine_whenMatching_expectParsedPort(line: String, expected: Int) {
    val actual = parseFProxyPortFromLine(line)

    assertEquals(expected, actual)
  }

  @ParameterizedTest
  @CsvSource(
    "Nothing to see here",
    "Starting service on port abc",
    "Starting FProxy on 127.0.0.1:9",
  )
  fun parseFProxyPortFromLine_whenNoMatch_expectNull(line: String) {
    val actual = parseFProxyPortFromLine(line)

    assertNull(actual)
  }

  @Test
  fun parseWrapperProperties_whenMixedLines_expectKeyValueMap() {
    val lines =
      listOf(
        COMMENT_LINE,
        "",
        " wrapper.logfile = ../logs/wrapper.log ",
        "wrapper.logfile=./override.log",
        "wrapper.working.dir = ..",
      )

    val props = parseWrapperProperties(lines)

    assertEquals("./override.log", props["wrapper.logfile"])
    assertEquals("..", props["wrapper.working.dir"])
  }

  @Test
  fun upsertWrapperProperty_whenKeyExists_expectFirstOccurrenceReplaced() {
    val lines =
      listOf(COMMENT_LINE, WRAPPER_LOGFILE_OLD, "wrapper.logfile=second.log", WRAPPER_WORKDIR_LINE)

    val updated = upsertWrapperProperty(lines, "wrapper.logfile", "new.log")

    assertEquals(
      listOf(
        COMMENT_LINE,
        "wrapper.logfile=new.log",
        "wrapper.logfile=second.log",
        WRAPPER_WORKDIR_LINE,
      ),
      updated,
    )
  }

  @Test
  fun upsertWrapperProperty_whenMissing_expectAppended() {
    val lines = listOf(WRAPPER_LOGFILE_OLD)

    val updated = upsertWrapperProperty(lines, "wrapper.working.dir", "..")

    assertEquals(listOf(WRAPPER_LOGFILE_OLD, WRAPPER_WORKDIR_LINE), updated)
  }

  @Test
  fun computeWrapperLogPath_whenRelative_expectResolvedAgainstConfDir() {
    val conf = Paths.get(CONF_PATH)

    val actual = computeWrapperLogPath(conf, "../logs/wrapper.log")

    assertEquals(Paths.get("/opt/cryptad/logs/wrapper.log"), actual)
  }

  @Test
  fun computeWrapperLogPath_whenAbsolute_expectReturnedAsIs() {
    val conf = Paths.get(CONF_PATH)

    val actual = computeWrapperLogPath(conf, "/var/log/cryptad/wrapper.log")

    assertEquals(Paths.get("/var/log/cryptad/wrapper.log"), actual)
  }

  @Test
  fun computeWrapperFilePath_whenRelativeAndWorkingDirRelative_expectResolvedAgainstConfDir() {
    val conf = Paths.get(CONF_PATH)

    val actual = computeWrapperFilePath(conf, "Cryptad.anchor", "..")

    assertEquals(Paths.get("/opt/cryptad/Cryptad.anchor"), actual)
  }

  @Test
  fun computeWrapperFilePath_whenRelativeAndWorkingDirAbsolute_expectResolvedAgainstWorkingDir() {
    val conf = Paths.get(CONF_PATH)

    val actual = computeWrapperFilePath(conf, "Cryptad.anchor", "/var/lib/cryptad")

    assertEquals(Paths.get("/var/lib/cryptad/Cryptad.anchor"), actual)
  }

  @Test
  fun computeWrapperFilePath_whenAbsoluteSpec_expectReturnedAsIs() {
    val conf = Paths.get(CONF_PATH)

    val actual = computeWrapperFilePath(conf, "/var/lib/cryptad/cryptad.anchor", "..")

    assertEquals(Paths.get("/var/lib/cryptad/cryptad.anchor"), actual)
  }

  @Test
  fun computeWrapperFilePath_whenBlankSpec_expectNull() {
    val conf = Paths.get(CONF_PATH)

    val actual = computeWrapperFilePath(conf, "  ", "..")

    assertNull(actual)
  }

  @Test
  fun scanWrapperConfPath_whenConfAssignmentPresent_expectParsedPath() {
    val lines = listOf("CONF=\"$CONF_PATH\"")

    val actual = scanWrapperConfPath(lines)

    assertEquals(Paths.get(CONF_PATH), actual)
  }

  @Test
  fun scanWrapperConfPath_whenCFlagPresent_expectParsedPath() {
    val lines = listOf("exec wrapper -c \"$CONF_PATH\"")

    val actual = scanWrapperConfPath(lines)

    assertEquals(Paths.get(CONF_PATH), actual)
  }

  @Test
  fun scanWrapperConfPath_whenNotPresent_expectNull() {
    val lines = listOf("echo nothing here")

    val actual = scanWrapperConfPath(lines)

    assertNull(actual)
  }

  @Test
  fun guessWrapperConfPathForCryptadScript_whenDefaultExists_expectDefault(@TempDir tempDir: Path) {
    val binDir = tempDir.resolve("bin").createDirectories()
    val confDir = tempDir.resolve("conf").createDirectories()
    val defaultConf = confDir.resolve("wrapper.conf").createFile()
    val script = binDir.resolve("cryptad").createFile()
    Files.writeString(script, "CONF=\"/tmp/other.conf\"\n")

    val actual = guessWrapperConfPathForCryptadScript(script)

    assertEquals(defaultConf.normalize(), actual)
  }

  @Test
  fun guessWrapperConfPathForCryptadScript_whenScriptOverrides_expectParsedPath(
    @TempDir tempDir: Path
  ) {
    val binDir = tempDir.resolve("bin").createDirectories()
    val script = binDir.resolve("cryptad").createFile()
    val overridePath = tempDir.resolve("alt/wrapper.conf")
    Files.writeString(script, "CONF=\"${overridePath}\"\n")

    val actual = guessWrapperConfPathForCryptadScript(script)

    assertEquals(overridePath.normalize(), actual)
  }

  @Test
  fun guessWrapperConfPathForCryptadScript_whenScriptMissing_expectDefault(@TempDir tempDir: Path) {
    val binDir = tempDir.resolve("bin").createDirectories()
    val script = binDir.resolve("cryptad")
    val expected = binDir.resolve("../conf/wrapper.conf").normalize()

    val actual = guessWrapperConfPathForCryptadScript(script)

    assertEquals(expected, actual)
  }

  @Test
  fun resolveCryptadPathWithEnv_whenAbsoluteOverride_expectNormalized(@TempDir tempDir: Path) {
    val overrideFile = tempDir.resolve("cryptad").createFile().toFile()

    val resolved =
      resolveCryptadPathWithEnv(tempDir, mapOf(CRYPTAD_PATH_ENV to overrideFile.absolutePath))

    assertEquals(overrideFile.toPath().normalize(), resolved.normalize())
  }

  @Test
  fun resolveCryptadPathWithEnv_whenRelativeOverride_expectResolvedAgainstCwd(
    @TempDir tempDir: Path
  ) {
    val rel = "rel/bin/cryptad"
    val target = tempDir.resolve(rel)
    target.parent.createDirectories()
    target.createFile().toFile()

    val resolved = resolveCryptadPathWithEnv(tempDir, mapOf(CRYPTAD_PATH_ENV to rel))

    assertEquals(target.normalize(), resolved.normalize())
  }

  @Test
  fun resolveCryptadPath_whenJarSiblingBinExists_expectBinScript(@TempDir tempDir: Path) {
    assumeFalse(AppEnv().isWindows())
    originalCp = System.getProperty(CLASS_PATH_KEY)

    val lib = tempDir.resolve("lib").createDirectories()
    val bin = tempDir.resolve("bin").createDirectories()
    val jar = lib.resolve("cryptad.jar").createFile()
    val script = bin.resolve("cryptad").createFile().toFile()
    assertTrue(script.setExecutable(true))
    System.setProperty(CLASS_PATH_KEY, jar.toString())

    val resolved = resolveCryptadPath(Paths.get("/does/not/matter"))

    assertEquals(script.toPath().normalize(), resolved.normalize())
  }

  @Test
  fun resolveCryptadPath_whenJarSameDirExists_expectLocalScript(@TempDir tempDir: Path) {
    assumeFalse(AppEnv().isWindows())
    originalCp = System.getProperty(CLASS_PATH_KEY)

    val lib = tempDir.resolve("lib").createDirectories()
    val jar = lib.resolve("cryptad.jar").createFile()
    val script = lib.resolve("cryptad").createFile().toFile()
    assertTrue(script.setExecutable(true))
    System.setProperty(CLASS_PATH_KEY, jar.toString())

    val resolved = resolveCryptadPath(Paths.get("/irrelevant"))

    assertEquals(script.toPath().normalize(), resolved.normalize())
  }

  @Test
  fun resolveCryptadPath_whenJarMissing_expectCwdFallback(@TempDir tempDir: Path) {
    assumeFalse(AppEnv().isWindows())
    originalCp = System.getProperty(CLASS_PATH_KEY)

    val bin = tempDir.resolve("bin").createDirectories()
    val script = bin.resolve("cryptad").createFile().toFile()
    assertTrue(script.setExecutable(true))
    System.setProperty(CLASS_PATH_KEY, Paths.get("/no/jar/here").toString())

    val resolved = resolveCryptadPath(tempDir)

    assertEquals(script.toPath().normalize(), resolved.normalize())
  }

  @ParameterizedTest
  @MethodSource("classPathJarSamples")
  fun findCryptadJarInClassPath_whenMatches_expectPath(classPath: String, expected: Path?) {
    val actual = findCryptadJarInClassPath(classPath)

    assertEquals(expected?.normalize(), actual)
  }

  @Test
  fun shellQuote_whenEmpty_expectTwoQuotes() {
    val actual = shellQuote("")

    assertEquals("''", actual)
  }

  @Test
  fun shellQuote_whenContainsSingleQuote_expectEscaped() {
    val actual = shellQuote("a'b")

    assertEquals("'a'\"'\"'b'", actual)
  }

  @Test
  fun findOnPath_whenExecutablePresent_expectResolvedPath() {
    val expected = findExecutableOnPathForSh()

    val actual = findOnPath("sh")

    assertEquals(expected, actual)
  }

  @Test
  fun buildCryptadCommand_whenScriptAvailable_expectUsesScript(@TempDir tempDir: Path) {
    val env = AppEnv()
    val cryptadPath = tempDir.resolve("cryptad")
    val script = findOnPath("script")

    val actual = buildCryptadCommand(cryptadPath)

    if (env.isWindows() || script == null) {
      assertEquals(listOf(cryptadPath.toString()), actual)
    } else if (env.isLinux()) {
      assertEquals(
        listOf(script, "-q", "-c", "exec ${shellQuote(cryptadPath.toString())}", "/dev/null"),
        actual,
      )
    } else {
      assertEquals(listOf(script, "-q", "/dev/null", cryptadPath.toString()), actual)
    }
  }

  @Test
  fun loadAppIconImage_whenFallbackPresent_expectImage() {
    val image = loadAppIconImage()

    assertNotNull(image)
  }

  private fun findExecutableOnPathForSh(): String? {
    val path = System.getenv("PATH") ?: return null
    return path
      .split(java.io.File.pathSeparator)
      .firstOrNull { dir ->
        try {
          val candidate = Paths.get(dir).resolve("sh")
          Files.isRegularFile(candidate) && Files.isExecutable(candidate)
        } catch (_: Exception) {
          false
        }
      }
      ?.let { Paths.get(it).resolve("sh").toString() }
  }

  companion object {
    private const val CLASS_PATH_KEY = "java.class.path"
    private const val COMMENT_LINE = "# comment"
    private const val WRAPPER_LOGFILE_OLD = "wrapper.logfile=old.log"
    private const val WRAPPER_WORKDIR_LINE = "wrapper.working.dir=.."
    private const val CONF_PATH = "/opt/cryptad/conf/wrapper.conf"

    @JvmStatic
    fun classPathJarSamples(): Stream<Arguments> {
      val tempDir = Files.createTempDirectory("cp-jar-test-")
      val cryptadJar = tempDir.resolve("cryptad-1.jar").createFile()
      val otherJar = tempDir.resolve("other.jar").createFile()
      val sep = java.io.File.pathSeparator

      return Stream.of(
        Arguments.of("${otherJar}${sep}${cryptadJar}", cryptadJar),
        Arguments.of("${otherJar}${sep}/no/such/jar", null),
        Arguments.of("", null),
      )
    }

    @JvmStatic
    fun fproxyLineSamples(): Stream<Arguments> =
      Stream.of(
        Arguments.of("Starting FProxy on 127.0.0.1:8888", 8888),
        Arguments.of("Starting FProxy on 127.0.0.1, [::1]:8080", 8080),
        Arguments.of("... Starting FProxy on [::1]:12345 ready", 12345),
      )
  }
}
