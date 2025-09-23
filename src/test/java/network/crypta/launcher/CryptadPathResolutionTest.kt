package network.crypta.launcher

import java.nio.file.Files
import java.nio.file.Paths
import kotlin.io.path.createDirectories
import kotlin.io.path.createFile
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CryptadPathResolutionTest {
  private var originalCp: String? = null

  @Before
  fun saveCp() {
    originalCp = System.getProperty("java.class.path")
  }

  @After
  fun restoreCp() {
    if (originalCp != null) System.setProperty("java.class.path", originalCp)
  }

  @Test
  fun resolvesFromJarSiblingBin() {
    val root = Files.createTempDirectory("cryptad-dist-test-")
    val lib = root.resolve("lib").createDirectories()
    val bin = root.resolve("bin").createDirectories()
    val jar = lib.resolve("cryptad.jar").createFile()
    val script = bin.resolve("cryptad").createFile().toFile()
    script.setExecutable(true)

    // Force classpath scan to find our fake jar
    System.setProperty("java.class.path", jar.toString())

    val resolved = resolveCryptadPath(Paths.get("/does/not/matter"))
    assertEquals(script.toPath().normalize(), resolved.normalize())
  }

  @Test
  fun resolvesFromJarSameDir() {
    val root = Files.createTempDirectory("cryptad-dist-test2-")
    val lib = root.resolve("lib").createDirectories()
    val jar = lib.resolve("cryptad.jar").createFile()
    val script = lib.resolve("cryptad").createFile().toFile()
    script.setExecutable(true)

    System.setProperty("java.class.path", jar.toString())

    val resolved = resolveCryptadPath(Paths.get("/irrelevant"))
    assertEquals(script.toPath().normalize(), resolved.normalize())
  }

  @Test
  fun fallsBackToCwd() {
    val cwd = Files.createTempDirectory("cryptad-cwd-")
    val bin = cwd.resolve("bin")
    Files.createDirectories(bin)
    val script = bin.resolve("cryptad").createFile().toFile()
    script.setExecutable(true)

    // Ensure classpath scan won't find a jar
    System.setProperty("java.class.path", Paths.get("/no/jar/here").toString())

    val resolved = resolveCryptadPath(cwd)
    assertTrue(Files.isRegularFile(resolved))
    assertEquals(script.toPath().normalize(), resolved.normalize())
  }

  @Test
  fun envAbsoluteOverride() {
    val cwd = Files.createTempDirectory("cryptad-env-abs-")
    val overrideFile = Files.createTempFile("cryptad-env-target-", "").toFile()
    overrideFile.setExecutable(true)

    val env = mapOf(CRYPTAD_PATH_ENV to overrideFile.absolutePath)
    val resolved = resolveCryptadPathWithEnv(cwd, env)
    assertEquals(overrideFile.toPath().normalize(), resolved.normalize())
  }

  @Test
  fun envRelativeOverrideResolvesAgainstCwd() {
    val cwd = Files.createTempDirectory("cryptad-env-rel-")
    val rel = "rel/bin/mycryptad"
    val target = cwd.resolve(rel)
    Files.createDirectories(target.parent)
    target.toFile().createNewFile()
    target.toFile().setExecutable(true)

    val env = mapOf(CRYPTAD_PATH_ENV to rel)
    val resolved = resolveCryptadPathWithEnv(cwd, env)
    assertEquals(target.normalize(), resolved.normalize())
  }
}
