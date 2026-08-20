package cryptad

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.time.LocalDateTime
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class DeterministicBootstrapJarTest {
  @TempDir lateinit var tempDirectory: java.nio.file.Path

  @Test
  fun write_whenInvokedRepeatedly_expectByteIdenticalJarWithFixedMetadata() {
    val first = tempDirectory.resolve("first.jar")
    val second = tempDirectory.resolve("second.jar")

    DeterministicBootstrapJar.write(first)
    DeterministicBootstrapJar.write(second)

    assertArrayEquals(Files.readAllBytes(first), Files.readAllBytes(second))
    ZipFile(first.toFile(), StandardCharsets.UTF_8).use { jar ->
      val entries = jar.entries().asSequence().toList()
      assertEquals(1, entries.size)
      val manifest = entries.single()
      assertEquals("META-INF/MANIFEST.MF", manifest.name)
      assertEquals(ZipEntry.STORED, manifest.method)
      assertEquals(LocalDateTime.of(1980, 1, 1, 0, 0, 2), manifest.timeLocal)
      assertEquals(0, manifest.extra?.size ?: 0)
      assertNull(manifest.comment)
      assertEquals(
        "Manifest-Version: 1.0\r\n\r\n",
        jar.getInputStream(manifest).bufferedReader(StandardCharsets.UTF_8).use { it.readText() },
      )
    }
  }
}
