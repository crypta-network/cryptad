package cryptad

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.LocalDateTime
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Writes the minimal, metadata-stable bootstrap JAR required by jpackage. */
internal object DeterministicBootstrapJar {
  private const val MANIFEST_PATH = "META-INF/MANIFEST.MF"
  private val manifestBytes = "Manifest-Version: 1.0\r\n\r\n".toByteArray(StandardCharsets.UTF_8)
  // Use the earliest DOS timestamp that Java can encode without synthesizing an extended-time
  // extra field. DOS ZIP timestamps have a two-second resolution.
  private val zipEpoch = LocalDateTime.of(1980, 1, 1, 0, 0, 2)

  /** Writes a bootstrap JAR whose bytes do not depend on the build time or host time zone. */
  fun write(output: Path) {
    output.parent?.let(Files::createDirectories)
    val crc = CRC32().apply { update(manifestBytes) }.value
    Files.newOutputStream(output).buffered().use { fileOutput ->
      ZipOutputStream(fileOutput, StandardCharsets.UTF_8).use { jarOutput ->
        val manifestEntry =
          ZipEntry(MANIFEST_PATH).apply {
            method = ZipEntry.STORED
            size = manifestBytes.size.toLong()
            compressedSize = manifestBytes.size.toLong()
            setCrc(crc)
            setTimeLocal(zipEpoch)
            extra = ByteArray(0)
          }
        jarOutput.putNextEntry(manifestEntry)
        jarOutput.write(manifestBytes)
        jarOutput.closeEntry()
      }
    }
  }
}
