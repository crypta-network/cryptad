package cryptad

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.Comparator
import java.util.Locale
import java.util.zip.Deflater
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.archivers.tar.TarConstants
import org.apache.commons.compress.archivers.zip.Zip64Mode
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream
import org.apache.commons.compress.archivers.zip.ZipFile
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream
import org.apache.commons.compress.compressors.gzip.GzipParameters

/**
 * Rewrites Gradle distribution archives with the metadata required by the Stable release archive
 * gate. The implementation runs on Gradle's Java toolchain and intentionally has no external
 * interpreter or operating-system command dependency.
 */
object PortableArchiveNormalizer {
  private const val FILE_TYPE_MASK = 0xF000
  private const val REGULAR_FILE_TYPE = 0x8000
  private const val DIRECTORY_TYPE = 0x4000
  private const val FILE_MODE = 0x1A4 // 0644
  private const val EXECUTABLE_MODE = 0x1ED // 0755
  private const val SYMLINK_MODE = 0x1FF // 0777
  private const val COPY_BUFFER_SIZE = 1024 * 1024

  /** Normalizes one `.tar.gz`, `.tgz`, `.tar`, or `.zip` archive in place. */
  fun normalize(archive: Path) {
    val source = archive.toAbsolutePath().normalize()
    require(Files.isRegularFile(source)) { "Portable archive is not a regular file: $source" }
    val fileName = source.fileName.toString().lowercase(Locale.ROOT)
    when {
      fileName.endsWith(".tar.gz") || fileName.endsWith(".tgz") -> normalizeTar(source, true)
      fileName.endsWith(".tar") -> normalizeTar(source, false)
      fileName.endsWith(".zip") -> normalizeZip(source)
      else -> throw IllegalArgumentException("Unsupported portable archive: ${source.fileName}")
    }
  }

  /** Returns the deterministic Unix permissions for one portable archive file member. */
  fun unixPermissionsForMember(memberName: String): String =
    if (isExecutableMember(safeMemberName(memberName))) "0755" else "0644"

  private fun normalizeTar(source: Path, compressed: Boolean) {
    val staging = Files.createTempDirectory(source.parent, ".archive-normalize-")
    val replacement = Files.createTempFile(source.parent, ".${source.fileName}.", ".tmp")
    try {
      val entries = readTarEntries(source, staging, compressed)
      BufferedOutputStream(Files.newOutputStream(replacement)).use { rawOutput ->
        val archiveOutput =
          if (compressed) {
            val parameters =
              GzipParameters().apply {
                compressionLevel = Deflater.BEST_COMPRESSION
                modificationTime = 0
                operatingSystem = GzipParameters.OS.UNKNOWN.type()
              }
            GzipCompressorOutputStream(rawOutput, parameters)
          } else {
            rawOutput
          }
        archiveOutput.use { encodedOutput ->
          TarArchiveOutputStream(encodedOutput).use { output ->
            output.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
            output.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX)
            output.setAddPaxHeadersForNonAsciiNames(true)
            entries.sortedBy(TarStagedEntry::name).forEach { writeTarEntry(output, it) }
          }
        }
      }
      replace(source, replacement)
    } finally {
      Files.deleteIfExists(replacement)
      deleteTree(staging)
    }
  }

  private fun readTarEntries(
    source: Path,
    staging: Path,
    compressed: Boolean,
  ): List<TarStagedEntry> {
    val entries = mutableListOf<TarStagedEntry>()
    val names = mutableSetOf<String>()
    BufferedInputStream(Files.newInputStream(source)).use { rawInput ->
      val archiveInput = if (compressed) GzipCompressorInputStream(rawInput) else rawInput
      archiveInput.use { decodedInput ->
        TarArchiveInputStream(decodedInput).use { input ->
          var entry = input.nextEntry
          while (entry != null) {
            if (!input.canReadEntryData(entry)) {
              throw IOException("Portable tar member cannot be read: ${entry.name}")
            }
            val name = safeMemberName(entry.name)
            require(names.add(name)) { "Portable tar contains duplicate member: $name" }
            val staged =
              when {
                entry.isFile -> stageTarFile(input, entry, name, staging, entries.size)
                entry.isDirectory ->
                  TarStagedEntry(name, TarEntryKind.DIRECTORY, normalizedMode(name, true))
                entry.isSymbolicLink -> {
                  val linkName = safeMemberName(entry.linkName)
                  require(safeSymlinkTarget(name, linkName)) {
                    "Portable tar symlink escapes its root: $name"
                  }
                  TarStagedEntry(name, TarEntryKind.SYMLINK, SYMLINK_MODE, linkName = linkName)
                }
                else -> throw IOException("Portable tar contains special member: $name")
              }
            entries.add(staged)
            entry = input.nextEntry
          }
        }
      }
    }
    return entries
  }

  private fun stageTarFile(
    input: TarArchiveInputStream,
    entry: TarArchiveEntry,
    name: String,
    staging: Path,
    index: Int,
  ): TarStagedEntry {
    require(entry.size >= 0) { "Portable tar member has an invalid size: $name" }
    val payload = staging.resolve(index.toString())
    Files.newOutputStream(payload).use { output -> input.copyTo(output, COPY_BUFFER_SIZE) }
    val actualSize = Files.size(payload)
    require(actualSize == entry.size) {
      "Portable tar member size changed while reading $name: expected ${entry.size}, got $actualSize"
    }
    return TarStagedEntry(
      name,
      TarEntryKind.FILE,
      normalizedMode(name, false),
      actualSize,
      payload,
    )
  }

  private fun writeTarEntry(output: TarArchiveOutputStream, staged: TarStagedEntry) {
    val flag =
      when (staged.kind) {
        TarEntryKind.FILE -> TarConstants.LF_NORMAL
        TarEntryKind.DIRECTORY -> TarConstants.LF_DIR
        TarEntryKind.SYMLINK -> TarConstants.LF_SYMLINK
      }
    val entry =
      TarArchiveEntry(staged.name, flag).apply {
        setModTime(0L)
        userId = 0
        groupId = 0
        userName = "root"
        groupName = "root"
        mode = staged.mode
        size = staged.size
        if (staged.linkName != null) {
          linkName = staged.linkName
        }
      }
    output.putArchiveEntry(entry)
    if (staged.payload != null) {
      Files.newInputStream(staged.payload).use { input -> input.copyTo(output, COPY_BUFFER_SIZE) }
    }
    output.closeArchiveEntry()
  }

  private fun normalizeZip(source: Path) {
    val replacement = Files.createTempFile(source.parent, ".${source.fileName}.", ".tmp")
    try {
      ZipFile.builder().setPath(source).get().use { input ->
        val entries = input.entries.asSequence().toList()
        val namedEntries = entries.associateBy { safeMemberName(it.name) }
        require(namedEntries.size == entries.size) { "Portable ZIP contains duplicate members" }
        ZipArchiveOutputStream(replacement.toFile()).use { output ->
          output.setEncoding("UTF-8")
          output.setFallbackToUTF8(false)
          output.setUseLanguageEncodingFlag(true)
          output.setCreateUnicodeExtraFields(ZipArchiveOutputStream.UnicodeExtraFieldPolicy.NEVER)
          output.setUseZip64(Zip64Mode.AsNeeded)
          output.setMethod(ZipArchiveOutputStream.DEFLATED)
          output.setLevel(Deflater.BEST_COMPRESSION)
          output.setComment("")
          namedEntries.toSortedMap().forEach { (name, original) ->
            writeZipEntry(input, output, name, original)
          }
        }
      }
      replace(source, replacement)
    } finally {
      Files.deleteIfExists(replacement)
    }
  }

  private fun writeZipEntry(
    input: ZipFile,
    output: ZipArchiveOutputStream,
    name: String,
    original: ZipArchiveEntry,
  ) {
    require(input.canReadEntryData(original)) { "Portable ZIP member cannot be read: $name" }
    require(!original.isUnixSymlink) { "Portable ZIP contains a symlink: $name" }
    val directory = original.isDirectory
    val fileType = original.unixMode and FILE_TYPE_MASK
    require(fileType == 0 || fileType == REGULAR_FILE_TYPE || fileType == DIRECTORY_TYPE) {
      "Portable ZIP contains special member: $name"
    }
    require(directory || fileType != DIRECTORY_TYPE) {
      "Portable ZIP member type does not match its name: $name"
    }
    require(original.size >= 0 && (!directory || original.size == 0L)) {
      "Portable ZIP member has an invalid size: $name"
    }
    val entryName = if (directory) "$name/" else name
    val entry =
      ZipArchiveEntry(entryName).apply {
        setTime(zipEpochMillis())
        setUnixMode(
          (if (directory) DIRECTORY_TYPE else REGULAR_FILE_TYPE) or
            normalizedMode(name, directory)
        )
        method = ZipArchiveOutputStream.DEFLATED
        comment = ""
        extra = byteArrayOf()
        if (!directory) {
          size = original.size
        }
      }
    output.putArchiveEntry(entry)
    if (!directory) {
      input.getInputStream(original).use { content -> content.copyTo(output, COPY_BUFFER_SIZE) }
    }
    output.closeArchiveEntry()
  }

  private fun normalizedMode(memberName: String, directory: Boolean): Int =
    if (directory || isExecutableMember(memberName)) EXECUTABLE_MODE else FILE_MODE

  private fun isExecutableMember(memberName: String): Boolean {
    val normalized = memberName.lowercase(Locale.ROOT)
    val executableBinMember =
      normalized.startsWith("bin/") &&
        !normalized.endsWith(".bat") &&
        !normalized.endsWith(".exe")
    return executableBinMember ||
      normalized == "lib/jexec" ||
      normalized == "lib/jspawnhelper" ||
      normalized.startsWith("lib/libwrapper-linux-") ||
      normalized.startsWith("lib/libwrapper-macosx-")
  }

  private fun safeMemberName(value: String): String {
    val normalized = value.replace('\\', '/').trimEnd('/')
    val parts = normalized.split('/')
    require(normalized.isNotEmpty()) { "Portable archive contains an empty member name" }
    require(!normalized.startsWith('/') && !normalized.startsWith("//")) {
      "Portable archive contains an absolute member: $value"
    }
    require(!DRIVE_PATH.containsMatchIn(normalized)) {
      "Portable archive contains a Windows-absolute member: $value"
    }
    require(parts.none { it == ".." }) { "Portable archive member traverses its root: $value" }
    require(parts.none { it == "__MACOSX" || it == ".DS_Store" || it.startsWith("._") }) {
      "Portable archive contains forbidden metadata: $value"
    }
    return normalized
  }

  private fun safeSymlinkTarget(memberName: String, linkName: String): Boolean {
    if (linkName.startsWith('/') || DRIVE_PATH.containsMatchIn(linkName)) {
      return false
    }
    val resolved = mutableListOf<String>()
    resolved.addAll(memberName.substringBeforeLast('/', "").split('/').filter(String::isNotEmpty))
    for (part in linkName.split('/')) {
      when (part) {
        "", "." -> Unit
        ".." -> if (resolved.isEmpty()) return false else resolved.removeLast()
        else -> resolved.add(part)
      }
    }
    return true
  }

  private fun zipEpochMillis(): Long =
    LocalDateTime.of(1980, 1, 1, 0, 0).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()

  private fun replace(source: Path, replacement: Path) {
    makeDistributionArchiveReadable(replacement)
    try {
      Files.move(
        replacement,
        source,
        StandardCopyOption.ATOMIC_MOVE,
        StandardCopyOption.REPLACE_EXISTING,
      )
    } catch (_: AtomicMoveNotSupportedException) {
      Files.move(replacement, source, StandardCopyOption.REPLACE_EXISTING)
    }
  }

  private fun makeDistributionArchiveReadable(archive: Path) {
    val posixView = Files.getFileAttributeView(archive, PosixFileAttributeView::class.java)
    if (posixView != null) {
      posixView.setPermissions(PosixFilePermissions.fromString("rw-r--r--"))
      return
    }

    val file = archive.toFile()
    check(file.setReadable(true, false) || file.canRead()) {
      "Cannot make normalized distribution archive readable: $archive"
    }
    check(file.setWritable(true, true) || file.canWrite()) {
      "Cannot make normalized distribution archive owner-writable: $archive"
    }
  }

  private fun deleteTree(root: Path) {
    if (!Files.exists(root)) return
    Files.walk(root).use { paths ->
      paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
    }
  }

  private enum class TarEntryKind {
    FILE,
    DIRECTORY,
    SYMLINK,
  }

  private data class TarStagedEntry(
    val name: String,
    val kind: TarEntryKind,
    val mode: Int,
    val size: Long = 0,
    val payload: Path? = null,
    val linkName: String? = null,
  )

  private val DRIVE_PATH = Regex("^[A-Za-z]:")
}
