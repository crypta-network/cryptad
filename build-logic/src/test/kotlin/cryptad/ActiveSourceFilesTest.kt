package cryptad

import groovy.json.JsonOutput
import java.net.URI
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class ActiveSourceFilesTest {
  @TempDir lateinit var root: Path

  @BeforeEach
  fun resolveOwnedFixtureRoot() {
    root = root.toRealPath()
  }

  @Test
  fun executableBit_whenProviderHasNoPosixModes_expectUnavailableRatherThanExecuteAccess() {
    val archive = root.resolve("provider.zip")
    FileSystems.newFileSystem(URI.create("jar:" + archive.toUri()), mapOf("create" to "true"))
      .use { fs ->
        val source = Files.writeString(fs.getPath("/source.java"), "abc")
        assertEquals(false, Files.getFileStore(source).supportsFileAttributeView("posix"))
        assertEquals(null, ActiveSourceFiles.executableBit(source))
      }
  }

  @Test
  fun trackedExecutableModes_whenIndexCarriesPortableBits_expectExactNamesAndRefuseAmbiguousStages() {
    val raw =
      "100644 ${"a".repeat(40)} 0\tsource space.java\u0000100755 ${"b".repeat(40)} 0\tnaïve/run.sh\u0000"
        .toByteArray()
    assertEquals(
      mapOf("source space.java" to false, "naïve/run.sh" to true),
      ActiveSourceFiles.trackedExecutableModes(raw),
    )
    for (invalid in
      listOf(
        raw + raw,
        "100755 ${"a".repeat(40)} 1\trun.sh\u0000".toByteArray(),
        "120000 ${"a".repeat(40)} 0\trun.sh\u0000".toByteArray(),
        raw.dropLast(1).toByteArray(),
      )) {
      assertThrows(IllegalArgumentException::class.java) {
        ActiveSourceFiles.trackedExecutableModes(invalid)
      }
    }
  }

  @Test
  fun repository_whenExportCarriesExecuteModes_expectPortableValidationAndExactRepackaging() {
    val source = Files.writeString(root.resolve("source.java"), "abc")
    val posix = Files.getFileStore(source).supportsFileAttributeView("posix")
    for (executable in listOf(false, true)) {
      if (posix)
        Files.setPosixFilePermissions(
          source,
          PosixFilePermissions.fromString(if (executable) "rwxr-xr-x" else "rw-r--r--"),
        )
      val record =
        sortedMapOf<String, Any>(
          "executable" to executable,
          "sha256" to
            MessageDigest.getInstance("SHA-256").digest("abc".toByteArray()).joinToString("") {
              "%02x".format(it)
            },
          "size" to 3,
        )
      val manifest =
        sortedMapOf(
          "files" to sortedMapOf("source.java" to record),
          "kind" to "cryptad-source-export",
          "schemaVersion" to 1,
          "sourceClass" to "working-source",
          "sourceCommit" to "a".repeat(40),
          "sourceTree" to "b".repeat(40),
        )
      val raw = JsonOutput.toJson(manifest) + "\n"
      Files.writeString(root.resolve(ActiveSourceFiles.SOURCE_ROSTER), raw)
      assertEquals(setOf("source.java"), ActiveSourceFiles.repository(root.toFile()))
      val output = root.resolve("build/export/roster.json").toFile()
      ActiveSourceFiles.writeRoster(root.toFile(), setOf("source.java"), output)
      assertEquals(raw, output.readText())
      if (posix) {
        // The archive must use the sealed mode even when host execute access differs.
        Files.setPosixFilePermissions(
          source,
          PosixFilePermissions.fromString(if (executable) "rw-r--r--" else "rwxr-xr-x"),
        )
      }
      val archive = root.resolve("export.tgz").toFile()
      ActiveSourceFiles.writeArchive(root.toFile(), setOf("source.java"), output, archive, "export")
      ActiveSourceFiles.verifyArchive(archive, output, "export")
      if (posix) {
        assertThrows(IllegalArgumentException::class.java) {
          ActiveSourceFiles.repository(root.toFile())
        }
      }
    }
  }

  @Test
  fun excludeUnselected_whenStaticOrGenerated_expectExactMembershipAndDeclaredGeneratedPreserved() {
    val history = Files.createDirectories(root.resolve("src/main/java/.stversions"))
    val tracked = Files.writeString(history.resolve("Tracked.java"), "class Tracked {}")
    val untracked = Files.writeString(history.resolve("Unselected.java"), "class Unselected {}")
    val selected = sortedSetOf("src/main/java/.stversions/Tracked.java")
    val ordinary =
      Files.writeString(root.resolve("src/main/java/Unlisted.java"), "class Unlisted {}")
    assertEquals(
      true,
      ActiveSourceFiles.excludeUnselected(root.toFile(), ordinary.toFile()) { selected },
    )
    assertEquals(
      false,
      ActiveSourceFiles.excludeUnselected(root.toFile(), root.resolve("src/main/java").toFile()) {
        selected
      },
    )
    assertEquals(
      false,
      ActiveSourceFiles.excludeUnselected(root.toFile(), history.toFile()) { selected },
    )
    assertEquals(
      false,
      ActiveSourceFiles.excludeUnselected(root.toFile(), tracked.toFile()) { selected },
    )
    assertEquals(
      true,
      ActiveSourceFiles.excludeUnselected(root.toFile(), untracked.toFile()) { selected },
    )
    assertEquals(
      false,
      ActiveSourceFiles.excludeUnselected(
        root.toFile(),
        root.resolve("build/generated/Version.java").toFile(),
        setOf(root.resolve("build/generated").toFile()),
      ) {
        error("Generated roots must not query history metadata")
      },
    )
  }

  @Test
  fun select_whenLocalHistoryIsUntracked_expectOnlyActiveSource() {
    Files.writeString(root.resolve("source.java"), "class Example {}")
    assertEquals(
      setOf("source.java"),
      ActiveSourceFiles.select(
        root.toFile(),
        "source.java\u0000".toByteArray(),
        ".stversions/source.java\u0000src/.stversions/history.java\u0000".toByteArray(),
      ),
    )
  }

  @Test
  fun select_whenHistoryNameIsTracked_expectExactMemberRetained() {
    Files.createDirectories(root.resolve(".stversions"))
    Files.writeString(root.resolve(".stversions/source.java"), "class Example {}")
    assertEquals(
      setOf(".stversions/source.java"),
      ActiveSourceFiles.select(
        root.toFile(),
        ".stversions/source.java\u0000".toByteArray(),
        byteArrayOf(),
      ),
    )
  }

  @Test
  fun select_whenMemberIsMissingOrEscapes_expectFailure() {
    for (name in
      listOf(
        "missing.java",
        "../outside.java",
        "/outside.java",
        "C:/outside.java",
        "a/../source.java",
      )) {
      assertThrows(IllegalArgumentException::class.java) {
        ActiveSourceFiles.select(root.toFile(), (name + '\u0000').toByteArray(), byteArrayOf())
      }
    }
  }

  @Test
  fun repository_whenRestrictedExportUsesProducerEncoding_expectExactBytesAndRejectDrift() {
    Files.writeString(root.resolve("source.java"), "abc")
    val record =
      sortedMapOf<String, Any>(
        "executable" to false,
        "sha256" to
          MessageDigest.getInstance("SHA-256").digest("abc".toByteArray()).joinToString("") {
            "%02x".format(it)
          },
        "size" to 3,
      )
    val manifest =
      sortedMapOf(
        "exportPolicy" to "production-without-test-seams-v1",
        "files" to sortedMapOf("source.java" to record),
        "kind" to "cryptad-restricted-installation",
        "schemaVersion" to 2,
        "sourceCommit" to "a".repeat(40),
      )
    val manifestPath = root.resolve(".restricted-manifest.json")
    // installation.plan() binds the compact JSON bytes without a trailing newline.
    val raw = JsonOutput.toJson(manifest)
    Files.writeString(manifestPath, raw)

    assertEquals(setOf("source.java"), ActiveSourceFiles.repository(root.toFile()))
    assertEquals(raw, Files.readString(manifestPath))
    for (invalid in listOf("$raw\n", " $raw", raw.replace("\"size\":3", "\"size\":3,\"size\":3"))) {
      Files.writeString(manifestPath, invalid)
      assertThrows(IllegalArgumentException::class.java) {
        ActiveSourceFiles.repository(root.toFile())
      }
    }
    Files.writeString(manifestPath, raw)
    Files.writeString(root.resolve("source.java"), "changed")
    assertThrows(IllegalArgumentException::class.java) {
      ActiveSourceFiles.repository(root.toFile())
    }
  }

  @Test
  fun repository_whenSourceExportLacksApprovedRoster_expectNoRecursiveFallback() {
    Files.writeString(root.resolve("source.java"), "class Example {}")
    assertThrows(IllegalArgumentException::class.java) {
      ActiveSourceFiles.repository(root.toFile())
    }
  }

  @Test
  fun select_whenPathEncodingIsInvalid_expectFailureWithoutReplacement() {
    assertThrows(java.nio.charset.CharacterCodingException::class.java) {
      ActiveSourceFiles.select(root.toFile(), byteArrayOf(0xc3.toByte(), 0x28, 0), byteArrayOf())
    }
  }

  @Test
  fun repository_whenFullSourceRosterBindsTests_expectExactFilesDespiteLocalHistory() {
    Files.writeString(root.resolve("ExampleTest.java"), "abc")
    val record =
      sortedMapOf<String, Any>(
        "executable" to false,
        "sha256" to
          MessageDigest.getInstance("SHA-256").digest("abc".toByteArray()).joinToString("") {
            "%02x".format(it)
          },
        "size" to 3,
      )
    val manifest =
      sortedMapOf(
        "files" to sortedMapOf("ExampleTest.java" to record),
        "kind" to "cryptad-source-export",
        "schemaVersion" to 1,
        "sourceClass" to "working-source",
        "sourceCommit" to "a".repeat(40),
        "sourceTree" to "b".repeat(40),
      )
    val roster = root.resolve(ActiveSourceFiles.SOURCE_ROSTER)
    Files.writeString(roster, JsonOutput.toJson(manifest))
    assertThrows(IllegalArgumentException::class.java) {
      ActiveSourceFiles.repository(root.toFile())
    }
    Files.writeString(roster, JsonOutput.toJson(manifest) + "\n")
    Files.createDirectories(root.resolve(".stversions"))
    Files.writeString(root.resolve(".stversions/stale.java"), "unselected")

    assertEquals(setOf("ExampleTest.java"), ActiveSourceFiles.repository(root.toFile()))
    val output = root.resolve("build/export/roster.json").toFile()
    ActiveSourceFiles.writeRoster(root.toFile(), setOf("ExampleTest.java"), output)
    assertEquals(Files.readString(root.resolve(ActiveSourceFiles.SOURCE_ROSTER)), output.readText())
    Files.delete(output.toPath())
    Files.createSymbolicLink(output.toPath(), root.resolve("ExampleTest.java"))
    assertThrows(IllegalArgumentException::class.java) {
      ActiveSourceFiles.writeRoster(root.toFile(), setOf("ExampleTest.java"), output)
    }
    assertEquals("abc", Files.readString(root.resolve("ExampleTest.java")))
  }

  @Test
  fun writeRoster_whenOwnedRootIsAliased_expectCanonicalFixtureWorksAndRawOutputRejected() {
    val real = Files.createDirectory(root.resolve("real"))
    val alias = Files.createSymbolicLink(root.resolve("alias"), real)
    val owned = alias.toRealPath()
    Files.writeString(owned.resolve("source.java"), "abc")
    val record =
      sortedMapOf<String, Any>(
        "executable" to false,
        "size" to 3,
        "sha256" to
          MessageDigest.getInstance("SHA-256").digest("abc".toByteArray()).joinToString("") {
            "%02x".format(it)
          },
      )
    val manifest =
      sortedMapOf(
        "files" to sortedMapOf("source.java" to record),
        "kind" to "cryptad-source-export",
        "schemaVersion" to 1,
        "sourceClass" to "working-source",
        "sourceCommit" to "a".repeat(40),
        "sourceTree" to "b".repeat(40),
      )
    Files.writeString(
      owned.resolve(ActiveSourceFiles.SOURCE_ROSTER),
      JsonOutput.toJson(manifest) + "\n",
    )
    assertThrows(IllegalArgumentException::class.java) {
      ActiveSourceFiles.writeRoster(
        owned.toFile(),
        setOf("source.java"),
        alias.resolve("build/roster.json").toFile(),
      )
    }
    val output = owned.resolve("build/roster.json").toFile()
    ActiveSourceFiles.writeRoster(owned.toFile(), setOf("source.java"), output)
    assertEquals(
      Files.readString(owned.resolve(ActiveSourceFiles.SOURCE_ROSTER)),
      output.readText(),
    )
  }

  @Test
  fun writeArchive_whenMembersAreEmptyOrSpanBuffersWithLongNames_expectExactBytesAndModes() {
    val longName = "nested/naïve space/${"long".repeat(30)}.bin"
    val bodies =
      sortedMapOf(
        "empty.txt" to byteArrayOf(),
        longName to ByteArray(2 * 65536 + 7) { (it % 251).toByte() },
      )
    val records = bodies.mapValues { (name, bytes) ->
      val path = root.resolve(name)
      Files.createDirectories(path.parent)
      Files.write(path, bytes)
      sortedMapOf(
        "executable" to (name == longName),
        "sha256" to
          MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it)
          },
        "size" to bytes.size,
      )
    }
    val manifest =
      sortedMapOf(
        "files" to records,
        "kind" to "cryptad-source-export",
        "schemaVersion" to 1,
        "sourceClass" to "working-source",
        "sourceCommit" to "a".repeat(40),
        "sourceTree" to "b".repeat(40),
      )
    val roster = root.resolve(ActiveSourceFiles.SOURCE_ROSTER).toFile()
    roster.writeText(JsonOutput.toJson(manifest) + "\n")
    val output = root.resolve("sources.tgz").toFile()

    ActiveSourceFiles.writeArchive(root.toFile(), bodies.keys, roster, output, "sources")

    val expected = bodies + (ActiveSourceFiles.SOURCE_ROSTER to roster.readBytes())
    val seen = mutableSetOf<String>()
    TarArchiveInputStream(BZip2CompressorInputStream(output.inputStream())).use { archive ->
      while (true) {
        val entry = archive.nextEntry ?: break
        val name = entry.name.removePrefix("sources/")
        val bytes = requireNotNull(expected[name])
        assertEquals(true, seen.add(name))
        assertEquals(bytes.size.toLong(), entry.size)
        assertEquals(name == longName, entry.mode and 73 != 0)
        assertArrayEquals(bytes, archive.readBytes())
      }
    }
    assertEquals(expected.keys, seen)
  }

  @Test
  fun verifyArchive_whenCopiedBytesOrRosterMembersDiffer_expectFailure() {
    val body = "abc".toByteArray()
    val record =
      sortedMapOf<String, Any>(
        "executable" to false,
        "size" to body.size,
        "sha256" to
          MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02x".format(it) },
      )
    val manifest =
      sortedMapOf(
        "files" to sortedMapOf("source.java" to record),
        "kind" to "cryptad-source-export",
        "schemaVersion" to 1,
        "sourceClass" to "working-source",
        "sourceCommit" to "a".repeat(40),
        "sourceTree" to "b".repeat(40),
      )
    val roster = root.resolve(ActiveSourceFiles.SOURCE_ROSTER).toFile()
    roster.writeText(JsonOutput.toJson(manifest) + "\n")
    val archive = root.resolve("sources.tgz").toFile()

    fun writeArchive(mode: String) {
      TarArchiveOutputStream(BZip2CompressorOutputStream(archive.outputStream())).use { output ->
        fun member(name: String, bytes: ByteArray) {
          val entry = TarArchiveEntry("sources/$name")
          entry.size = bytes.size.toLong()
          entry.mode = 420
          output.putArchiveEntry(entry)
          output.write(bytes)
          output.closeArchiveEntry()
        }
        member(ActiveSourceFiles.SOURCE_ROSTER, roster.readBytes())
        member("source.java", if (mode == "bytes") "abd".toByteArray() else body)
        if (mode == "history") member(".stversions/hidden.java", body)
        if (mode == "duplicate") member("source.java", body)
      }
    }

    writeArchive("valid")
    ActiveSourceFiles.verifyArchive(archive, roster, "sources")
    archive.appendBytes("unreferenced trailer".toByteArray())
    assertThrows(IllegalArgumentException::class.java) {
      ActiveSourceFiles.verifyArchive(archive, roster, "sources")
    }
    for (mode in listOf("bytes", "history", "duplicate")) {
      writeArchive(mode)
      assertThrows(IllegalArgumentException::class.java) {
        ActiveSourceFiles.verifyArchive(archive, roster, "sources")
      }
    }
  }
}
