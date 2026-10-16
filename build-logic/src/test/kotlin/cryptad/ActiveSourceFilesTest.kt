package cryptad

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.net.URI
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
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
  fun repository_whenTrackedMembersAreDeleted_expectCurrentWorkingRoster() {
    git("init", "--quiet")
    Files.writeString(root.resolve("source.java"), "class Example {}")
    Files.createDirectory(root.resolve(".stversions"))
    Files.writeString(root.resolve(".stversions/kept.kt"), "class Kept")
    val deleted = listOf("deleted space é.kt", ".stversions/deleted.kt")
    deleted.forEach { Files.writeString(root.resolve(it), "class Deleted") }
    git("add", ".")
    deleted.forEach { Files.delete(root.resolve(it)) }
    Files.writeString(root.resolve("new source.kt"), "class NewSource")
    Files.writeString(root.resolve(".stversions/untracked.kt"), "invalid historical source")
    val expected = setOf("source.java", ".stversions/kept.kt", "new source.kt")

    assertEquals(expected, ActiveSourceFiles.repository(root.toFile()))
    git("add", "--update")
    assertEquals(expected, ActiveSourceFiles.repository(root.toFile()))
  }

  @Test
  fun writeRoster_whenOnlyExcludedHistoryIsUntracked_expectIdenticalCommittedManifest() {
    committedFixture()
    val clean = writeRepositoryRoster()
    assertEquals("committed-source", (JsonSlurper().parse(clean) as Map<*, *>)["sourceClass"])
    for (name in listOf(".stversions/archived.java", "nested/.stversions/archived.kt")) {
      val path = root.resolve(name)
      Files.createDirectories(path.parent)
      Files.writeString(path, "unselected historical source")
    }

    assertArrayEquals(clean, writeRepositoryRoster())
  }

  @Test
  fun writeRoster_whenSelectedUntrackedFileIsAdded_expectWorkingSourceBeforeAndAfterStaging() {
    committedFixture()
    Files.writeString(root.resolve("new source é.kt"), "class NewSource")

    for (staged in listOf(false, true)) {
      if (staged) git("add", "new source é.kt")
      val manifest = JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>
      assertEquals("working-source", manifest["sourceClass"])
      assertEquals(
        setOf("source.java", ".stversions/kept.kt", "new source é.kt"),
        (manifest["files"] as Map<*, *>).keys,
      )
    }
  }

  @Test
  fun writeRoster_whenTrackedHistoryChanges_expectWorkingSourceBeforeAndAfterStaging() {
    committedFixture()
    val source = root.resolve(".stversions/kept.kt")
    Files.writeString(source, "class Changed")

    for (staged in listOf(false, true)) {
      if (staged) git("add", "--update")
      assertEquals(
        "working-source",
        (JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>)["sourceClass"],
      )
    }
    Files.delete(source)
    for (staged in listOf(false, true)) {
      if (staged) git("add", "--update")
      val manifest = JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>
      assertEquals("working-source", manifest["sourceClass"])
      assertEquals(setOf("source.java"), (manifest["files"] as Map<*, *>).keys)
    }
  }

  @Test
  fun writeRoster_whenIndexFlagsHideSourceState_expectRejectionUntilFlagsAreCleared() {
    committedFixture()
    val source = root.resolve("source.java")
    val original = Files.readAllBytes(source)
    for (flag in listOf("--assume-unchanged", "--skip-worktree")) {
      git("update-index", flag, "--", "source.java")
      assertThrows(IllegalArgumentException::class.java) { writeRepositoryRoster() }
      Files.writeString(source, "class Changed {}")
      assertThrows(IllegalArgumentException::class.java) { writeRepositoryRoster() }
      Files.delete(source)
      assertThrows(IllegalArgumentException::class.java) { writeRepositoryRoster() }

      git("update-index", "--no-assume-unchanged", "--", "source.java")
      git("update-index", "--no-skip-worktree", "--", "source.java")
      val deleted = JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>
      assertEquals("working-source", deleted["sourceClass"])
      assertEquals(setOf(".stversions/kept.kt"), (deleted["files"] as Map<*, *>).keys)
      Files.writeString(source, "class Changed {}")
      assertEquals(
        "working-source",
        (JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>)["sourceClass"],
      )
      Files.write(source, original)
      assertEquals(
        "committed-source",
        (JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>)["sourceClass"],
      )
    }
  }

  @Test
  fun writeRoster_whenBothHiddenIndexFlagsAreSet_expectRejection() {
    committedFixture()
    git("update-index", "--assume-unchanged", "--", "source.java")
    git("update-index", "--skip-worktree", "--", "source.java")
    Files.writeString(root.resolve("source.java"), "class Changed {}")

    assertThrows(IllegalArgumentException::class.java) { writeRepositoryRoster() }
  }

  @Test
  fun writeRoster_whenGitIgnoresExecuteModes_expectPortableHostComparison() {
    committedFixture()
    val source = root.resolve("source.java")
    val posix = Files.getFileStore(source).supportsFileAttributeView("posix")
    git("config", "core.filemode", "false")
    for (indexed in listOf(false, true)) {
      git("update-index", if (indexed) "--chmod=+x" else "--chmod=-x", "--", "source.java")
      commitFixture()
      for (permissions in listOf("rw-r--r--", "rwxr-xr-x", "rw-r-xr--", "rw-r--r-x")) {
        if (posix)
          Files.setPosixFilePermissions(source, PosixFilePermissions.fromString(permissions))
        assertArrayEquals(byteArrayOf(), git("status", "--porcelain", "--untracked-files=no"))
        val index = Files.readAllBytes(root.resolve(".git/index"))

        val manifest = JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>

        val executable = if (posix) permissions.contains('x') else indexed
        assertEquals(
          if (executable != indexed) "working-source" else "committed-source",
          manifest["sourceClass"],
        )
        val record = (manifest["files"] as Map<*, *>)["source.java"] as Map<*, *>
        assertEquals(executable, record["executable"])
        assertArrayEquals(index, Files.readAllBytes(root.resolve(".git/index")))
      }
    }
  }

  @Test
  fun writeRoster_whenGitStatCacheHidesByteEdits_expectWorkingSourceWithoutIndexMutation() {
    committedFixture()
    val source = root.resolve("source.java")
    val stamp = FileTime.fromMillis(Files.getLastModifiedTime(source).toMillis() - 10000)
    git("config", "core.trustctime", "false")
    Files.setLastModifiedTime(source, stamp)
    git("update-index", "--refresh")
    Files.writeString(source, "class Changed {}")
    Files.setLastModifiedTime(source, stamp)
    assertArrayEquals(byteArrayOf(), git("status", "--porcelain"))
    val index = Files.readAllBytes(root.resolve(".git/index"))

    val manifest = JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>

    assertEquals("working-source", manifest["sourceClass"])
    assertArrayEquals(index, Files.readAllBytes(root.resolve(".git/index")))
  }

  @Test
  fun writeRoster_whenCleanFilterMasksEdits_expectWorkingSourceWithoutIndexMutation() {
    committedFixture()
    val source = root.resolve("source.java")
    val original = Files.readAllBytes(source)
    for (driver in listOf("mask", "unset", "unspecified")) {
      Files.writeString(root.resolve(".git/info/attributes"), "source.java filter=$driver\n")
      git("config", "filter.$driver.clean", "git show HEAD:source.java")
      Files.writeString(source, "class Changed {}")
      val index = Files.readAllBytes(root.resolve(".git/index"))

      assertEquals(
        "working-source",
        (JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>)["sourceClass"],
      )
      assertArrayEquals(index, Files.readAllBytes(root.resolve(".git/index")))
      Files.write(source, original)
      assertEquals(
        "working-source",
        (JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>)["sourceClass"],
      )
    }
    Files.writeString(root.resolve(".git/info/attributes"), "")
    assertEquals(
      "committed-source",
      (JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>)["sourceClass"],
    )
  }

  @Test
  fun writeRoster_whenHeadHasReplacement_expectOriginalIdentityAndWorkingSource() {
    committedFixture()
    val original = git("rev-parse", "HEAD").toString(Charsets.US_ASCII).trim()
    val tree = git("rev-parse", "HEAD^{tree}").toString(Charsets.US_ASCII).trim()
    Files.writeString(root.resolve("source.java"), "class Changed {}")
    git("add", ".")
    commitFixture()
    val replacement = git("rev-parse", "HEAD").toString(Charsets.US_ASCII).trim()
    git("update-ref", "HEAD", original)
    git("replace", original, replacement)

    val manifest = JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>

    assertEquals(original, manifest["sourceCommit"])
    assertEquals(tree, manifest["sourceTree"])
    assertEquals("working-source", manifest["sourceClass"])
  }

  @Test
  fun writeRoster_whenCheckoutUsesCrLf_expectCommittedSourceAndDetectChangedBytes() {
    committedFixture()
    Files.writeString(root.resolve(".gitattributes"), "*.bat text eol=crlf\n")
    val script = root.resolve("native space é.bat")
    Files.writeString(script, "echo one\n")
    git("add", ".")
    commitFixture()
    Files.delete(script)
    git("checkout-index", "--force", "--all")
    assertEquals("echo one\r\n", Files.readString(script))
    assertEquals(
      "committed-source",
      (JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>)["sourceClass"],
    )

    Files.writeString(script, "echo two\r\n")

    assertEquals(
      "working-source",
      (JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>)["sourceClass"],
    )
  }

  @Test
  fun writeRoster_whenSelectedMembersAreIntentToAdd_expectWorkingSource() {
    committedFixture()
    for ((name, body) in
      listOf(
        "new space é.kt" to "class New",
        "empty.kt" to "",
        ".stversions/new.kt" to "class Kept",
      )) {
      Files.writeString(root.resolve(name), body)
      git("add", "--intent-to-add", "--", name)

      val manifest = JsonSlurper().parse(writeRepositoryRoster()) as Map<*, *>

      assertEquals("working-source", manifest["sourceClass"])
      assertEquals(true, (manifest["files"] as Map<*, *>).containsKey(name))
      git("reset", "--quiet", "--", name)
      Files.delete(root.resolve(name))
    }
  }

  @Test
  fun repository_whenGitSelectsReservedExportRoster_expectRejection() {
    committedFixture()
    Files.writeString(root.resolve(ActiveSourceFiles.SOURCE_ROSTER), "{}\n")
    for (tracked in listOf(false, true)) {
      if (tracked) {
        git("add", "--", ActiveSourceFiles.SOURCE_ROSTER)
        commitFixture()
      }
      assertThrows(IllegalArgumentException::class.java) {
        ActiveSourceFiles.repository(root.toFile())
      }
    }
  }

  private fun committedFixture() {
    git("init", "--quiet")
    Files.writeString(root.resolve("source.java"), "class Example {}")
    Files.createDirectories(root.resolve(".stversions"))
    Files.writeString(root.resolve(".stversions/kept.kt"), "class Kept")
    git("add", ".")
    commitFixture()
  }

  private fun commitFixture() {
    git(
      "-c",
      "user.name=Source roster fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "--quiet",
      "--allow-empty",
      "-m",
      "fixture: committed sources",
    )
  }

  private fun writeRepositoryRoster(): ByteArray {
    val output = root.resolve("build/export/roster.json").toFile()
    ActiveSourceFiles.writeRoster(
      root.toFile(),
      ActiveSourceFiles.repository(root.toFile()),
      output,
    )
    return output.readBytes()
  }

  private fun git(vararg arguments: String): ByteArray {
    val process = ProcessBuilder(listOf("git") + arguments).directory(root.toFile()).start()
    assertEquals(true, process.waitFor(15, TimeUnit.SECONDS))
    assertEquals(0, process.exitValue(), process.errorStream.bufferedReader().readText())
    return process.inputStream.readBytes()
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
