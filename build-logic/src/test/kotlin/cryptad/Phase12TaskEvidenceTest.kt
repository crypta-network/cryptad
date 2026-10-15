package cryptad

import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.Path
import org.gradle.api.file.Directory
import org.gradle.jvm.toolchain.JavaInstallationMetadata
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class Phase12TaskEvidenceTest {
  @TempDir lateinit var temporary: Path

  @BeforeEach
  fun resolveOwnedFixtureRoot() {
    temporary = temporary.toRealPath()
  }

  @Test
  fun reportSnapshot_whenBytesOrExactJUnitRosterChange_expectDifferentPrivateBinding() {
    val root = temporary.toRealPath()
    val reports = Files.createDirectories(root.resolve("build/test-results/test"))
    val first = Files.writeString(reports.resolve("TEST-First.xml"), "<testsuite tests=\"1\"/>")
    Files.writeString(reports.resolve("ignored.txt"), "not a report")
    val original = Phase12TaskEvidence.reportSnapshot(root.toFile(), listOf(reports.toFile()), true)
    assertEquals("complete", original["reportObservation"])
    assertEquals(1, (original["reportFiles"] as List<*>).size)
    Files.writeString(first, "<testsuite tests=\"0\"/>")
    val edited = Phase12TaskEvidence.reportSnapshot(root.toFile(), listOf(reports.toFile()), true)
    assertNotEquals(original, edited)
    Files.writeString(reports.resolve("TEST-Added.xml"), "<testsuite tests=\"1\"/>")
    assertEquals(
      2,
      (Phase12TaskEvidence.reportSnapshot(root.toFile(), listOf(reports.toFile()), true)[
            "reportFiles"]
          as List<*>)
        .size,
    )
    Files.delete(first)
    assertNotEquals(
      edited,
      Phase12TaskEvidence.reportSnapshot(root.toFile(), listOf(reports.toFile()), true),
    )
  }

  @Test
  fun reportSnapshot_whenAnalyzerReportExists_expectExactPrivateBinding() {
    val report = Files.createDirectories(temporary.resolve("reports/spotbugs")).resolve("main.xml")
    Files.writeString(report, "abc")

    val observed =
      Phase12TaskEvidence.reportSnapshot(
        temporary.toFile(),
        listOf(report.toFile()),
        junit = false,
      )

    assertEquals(
      mapOf(
        "reportObservation" to "complete",
        "reportFiles" to
          listOf(
            mapOf(
              "path" to "reports/spotbugs/main.xml",
              "size" to 3L,
              "sha256" to "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )
          ),
      ),
      observed,
    )
  }

  @Test
  fun reportSnapshot_whenOutputRosterOrKindIsInvalid_expectRefusal() {
    val report = Files.writeString(temporary.resolve("report.xml"), "abc").toFile()
    for (outputs in listOf(emptyList(), listOf(report, report))) {
      assertThrows(IllegalArgumentException::class.java) {
        Phase12TaskEvidence.reportSnapshot(temporary.toFile(), outputs, junit = false)
      }
    }
    assertThrows(IllegalArgumentException::class.java) {
      Phase12TaskEvidence.reportSnapshot(temporary.toFile(), listOf(report), junit = true)
    }
    val directory = Files.createDirectory(temporary.resolve("reports")).toFile()
    assertThrows(IllegalArgumentException::class.java) {
      Phase12TaskEvidence.reportSnapshot(temporary.toFile(), listOf(directory), junit = false)
    }
  }

  @Test
  fun reportSnapshot_whenIgnoredEntriesExceedDirectoryBound_expectRefusal() {
    val directory = Files.createDirectory(temporary.resolve("reports"))
    repeat(4097) { Files.createFile(directory.resolve("ignored-$it.txt")) }

    assertThrows(IllegalArgumentException::class.java) {
      Phase12TaskEvidence.reportSnapshot(
        temporary.toFile(),
        listOf(directory.toFile()),
        junit = true,
      )
    }
  }

  @Test
  fun reportSnapshot_whenLinkedOrOversizedReport_expectRefusalAndMissingOutputExpectEmptyRoster() {
    val root = temporary.toRealPath()
    val reports = Files.createDirectory(root.resolve("reports"))
    val target = Files.writeString(root.resolve("target.xml"), "<testsuite/>")
    val member = reports.resolve("TEST-Linked.xml")
    Files.createLink(member, target)
    if (Files.getFileStore(member).supportsFileAttributeView("unix")) {
      assertThrows(IllegalArgumentException::class.java) {
        Phase12TaskEvidence.reportSnapshot(root.toFile(), listOf(reports.toFile()), true)
      }
    } else {
      // Java has no portable link count here. The Python collector independently refuses it.
      val snapshot =
        Phase12TaskEvidence.reportSnapshot(root.toFile(), listOf(reports.toFile()), true)
      assertEquals("complete", snapshot["reportObservation"])
      val files = snapshot["reportFiles"] as List<*>
      assertEquals(1, files.size)
      val observed = files.single() as Map<*, *>
      assertEquals("reports/TEST-Linked.xml", observed["path"])
      assertEquals(Files.size(target), observed["size"])
      assertEquals(
        Phase12TaskEvidence.fingerprint(root.toFile(), target.toFile())["digest"],
        observed["sha256"],
      )
    }
    Files.delete(member)
    Files.createSymbolicLink(member, target)
    assertThrows(IllegalArgumentException::class.java) {
      Phase12TaskEvidence.reportSnapshot(root.toFile(), listOf(reports.toFile()), true)
    }
    Files.delete(member)
    java.io.RandomAccessFile(member.toFile(), "rw").use { it.setLength(16L * 1024 * 1024 + 1) }
    assertThrows(IllegalArgumentException::class.java) {
      Phase12TaskEvidence.reportSnapshot(root.toFile(), listOf(reports.toFile()), true)
    }
    assertEquals(
      emptyList<Any>(),
      Phase12TaskEvidence.reportSnapshot(
          root.toFile(),
          listOf(root.resolve("missing").toFile()),
          false,
        )["reportFiles"],
    )
  }

  @Test
  fun diagnosticsComplete_whenJavacTruncatesOrReachesBound_expectIncompleteCapture() {
    assertEquals(true, Phase12TaskEvidence.diagnosticsComplete("42 warnings\n", 42))
    assertEquals(
      false,
      Phase12TaskEvidence.diagnosticsComplete(
        "only showing the first 100 warnings, of 201 total\n",
        100,
      ),
    )
    assertEquals(false, Phase12TaskEvidence.diagnosticsComplete("10000 warnings\n", 500))
    assertEquals(false, Phase12TaskEvidence.diagnosticsComplete("", 10000))
  }

  @Test
  fun fingerprint_whenAncestorOrFinalMemberIsLinked_expectRejection() {
    val root = temporary.toRealPath()
    val real = Files.createDirectory(root.resolve("real"))
    val source = Files.writeString(real.resolve("Example.java"), "class Example {}")
    val alias = Files.createSymbolicLink(root.resolve("alias"), real)
    val finalLink = Files.createSymbolicLink(root.resolve("Example.java"), source)
    for (path in listOf(alias.resolve("Example.java"), finalLink)) {
      assertThrows(IllegalArgumentException::class.java) {
        Phase12TaskEvidence.fingerprint(root.toFile(), path.toFile())
      }
    }
  }

  @Test
  fun outcome_whenGradleReusesOrSkipsTask_expectDistinctNativeOutcome() {
    assertEquals(
      "executed",
      Phase12TaskEvidence.outcome(
        failed = false,
        noSource = false,
        skipMessage = null,
        upToDate = false,
        skipped = false,
      ),
    )
    assertEquals(
      "up-to-date",
      Phase12TaskEvidence.outcome(
        failed = false,
        noSource = false,
        skipMessage = "UP-TO-DATE",
        upToDate = true,
        skipped = true,
      ),
    )
    assertEquals(
      "from-cache",
      Phase12TaskEvidence.outcome(
        failed = false,
        noSource = false,
        skipMessage = "FROM-CACHE",
        upToDate = true,
        skipped = true,
      ),
    )
    assertEquals(
      "no-source",
      Phase12TaskEvidence.outcome(
        failed = false,
        noSource = true,
        skipMessage = "NO-SOURCE",
        upToDate = true,
        skipped = true,
      ),
    )
    assertEquals(
      "skipped",
      Phase12TaskEvidence.outcome(
        failed = false,
        noSource = false,
        skipMessage = "SKIPPED",
        upToDate = false,
        skipped = true,
      ),
    )
    assertEquals(
      "failed",
      Phase12TaskEvidence.outcome(
        failed = true,
        noSource = false,
        skipMessage = null,
        upToDate = false,
        skipped = false,
      ),
    )
  }

  @Test
  fun fingerprint_whenOwnedSourceContainsSpacesAndUnicode_expectRelativeIdentityAndExactBytes() {
    val root = temporary.toRealPath()
    val source =
      Files.createDirectories(root.resolve("src/main/java/naïve space")).resolve("Example.java")
    Files.writeString(source, "abc")

    val result = Phase12TaskEvidence.fingerprint(root.toFile(), source.toFile())

    assertEquals("src/main/java/naïve space/Example.java", result["path"])
    assertEquals(3L, result["size"])
    assertEquals(
      "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      result["digest"],
    )
    Files.writeString(source, "abcd")
    val changed = Phase12TaskEvidence.fingerprint(root.toFile(), source.toFile())
    assertEquals(4L, changed["size"])
    assertNotEquals(result["digest"], changed["digest"])
  }

  @Test
  fun fingerprint_whenInputMissing_expectFailureRatherThanEmptyRoster() {
    assertThrows(java.nio.file.NoSuchFileException::class.java) {
      Phase12TaskEvidence.fingerprint(
        temporary.toFile(),
        temporary.resolve("missing.java").toFile(),
      )
    }
  }

  @Test
  fun fingerprint_whenInputDirectory_expectDirectoryFactWithoutRecursiveSourceDiscovery() {
    val root = temporary.toRealPath()
    val directory = Files.createDirectory(root.resolve("classes"))
    Files.writeString(directory.resolve("unexpected.class"), "private")

    assertEquals(
      mapOf("path" to "classes", "kind" to "directory"),
      Phase12TaskEvidence.fingerprint(root.toFile(), directory.toFile()),
    )
  }

  @Test
  fun policyDigest_whenFilterOrderChanges_expectSameIdentityAndChangedScopeExpectDifferentIdentity() {
    val first = Phase12TaskEvidence.policyDigest(linkedSetOf("a/**", "b/**"), setOf("**/nested/**"))
    val reordered =
      Phase12TaskEvidence.policyDigest(linkedSetOf("b/**", "a/**"), setOf("**/nested/**"))
    val narrowed = Phase12TaskEvidence.policyDigest(setOf("a/**"), setOf("**/nested/**"))

    assertEquals(first, reordered)
    assertNotEquals(first, narrowed)
  }

  @Test
  fun toolchain_whenSelectedInstallationDiffersFromDaemon_expectSelectedMetadataAndReleaseArchitecture() {
    Files.writeString(temporary.resolve("release"), "OS_ARCH=\"x86_64\"\n")

    val observed = Phase12TaskEvidence.toolchain(selectedToolchain())

    assertEquals(
      mapOf(
        "javaVersion" to "25.0.4+7-LTS",
        "javaVendor" to "Selected test vendor",
        "javaArch" to "x86_64",
      ),
      observed,
    )
  }

  @Test
  fun toolchain_whenReleaseIsMissingMalformedOrOversized_expectUnavailableWithoutDaemonFallback() {
    val selected = selectedToolchain()
    assertNull(Phase12TaskEvidence.toolchain(null))
    assertNull(Phase12TaskEvidence.toolchain(selected))
    Files.writeString(temporary.resolve("release"), "OS_ARCH=\"amd64\"\nOS_ARCH=\"aarch64\"\n")
    assertNull(Phase12TaskEvidence.toolchain(selected))
    Files.writeString(temporary.resolve("release"), "#".repeat(65537))
    assertNull(Phase12TaskEvidence.toolchain(selected))
  }

  private fun selectedToolchain(): JavaInstallationMetadata {
    val directory =
      Proxy.newProxyInstance(Directory::class.java.classLoader, arrayOf(Directory::class.java)) {
        _,
        method,
        _ ->
        if (method.name == "getAsFile") temporary.toFile()
        else error("Unexpected directory operation")
      } as Directory
    return Proxy.newProxyInstance(
      JavaInstallationMetadata::class.java.classLoader,
      arrayOf(JavaInstallationMetadata::class.java),
    ) { _, method, _ ->
      when (method.name) {
        "getInstallationPath" -> directory
        "getJavaRuntimeVersion" -> "25.0.4+7-LTS"
        "getVendor" -> "Selected test vendor"
        else -> error("Unexpected toolchain operation")
      }
    } as JavaInstallationMetadata
  }
}
