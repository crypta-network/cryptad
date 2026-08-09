package cryptad

import java.io.File
import java.nio.file.Files
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

/** Exercises the closed authenticated-tree selector without reading or mutating repository files. */
@DisableCachingByDefault(because = "This deterministic verification task has no persistent output")
abstract class VerifyStableTrackedMaterialPaths : DefaultTask() {
  @TaskAction
  fun verifySelection() {
    val root = temporaryDir.resolve("repository")
    root.deleteRecursively()
    val backend = root.resolve(StableTrackedMaterialPaths.PUBLICATION_BACKEND_ROOT)
    val builder = backend.resolve("build_wheel.py").also(::writeFixture)
    val provider =
      backend
        .resolve("src/cryptad_stable_maintenance_backend/provider.py")
        .also(::writeFixture)
    val trackedPaths = listOf(relativePath(root, provider), relativePath(root, builder))
    val encodedTrackedPaths = encodePaths(trackedPaths)

    val baseline = selectRelativePaths(root, encodedTrackedPaths)
    check(baseline == trackedPaths.sorted()) {
      "Authenticated publication-backend materials are not sorted deterministically"
    }

    val generatedPaths =
      listOf(
        "__pycache__/provider.py",
        ".pytest_cache/state",
        "build/generated.py",
        "dist/generated.py",
        "package.egg-info/PKG-INFO",
        "provider.pyc",
        "cryptad_backend-1-py3-none-any.whl",
        ".DS_Store",
        "._provider.py",
      )
    generatedPaths.forEach { relativePath -> writeFixture(backend.resolve(relativePath)) }
    check(selectRelativePaths(root, encodedTrackedPaths) == baseline) {
      "Ignored cache or build outputs changed authenticated HEAD-tree material selection"
    }

    expectRejected("duplicate material path") {
      StableTrackedMaterialPaths.selectPublicationBackendFiles(
        root,
        encodePaths(listOf(trackedPaths.first(), trackedPaths.first())),
      )
    }
    expectRejected("case-folded duplicate material path") {
      StableTrackedMaterialPaths.selectPublicationBackendFiles(
        root,
        encodePaths(
          listOf(
            trackedPaths.last(),
            trackedPaths.last().replace("build_wheel.py", "BUILD_WHEEL.PY"),
          )
        ),
      )
    }
    expectRejected("non-NUL-terminated path list") {
      StableTrackedMaterialPaths.selectPublicationBackendFiles(
        root,
        trackedPaths.first().toByteArray(Charsets.UTF_8),
      )
    }
    expectRejected("path traversal") {
      StableTrackedMaterialPaths.selectPublicationBackendFiles(
        root,
        encodePaths(
          listOf(
            "${StableTrackedMaterialPaths.PUBLICATION_BACKEND_ROOT}/../outside.py"
          )
        ),
      )
    }
    generatedPaths.forEach { relativePath ->
      expectRejected("tracked generated material $relativePath") {
        StableTrackedMaterialPaths.selectPublicationBackendFiles(
          root,
          encodePaths(
            listOf("${StableTrackedMaterialPaths.PUBLICATION_BACKEND_ROOT}/$relativePath")
          ),
        )
      }
    }
    expectRejected("missing regular file") {
      StableTrackedMaterialPaths.selectPublicationBackendFiles(
        root,
        encodePaths(
          listOf(
            "${StableTrackedMaterialPaths.PUBLICATION_BACKEND_ROOT}/src/missing.py"
          )
        ),
      )
    }
    verifySymlinkRejected(root, backend, provider)
  }

  private fun verifySymlinkRejected(root: File, backend: File, target: File) {
    val link = backend.resolve("src/link.py")
    try {
      Files.createSymbolicLink(link.toPath(), target.toPath())
    } catch (_: UnsupportedOperationException) {
      return
    } catch (_: SecurityException) {
      return
    }
    expectRejected("symbolic-link material") {
      StableTrackedMaterialPaths.selectPublicationBackendFiles(
        root,
        encodePaths(listOf(relativePath(root, link))),
      )
    }
  }

  private fun selectRelativePaths(root: File, encodedPaths: ByteArray): List<String> =
    StableTrackedMaterialPaths.selectPublicationBackendFiles(root, encodedPaths).map { file ->
      relativePath(root, file)
    }

  private fun relativePath(root: File, file: File): String =
    root.canonicalFile.toPath().relativize(file.toPath()).joinToString("/")

  private fun encodePaths(paths: List<String>): ByteArray =
    (paths.joinToString("\u0000") + "\u0000").toByteArray(Charsets.UTF_8)

  private fun writeFixture(file: File) {
    file.parentFile.mkdirs()
    file.writeText("fixture\n", Charsets.UTF_8)
  }

  private fun expectRejected(description: String, action: () -> Unit) {
    try {
      action()
    } catch (_: GradleException) {
      return
    }
    throw GradleException("Stable tracked-material verification accepted $description")
  }
}
