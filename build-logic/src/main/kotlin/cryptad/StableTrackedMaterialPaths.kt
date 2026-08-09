package cryptad

import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.util.Locale
import org.gradle.api.GradleException

/** Selects repository materials from an authenticated, NUL-delimited Git tree listing. */
internal object StableTrackedMaterialPaths {
  const val PUBLICATION_BACKEND_ROOT =
    "tools/release-certification/publication-backend"

  private val forbiddenDirectoryNames =
    setOf(
      ".mypy_cache",
      ".pytest_cache",
      ".ruff_cache",
      ".tox",
      "__macosx",
      "__pycache__",
      "build",
      "dist",
    )
  private val forbiddenFileSuffixes = setOf(".pyc", ".pyd", ".pyo", ".whl")

  fun selectPublicationBackendFiles(
    repositoryRoot: File,
    nulDelimitedHeadPaths: ByteArray,
  ): List<File> {
    val repositoryPaths = parseNulDelimitedPaths(nulDelimitedHeadPaths)
    if (repositoryPaths.isEmpty()) {
      throw GradleException("Authenticated HEAD tree contains no publication-backend materials")
    }

    val root = repositoryRoot.canonicalFile.toPath()
    val backendRoot = root.resolve(PUBLICATION_BACKEND_ROOT).normalize()
    if (!backendRoot.startsWith(root) || !Files.isDirectory(backendRoot, LinkOption.NOFOLLOW_LINKS)) {
      throw GradleException("Publication-backend material root is missing or unsafe")
    }
    val realBackendRoot = backendRoot.toRealPath()
    if (!realBackendRoot.startsWith(root)) {
      throw GradleException("Publication-backend material root escapes the repository")
    }

    val exactPaths = mutableSetOf<String>()
    val caseFoldedPaths = mutableSetOf<String>()
    return repositoryPaths
      .map { repositoryPath ->
        validateRepositoryPath(repositoryPath)
        if (!exactPaths.add(repositoryPath)) {
          throw GradleException(
            "Authenticated HEAD tree contains duplicate material path: $repositoryPath"
          )
        }
        val caseFoldedPath = repositoryPath.lowercase(Locale.ROOT)
        if (!caseFoldedPaths.add(caseFoldedPath)) {
          throw GradleException(
            "Authenticated HEAD tree contains a case-folded material path collision: " +
              repositoryPath
          )
        }

        val materialPath = root.resolve(repositoryPath).normalize()
        if (!materialPath.startsWith(backendRoot)) {
          throw GradleException("Publication-backend material escapes its root: $repositoryPath")
        }
        if (
          Files.isSymbolicLink(materialPath) ||
            !Files.isRegularFile(materialPath, LinkOption.NOFOLLOW_LINKS)
        ) {
          throw GradleException(
            "Authenticated publication-backend material is not a regular file: $repositoryPath"
          )
        }
        if (!materialPath.toRealPath().startsWith(realBackendRoot)) {
          throw GradleException("Publication-backend material resolves outside its root: $repositoryPath")
        }
        materialPath.toFile()
      }
      .sortedBy { material -> root.relativize(material.toPath()).joinToString("/") }
  }

  private fun parseNulDelimitedPaths(encodedPaths: ByteArray): List<String> {
    if (encodedPaths.isEmpty() || encodedPaths.last() != 0.toByte()) {
      throw GradleException("Authenticated HEAD tree path list is empty or not NUL-terminated")
    }
    val paths = mutableListOf<String>()
    var start = 0
    encodedPaths.indices.forEach { index ->
      if (encodedPaths[index] == 0.toByte()) {
        if (index == start) {
          throw GradleException("Authenticated HEAD tree path list contains an empty path")
        }
        paths += decodeUtf8(encodedPaths, start, index - start)
        start = index + 1
      }
    }
    return paths
  }

  private fun decodeUtf8(bytes: ByteArray, offset: Int, length: Int): String {
    val decoder =
      StandardCharsets.UTF_8
        .newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
    return try {
      decoder.decode(ByteBuffer.wrap(bytes, offset, length)).toString()
    } catch (_: java.nio.charset.CharacterCodingException) {
      throw GradleException("Authenticated HEAD tree contains a non-UTF-8 material path")
    }
  }

  private fun validateRepositoryPath(repositoryPath: String) {
    if (
      repositoryPath.any { character -> character.code < 0x20 || character.code == 0x7f } ||
        '\\' in repositoryPath
    ) {
      throw GradleException("Authenticated HEAD tree contains an unsafe material path")
    }
    val prefix = "$PUBLICATION_BACKEND_ROOT/"
    if (!repositoryPath.startsWith(prefix)) {
      throw GradleException(
        "Authenticated material is outside the publication-backend tree: $repositoryPath"
      )
    }
    val relativePath = repositoryPath.removePrefix(prefix)
    val segments = relativePath.split('/')
    if (segments.any { segment -> segment.isBlank() || segment == "." || segment == ".." }) {
      throw GradleException("Authenticated HEAD tree contains a non-canonical path: $repositoryPath")
    }

    val foldedSegments = segments.map { segment -> segment.lowercase(Locale.ROOT) }
    val fileName = foldedSegments.last()
    if (
      foldedSegments.any { segment ->
        segment in forbiddenDirectoryNames || segment.endsWith(".egg-info")
      } ||
        forbiddenFileSuffixes.any(fileName::endsWith) ||
        fileName == ".coverage" ||
        fileName == ".ds_store" ||
        fileName.startsWith("._")
    ) {
      throw GradleException(
        "Authenticated HEAD tree contains generated publication-backend material: $repositoryPath"
      )
    }
  }
}
