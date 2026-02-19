package cryptad

import com.diffplug.spotless.FormatterFunc
import java.io.Serializable

/**
 * Reorders Java import declarations by specificity so Spotless output matches Sonar java:S8445:
 * module, on-demand package, single-type, static on-demand, single-static.
 */
object SonarS8445ImportOrderFormatter : FormatterFunc, Serializable {
  private const val IMPORT_PREFIX = "import "

  override fun apply(source: String): String {
    val lines = source.split('\n')
    val importIndexes = lines.indices.filter { lines[it].trimStart().startsWith(IMPORT_PREFIX) }
    if (importIndexes.isEmpty()) {
      return source
    }

    val importBlockStart = importIndexes.first()
    val importBlockEnd = importIndexes.last()

    // Leave unusual import sections unchanged when comments/code are mixed into the import block.
    for (index in importBlockStart..importBlockEnd) {
      val trimmedLine = lines[index].trim()
      if (trimmedLine.isNotEmpty() && !trimmedLine.startsWith(IMPORT_PREFIX)) {
        return source
      }
    }

    val sortedImports =
        importIndexes
            .asSequence()
            .map { lines[it].trim() }
            .distinct()
            .sortedWith(compareBy({ classifyImportSpecificity(it) }, { it }))
            .toList()

    val rebuiltImportBlock = mutableListOf<String>()
    var previousGroup = -1
    for (importLine in sortedImports) {
      val currentGroup = classifyImportSpecificity(importLine)
      if (rebuiltImportBlock.isNotEmpty() && currentGroup != previousGroup) {
        rebuiltImportBlock.add("")
      }
      rebuiltImportBlock.add(importLine)
      previousGroup = currentGroup
    }

    val rebuiltFile = mutableListOf<String>()
    rebuiltFile.addAll(lines.subList(0, importBlockStart))
    rebuiltFile.addAll(rebuiltImportBlock)
    rebuiltFile.addAll(lines.subList(importBlockEnd + 1, lines.size))

    return rebuiltFile.joinToString("\n")
  }

  private fun classifyImportSpecificity(importLine: String): Int {
    val importTarget = importLine.removePrefix(IMPORT_PREFIX).removeSuffix(";").trim()
    val isStaticImport = importTarget.startsWith("static ")
    val isModuleImport = importTarget.startsWith("module ")
    val isOnDemandImport = importTarget.endsWith(".*")

    return when {
      isModuleImport -> 0
      !isStaticImport && isOnDemandImport -> 1
      !isStaticImport -> 2
      isOnDemandImport -> 3
      else -> 4
    }
  }

  @Suppress("UnusedPrivateMember")
  private fun readResolve(): Any = SonarS8445ImportOrderFormatter
}
