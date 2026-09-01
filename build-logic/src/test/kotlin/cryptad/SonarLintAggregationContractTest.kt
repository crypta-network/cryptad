package cryptad

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SonarLintAggregationContractTest {
  @Test
  fun sonarlintMain_whenRepositoryUsesLeafModules_expectAggregatedSourcesAndClasses() {
    val repositoryRoot = repositoryRoot()
    val rootBuild = Files.readString(repositoryRoot.resolve("build.gradle.kts"))
    val sonarConvention =
      Files.readString(
        repositoryRoot.resolve("build-logic/src/main/kotlin/cryptad.sonar.gradle.kts")
      )

    assertTrue(
      rootBuild.contains(
        "extensions.extraProperties[\"cryptad.additionalSonarMainSourceDirs\"] ="
      )
    )
    assertTrue(
      rootBuild.contains(
        "extensions.extraProperties[\"cryptad.additionalSonarMainOutputDirs\"] ="
      )
    )
    assertTrue(
      sonarConvention.contains(
        "setSource(files(mainSourceSet.allSource, additionalSonarMainSourceDirs))"
      )
    )
    assertTrue(
      sonarConvention.contains(
        "mainOutputDirectories.from(mainSourceSet.output.classesDirs, additionalSonarMainOutputDirs)"
      )
    )
  }

  private fun repositoryRoot(): Path {
    var current: Path? = Path.of("").toAbsolutePath().normalize()
    while (current != null) {
      if (
        Files.isRegularFile(current.resolve("settings.gradle.kts")) &&
          Files.isDirectory(current.resolve("platform-api/src/main/java"))
      ) {
        return current
      }
      current = current.parent
    }
    throw IllegalStateException("Cannot locate the Cryptad repository root")
  }
}
