import cryptad.ActiveSourceFiles
import cryptad.SonarS8445ImportOrderFormatter

plugins { id("com.diffplug.spotless") }

val activeSourceRoster = ActiveSourceFiles.selectedRoster(rootProject)

fun inactiveFormatterSource(element: FileTreeElement): Boolean =
  ActiveSourceFiles.excludeUnselected(rootDir, element.file) {
    activeSourceRoster.value
  }

val javaTargets =
  fileTree(projectDir) {
    include("src/**/*.java")
    exclude { inactiveFormatterSource(it) }
  }
val kotlinTargets =
  fileTree(projectDir) {
    include("src/**/*.kt")
    exclude { inactiveFormatterSource(it) }
  }

val kotlinGradleTargets =
  if (project == rootProject) {
    fileTree(projectDir) {
      include("build.gradle.kts")
      include("settings.gradle.kts")
      include("*/build.gradle.kts")
      include("build-logic/build.gradle.kts")
      include("build-logic/settings.gradle.kts")
      include("build-logic/src/**/*.gradle.kts")
      exclude { inactiveFormatterSource(it) }
    }
  } else {
    fileTree(projectDir) {
      include("build.gradle.kts")
      include("settings.gradle.kts")
      include("src/**/*.gradle.kts")
      exclude { inactiveFormatterSource(it) }
    }
  }

val libs: VersionCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")

spotless {
  java {
    googleJavaFormat(libs.findVersion("googleJavaFormat").get().requiredVersion).reflowLongStrings()
    target(javaTargets)
    removeUnusedImports()
    importOrder("module ", "", "\\#").wildcardsLast(false)
    // Enforce Sonar java:S8445 grouping globally:
    // module, on-demand package, single-type, static on-demand, single-static.
    custom("sonarS8445ImportOrder", SonarS8445ImportOrderFormatter)
  }
  kotlin {
    // Restrict to source trees rather than scanning entire repo to avoid special FS entries
    // created by Flatpak builder (e.g., .flatpak-builder/**/host/proc/**/map_files).
    target(kotlinTargets)
    ktfmt(libs.findVersion("ktfmt").get().requiredVersion).googleStyle()
    trimTrailingWhitespace()
    endWithNewline()
  }
  kotlinGradle {
    // Keep the root task on checked-in Gradle scripts only. The broad repo-wide glob was pulling
    // generated build-logic outputs into the root target set, which is both wasted work and can
    // destabilize Spotless path validation on non-clean worktrees.
    target(kotlinGradleTargets)
    ktfmt(libs.findVersion("ktfmt").get().requiredVersion).googleStyle()
  }
}

// Format on Java compilation to keep sources tidy locally
tasks.named("compileJava") { dependsOn("spotlessApply") }
