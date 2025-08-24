import java.io.IOException
import org.gradle.api.tasks.SourceSetContainer
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

val versionBuildDir = file("$projectDir/build/tmp/compileVersion/")
val versionSrc = "network/crypta/node/Version.kt"

val gitrev: String =
  try {
    val cmd = "git rev-parse --short HEAD"
    ProcessBuilder(cmd.split(" "))
      .directory(rootDir)
      .start()
      .inputStream
      .bufferedReader()
      .readText()
      .trim()
  } catch (_: IOException) {
    "@unknown@"
  }

val sourceSetsContainer = extensions.getByType(SourceSetContainer::class.java)

val generateVersionSource by
  tasks.registering(Copy::class) {
    // Always regenerate to ensure fresh version info
    outputs.upToDateWhen { false }

    // Capture version during configuration to avoid deprecation warning
    val buildVersion = project.version.toString()

    // Delete old generated version first to ensure clean generation
    doFirst { delete(versionBuildDir) }

    from(sourceSetsContainer["main"].java.srcDirs) {
      include(versionSrc)
      filter { line: String ->
        line.replace("@build_number@", buildVersion).replace("@git_rev@", gitrev)
      }
    }
    into(versionBuildDir)
  }

tasks.named<KotlinCompile>("compileKotlin") {
  dependsOn(generateVersionSource)
  source(versionBuildDir)
  inputs.property("buildNumber", project.version.toString())
  inputs.property("gitRevision", gitrev)
  inputs.files(generateVersionSource)
}
