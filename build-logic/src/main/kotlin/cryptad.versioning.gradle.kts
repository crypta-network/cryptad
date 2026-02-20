import java.io.IOException
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.compile.JavaCompile

val versionBuildDir = file("$projectDir/build/tmp/compileVersion/")
val versionSrc = "network/crypta/node/Version.java"

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

val sourceSetsContainer: SourceSetContainer = extensions.getByType(SourceSetContainer::class.java)

val generateVersionSource by
  tasks.registering(Copy::class) {
    // Capture version during configuration to avoid deprecation warning
    val buildVersion = project.version.toString()

    // Inputs: the template file and dynamic properties that impact content
    val javaSrcDirs = sourceSetsContainer["main"].java.srcDirs
    val templateInputs = javaSrcDirs.map { it.resolve(versionSrc) }
    inputs.files(templateInputs)
    inputs.property("buildVersion", buildVersion)
    inputs.property("gitRevision", gitrev)

    // Output: the generated Version.java in the build dir
    outputs.file(file(versionBuildDir.resolve(versionSrc)))

    from(javaSrcDirs) {
      include(versionSrc)
      filter { line: String ->
        line.replace("@build_number@", buildVersion).replace("@git_rev@", gitrev)
      }
    }
    into(versionBuildDir)
  }

tasks.named<JavaCompile>("compileJava") {
  dependsOn(generateVersionSource)
  source(versionBuildDir)
  inputs.property("buildNumber", project.version.toString())
  inputs.property("gitRevision", gitrev)
  inputs.files(generateVersionSource)
}
