import java.io.IOException
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.compile.JavaCompile

plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

dependencies {
  api(project(":foundation-support"))
  api(project(":foundation-crypto-keys"))

  implementation(libs.slf4jApi)

  compileOnly(libs.jetbrainsAnnotations)
}

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
    val buildVersion = project.version.toString()
    val javaSrcDirs = sourceSetsContainer["main"].java.srcDirs
    val templateInputs = javaSrcDirs.map { it.resolve(versionSrc) }
    inputs.files(templateInputs)
    inputs.property("buildVersion", buildVersion)
    inputs.property("gitRevision", gitrev)
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
