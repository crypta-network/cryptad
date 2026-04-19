import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import org.gradle.api.tasks.PathSensitivity

plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")
val stageAppDir = layout.buildDirectory.dir("cryptad-app/publisher")
val generatedManifestDir = layout.buildDirectory.dir("generated/stageApp")
val stageAssetsDir = layout.projectDirectory.dir("src/staged")
val manifestTemplateFile = stageAssetsDir.file("cryptad-app.properties.template")
val launcherRelativePath = "bin/publisher.sh"
val stagedLauncher =
  stageAppDir.map { stageDirectory -> stageDirectory.file(launcherRelativePath).asFile.toPath() }

dependencies {
  testImplementation(mainSourceSet.map { it.output })
  testImplementation(project(":platform-apphost"))
  testImplementation(libs.junitJupiterApi)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

val generateManifest by
  tasks.registering(Copy::class) {
    from(manifestTemplateFile) {
      rename { "cryptad-app.properties" }
      expand("appVersion" to project.version.toString())
    }
    into(generatedManifestDir)
    filteringCharset = "UTF-8"
  }

val stageApp by
  tasks.registering(Sync::class) {
    group = "build"
    description = "Stages the Publisher AppHost bundle."
    dependsOn(generateManifest)
    into(stageAppDir)
    from(stageAssetsDir) { exclude("cryptad-app.properties.template") }
    from(generatedManifestDir)
    doLast {
      val launcher = stagedLauncher.get()
      if (
        Files.exists(launcher) && Files.getFileStore(launcher).supportsFileAttributeView("posix")
      ) {
        Files.setPosixFilePermissions(launcher, PosixFilePermissions.fromString("rwxr-xr-x"))
      }
    }
  }

tasks.named<Test>("test") {
  dependsOn(stageApp)
  inputs
    .dir(stageAppDir)
    .withPropertyName("publisherStagedBundle")
    .withPathSensitivity(PathSensitivity.RELATIVE)
  inputs.property("publisherAppVersion", project.version.toString())
  systemProperty("publisher.stageDir", stageAppDir.get().asFile.absolutePath)
  systemProperty("publisher.appVersion", project.version.toString())
}
