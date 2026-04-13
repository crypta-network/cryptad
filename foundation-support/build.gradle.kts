plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  implementation(project(":foundation-fs"))
  implementation(libs.slf4jApi)
  implementation(project(":thirdparty-legacy"))
  implementation(libs.commonsCompress)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(files(rootProject.file("libs/wrapper.jar")))
  compileOnly(libs.jetbrainsAnnotations)

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.junitJupiterParams)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}
