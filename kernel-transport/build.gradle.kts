plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  api(project(":foundation-support"))

  implementation(project(":foundation-compat"))
  implementation(libs.slf4jApi)
  implementation(files(rootProject.file("libs/wrapper.jar")))

  compileOnly(libs.jetbrainsAnnotations)

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.mockitoJunitJupiter)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}
