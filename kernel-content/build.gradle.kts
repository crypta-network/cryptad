plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  api(project(":foundation-support"))
  api(project(":foundation-crypto-keys"))
  api(project(":kernel-routing"))

  implementation(project(":foundation-config"))
  implementation(libs.slf4jApi)

  compileOnly(libs.jetbrainsAnnotations)

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.junitJupiterParams)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}
