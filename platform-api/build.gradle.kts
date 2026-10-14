plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":foundation-fs"))
  implementation(project(":foundation-support"))
  implementation(project(":kernel-content"))

  api(project(":runtime-spi"))
  api(project(":platform-app-ui"))
  api(project(":platform-apphost"))
  api(project(":platform-appcatalog"))
  api(project(":platform-appvault"))
  api(project(":platform-trustgraph"))

  compileOnly(libs.jetbrainsAnnotations)

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.junitJupiterParams)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.mockitoJunitJupiter)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

val restartNativeExports = layout.buildDirectory.dir("test-results/pr319-native")
val privacyNativeExports = layout.buildDirectory.dir("test-results/pr320-native")
val storageNativeExports = layout.buildDirectory.dir("test-results/pr318-native")

tasks.named<Test>("test") {
  // Export files belong to this execution, including when a producer skips or fails.
  outputs.dir(restartNativeExports)
  outputs.dir(privacyNativeExports)
  outputs.dir(storageNativeExports)
  doFirst { delete(restartNativeExports, privacyNativeExports, storageNativeExports) }
}

// Native packaged-export tests live with the devtools historical bridge and execute this module.
// Include those executions in module reports as well as the root aggregate consumed by Sonar.
tasks.withType<JacocoReport>().configureEach {
  dependsOn(":platform-devtools:test")
  executionData(project(":platform-devtools").layout.buildDirectory.file("jacoco/test.exec"))
}

tasks.withType<JacocoCoverageVerification>().configureEach {
  dependsOn(":platform-devtools:test")
  executionData(project(":platform-devtools").layout.buildDirectory.file("jacoco/test.exec"))
}
