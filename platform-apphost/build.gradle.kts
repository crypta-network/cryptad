plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  // AppEnv is the repo's single source of truth for OS detection and keeps Windows launch
  // handling out of raw os.name checks.
  implementation(project(":foundation-fs"))
  api(project(":platform-appdist"))

  compileOnly(libs.jetbrainsAnnotations)

  // Keep leaf-local tests runnable through :platform-apphost:test without depending on the root
  // project's aggregated classpath.
  testImplementation(mainSourceSet.map { it.output })
  testImplementation(project(":platform-appdist"))
  testImplementation(libs.junitJupiterApi)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}
