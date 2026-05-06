plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  application
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  implementation(project(":platform-design-system"))
  implementation(project(":platform-api")) { isTransitive = false }
  implementation(project(":platform-appcatalog"))
  implementation(project(":platform-appdist"))
  implementation(project(":platform-sdk-js"))
  implementation(libs.picocli)

  compileOnly(libs.jetbrainsAnnotations)

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(project(":platform-appcatalog"))
  testImplementation(project(":platform-appdist"))
  testImplementation(libs.junitJupiterApi)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

application {
  mainClass.set("network.crypta.platform.devtools.CryptaAppCli")
  applicationName = "crypta-app"
}
