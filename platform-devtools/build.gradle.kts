plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  application
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":platform-design-system"))
  implementation(project(":platform-api")) { isTransitive = false }
  implementation(project(":platform-apphost")) { isTransitive = false }
  implementation(project(":platform-app-ui")) { isTransitive = false }
  implementation(project(":platform-appcatalog"))
  implementation(project(":platform-appdist"))
  implementation(project(":platform-sdk-js"))
  implementation(libs.picocli)

  compileOnly(libs.jetbrainsAnnotations)

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(project(":platform-appcatalog"))
  testImplementation(project(":platform-appdist"))
  testImplementation(project(":platform-api"))
  testImplementation(libs.junitJupiterApi)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

tasks.test {
  dependsOn(":apps:site-publisher:stageApp")
  systemProperty(
    "sharesite.synthetic.sitePublisherBundle",
    project(":apps:site-publisher")
      .layout
      .buildDirectory
      .dir("cryptad-app/site-publisher")
      .get()
      .asFile
      .absolutePath,
  )
}

application {
  mainClass.set("network.crypta.platform.devtools.CryptaAppCli")
  applicationName = "crypta-app"
}
