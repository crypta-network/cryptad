plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(project(":foundation-support"))
  implementation(project(":foundation-config"))
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":interop-wire"))
  implementation(project(":kernel-content"))
  implementation(project(":kernel-transport"))
  implementation(project(":runtime-spi"))
  implementation(project(":runtime-node"))

  implementation(libs.slf4jApi)
  implementation(files(rootProject.file("libs/wrapper.jar")))

  compileOnly(libs.jetbrainsAnnotations)
}
