plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(project(":foundation-support"))
  implementation(project(":foundation-config"))
  implementation(project(":foundation-fs"))
  implementation(project(":foundation-compat"))
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":interop-wire"))
  implementation(project(":kernel-content"))
  implementation(project(":runtime-spi"))
  implementation(project(":runtime-node"))
  implementation(project(":thirdparty-onion"))

  implementation(libs.slf4jApi)
  implementation(libs.pebble)
  implementation(files(rootProject.file("libs/wrapper.jar")))

  compileOnly(libs.jetbrainsAnnotations)
}
