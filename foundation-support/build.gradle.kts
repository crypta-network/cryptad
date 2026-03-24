plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(project(":foundation-fs"))
  implementation(libs.slf4jApi)
  implementation(project(":thirdparty-legacy"))
  implementation(libs.commonsCompress)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(files(rootProject.file("libs/wrapper.jar")))
  compileOnly(libs.jetbrainsAnnotations)
}
