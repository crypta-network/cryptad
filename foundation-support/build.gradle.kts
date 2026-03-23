plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(libs.slf4jApi)
  implementation(project(":thirdparty-legacy"))
  implementation(libs.commonsCompress)
  compileOnly(libs.jetbrainsAnnotations)
}
