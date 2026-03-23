plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

dependencies {
  api(project(":foundation-support"))
  api(project(":foundation-store-contracts"))
  implementation(project(":foundation-fs"))
  implementation(project(":thirdparty-legacy"))
  implementation(libs.bcprov)
  implementation(libs.slf4jApi)
  compileOnly(libs.jetbrainsAnnotations)
}
