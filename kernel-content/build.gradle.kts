plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

dependencies {
  api(project(":foundation-support"))
  api(project(":foundation-crypto-keys"))

  implementation(libs.slf4jApi)

  compileOnly(libs.jetbrainsAnnotations)
}
