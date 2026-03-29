plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(project(":foundation-support"))
  implementation(libs.slf4jApi)
}
