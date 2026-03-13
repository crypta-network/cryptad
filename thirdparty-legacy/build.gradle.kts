plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(libs.bcprov)
  compileOnly(libs.jetbrainsAnnotations)
}
