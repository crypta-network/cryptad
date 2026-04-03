plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

dependencies {
  api(project(":runtime-spi"))

  compileOnly(libs.jetbrainsAnnotations)
}
