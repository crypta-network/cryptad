plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

dependencies {
  api(project(":runtime-spi"))
  api(project(":platform-apphost"))

  compileOnly(libs.jetbrainsAnnotations)
}
