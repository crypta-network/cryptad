plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(project(":foundation-fs"))
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(libs.flatlaf)
  implementation(libs.oshiCore)
  implementation(libs.versionCompare)
  implementation(libs.jfa) { exclude(group = "net.java.dev.jna", module = "jna") }
  implementation(libs.dbusCore)
  implementation(libs.slf4jApi)
  compileOnly(libs.jetbrainsAnnotations)
}
