plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

dependencies {
  // Public config/l10n APIs expose SimpleFieldSet, so foundation-support must be exported.
  api(project(":foundation-support"))
  // Public config APIs also expose Resolved, so foundation-fs must stay on downstream classpaths.
  api(project(":foundation-fs"))
  implementation(libs.slf4jApi)
  implementation(files(rootProject.file("libs/wrapper.jar")))
  compileOnly(libs.jetbrainsAnnotations)
}
