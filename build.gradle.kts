plugins {
  // Apply Gradle 9 convention plugins from included build
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  id("cryptad.versioning")
  id("cryptad.buildjar")
  id("cryptad.distribution")
}

// Update version manually before a new release development starts
version = "1"

dependencies {
  implementation(libs.bcprov)
  implementation(libs.bcpkix)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(libs.commonsCompress)
  implementation(files("libs/wrapper.jar"))
  implementation(libs.pebble)
  implementation(libs.unbescape)
  implementation(libs.slf4jApi)
  // CLI parsing and UX
  implementation(libs.picocli)

  testImplementation(libs.junit4)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.hamcrest)
  testImplementation(libs.objenesis)

  runtimeOnly(files("libs/db4o-7.4.58.jar"))
}

// Utility task to print the project version
tasks.register("printVersion") {
  group = "help"
  description = "Prints the project version"
  doLast {
    println(project.version.toString())
  }
}
