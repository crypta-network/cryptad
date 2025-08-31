dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
  repositories { mavenCentral() }
  versionCatalogs { create("libs") { from(files("../gradle/libs.versions.toml")) } }
}

pluginManagement {
  repositories {
    gradlePluginPortal()
    mavenCentral()
  }
  plugins {
    // Read versions from the root version catalog to avoid hardcoding
    val toml = file("../gradle/libs.versions.toml").readText()
    fun ver(key: String): String {
      val pattern = Regex("""^\s*${Regex.escape(key)}\s*=\s*\"([^\"]+)\"""", RegexOption.MULTILINE)
      return pattern.find(toml)?.groupValues?.get(1)
        ?: error("Version '$key' not found in libs.versions.toml")
    }

    id("org.jetbrains.kotlin.jvm") version ver("kotlin")
    id("com.diffplug.spotless") version ver("spotless")
  }
}

// Ensure toolchain download repositories are configured for this included build too
plugins { id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0" }

rootProject.name = "build-logic"
