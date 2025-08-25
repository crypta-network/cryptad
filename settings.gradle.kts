pluginManagement {
  repositories {
    gradlePluginPortal()
    mavenCentral()
  }
}

dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
  repositories { mavenCentral() }
}

rootProject.name = "cryptad"

// Gradle 9: Use an included build for convention plugins instead of buildSrc
includeBuild("build-logic")
