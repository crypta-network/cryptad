pluginManagement {
  repositories {
    gradlePluginPortal()
    mavenCentral()
  }
}

// Configure repositories for Java toolchain auto-provisioning (fixes Gradle 10 deprecation)
plugins { id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0" }

dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
  repositories {
    mavenCentral {
      metadataSources {
        mavenPom()
        artifact()
        ignoreGradleMetadataRedirection()
      }
    }
    maven("https://jitpack.io") {
      metadataSources {
        mavenPom()
        artifact()
        ignoreGradleMetadataRedirection()
      }
    }
  }
}

rootProject.name = "cryptad"

// Gradle 9: Use an included build for convention plugins instead of buildSrc
includeBuild("build-logic")
