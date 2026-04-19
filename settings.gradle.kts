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
  }
}

rootProject.name = "cryptad"

include(
  ":apps:queue-manager",
  ":apps:publisher",
  ":foundation-support",
  ":foundation-store",
  ":foundation-store-contracts",
  ":foundation-crypto-keys",
  ":interop-wire",
  ":foundation-config",
  ":foundation-fs",
  ":foundation-compat",
  ":kernel-content",
  ":kernel-transport",
  ":kernel-routing",
  ":runtime-spi",
  ":platform-api",
  ":platform-apphost",
  ":platform-web-shell",
  ":runtime-alerts",
  ":runtime-node",
  ":adapter-fcp",
  ":bridge-fcp-runtime",
  ":bridge-http-runtime",
  ":adapter-http-legacy-admin",
  ":adapter-http-legacy-browse",
  ":thirdparty-onion",
  ":thirdparty-legacy",
  ":launcher-desktop",
)

// Gradle 9: Use an included build for convention plugins instead of buildSrc
includeBuild("build-logic")
