import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  // Enables precompiled script plugins under src/main/kotlin
  `kotlin-dsl`
}

java {
  // Keep build-logic compatible with Gradle's embedded Kotlin
  toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
  sourceCompatibility = JavaVersion.VERSION_21
  targetCompatibility = JavaVersion.VERSION_21
}

kotlin { jvmToolchain(21) }

repositories {
  // Needed to resolve plugin marker artifacts like org.beryx:badass-runtime-plugin
  gradlePluginPortal()
  mavenCentral()
}

dependencies {
  // Allow precompiled plugins to apply these without specifying versions in their scripts
  implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:${libs.versions.kotlin.get()}")
  implementation("com.diffplug.spotless:spotless-plugin-gradle:${libs.versions.spotless.get()}")
  // SonarQube plugin marker for precompiled convention plugin usage
  implementation("org.sonarqube:org.sonarqube.gradle.plugin:${libs.versions.sonarqube.get()}")
  // name.remal.sonarlint plugin marker so our convention plugin can apply it without a version
  implementation(
    "name.remal.sonarlint:name.remal.sonarlint.gradle.plugin:${libs.versions.remalSonarlint.get()}"
  )
  // SonarLint implementation API for typed configuration in precompiled plugin
  implementation(
    "name.remal.gradle-plugins.sonarlint:sonarlint:${libs.versions.remalSonarlint.get()}"
  )
}

tasks.withType<KotlinCompile>().configureEach {
  // Keep build-logic compatible with Gradle's embedded Kotlin
  compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
}
