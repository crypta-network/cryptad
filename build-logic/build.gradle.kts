import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  // Enables precompiled script plugins under src/main/kotlin
  `kotlin-dsl`
}

java {
  toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }
  sourceCompatibility = JavaVersion.VERSION_25
  targetCompatibility = JavaVersion.VERSION_25
}

kotlin { jvmToolchain(25) }

repositories {
  // Needed to resolve plugin marker artifacts like org.beryx:badass-runtime-plugin
  gradlePluginPortal()
  mavenCentral()
}

dependencies {
  // Portable archive normalization runs inside Gradle so distribution tasks remain Java-only.
  implementation(libs.commonsCompress)
  // Allow precompiled plugins to apply these without specifying versions in their scripts
  implementation("com.diffplug.spotless:spotless-plugin-gradle:${libs.versions.spotless.get()}")
  implementation(
    "com.github.spotbugs:com.github.spotbugs.gradle.plugin:${libs.versions.spotbugs.get()}"
  )
  implementation(
    "net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin:${libs.versions.errorpronePlugin.get()}"
  )
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
  compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_25)
}
