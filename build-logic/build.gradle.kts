import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  // Enables precompiled script plugins under src/main/kotlin
  `kotlin-dsl`
}

java {
  // Use Java 21 toolchain for build logic
  toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
  sourceCompatibility = JavaVersion.VERSION_21
  targetCompatibility = JavaVersion.VERSION_21
}

kotlin { jvmToolchain(21) }

repositories { mavenCentral() }

dependencies {
  // Allow precompiled plugins to apply these without specifying versions in their scripts
  implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:${libs.versions.kotlin.get()}")
  implementation("com.diffplug.spotless:spotless-plugin-gradle:${libs.versions.spotless.get()}")
}

// Align Kotlin JVM target with Java 21 for build-logic itself
tasks.withType<KotlinCompile>().configureEach {
  compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
}
