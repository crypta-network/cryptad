import java.math.BigDecimal
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.getByType
import org.gradle.testing.jacoco.plugins.JacocoPluginExtension
import org.gradle.testing.jacoco.tasks.JacocoCoverageVerification
import org.gradle.testing.jacoco.tasks.JacocoReport
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  java
  id("org.jetbrains.kotlin.jvm")
  jacoco
}

java {
  sourceCompatibility = JavaVersion.VERSION_21
  targetCompatibility = JavaVersion.VERSION_21
}

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

// Allow Kotlin sources to live under src/main/java and src/test/java, and exclude Version.kt
extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinProjectExtension>(
  org.jetbrains.kotlin.gradle.dsl.KotlinProjectExtension::class
) {
  sourceSets.getByName("main").kotlin.srcDir("src/main/java")
  sourceSets.getByName("test").kotlin.srcDir("src/test/java")
  sourceSets.named("main") { kotlin.exclude("**/Version.kt") }
}

sourceSets.named("main") {
  // Exclude templated Version.kt from direct Java compilation
  java.exclude("network/crypta/node/Version.kt")
}

tasks.withType<JavaCompile>().configureEach {
  options.encoding = "UTF-8"
  // Surface deprecation/unchecked sites explicitly during compilation.
  options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-Xlint:unchecked"))
}

tasks.withType<Javadoc>().configureEach {
  options.encoding = "UTF-8"
  isFailOnError = false
}

tasks.withType<KotlinCompile>().configureEach {
  compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
}

// Ensure Kotlin sources compile before Java when Java depends on Kotlin types
tasks.named("compileJava") { dependsOn(tasks.named("compileKotlin")) }

// Tests: settings and module opens needed at runtime
tasks.withType<Test>().configureEach {
  useJUnitPlatform()
  // Verbose failures: full exception stack traces/causes for easier debugging
  testLogging { exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
  // Open JDK internals used by tests
  if (JavaVersion.current() >= JavaVersion.VERSION_1_9) {
    jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.io=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util.zip=ALL-UNNAMED")
  }
  // Allow dynamic agent loading for Mockito inline mock-maker (JEP 451).
  jvmArgs("-XX:+EnableDynamicAgentLoading")
  minHeapSize = "128m"
  maxHeapSize = "512m"
  include("network/crypta/**/*Test.class")
  exclude("network/crypta/**/*$*Test.class")
  // Point tests expecting old layout to new standard resource locations
  systemProperty("test.l10npath_test", "src/test/resources/network/crypta/l10n/")
  systemProperty("test.l10npath_main", "src/main/resources/network/crypta/l10n/")
}

// Match prior behavior: disable assertions in tests
tasks.withType<Test>().configureEach { enableAssertions = false }

// JaCoCo setup: use a recent agent and produce XML for Sonar
// Version is sourced from the version catalog (gradle/libs.versions.toml: [versions].jacoco)
val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

extensions.configure<JacocoPluginExtension>("jacoco") {
  toolVersion = libs.findVersion("jacoco").get().requiredVersion
}

// Generate XML + HTML reports; ensure reports run after tests
tasks.withType<JacocoReport>().configureEach {
  dependsOn(tasks.withType<Test>())
  reports {
    xml.required.set(true)
    csv.required.set(false)
    html.required.set(true)
  }
}

// Enforce coverage threshold (80% minimum)
tasks.withType<JacocoCoverageVerification>().configureEach {
  dependsOn(tasks.withType<Test>())
  violationRules {
    // Do not fail the build on coverage violations; still log them
    isFailOnViolation = false
    rule {
      limit {
        counter = "LINE"
        value = "COVEREDRATIO"
        minimum = BigDecimal("0.80")
      }
    }
  }
}

// Integrate coverage checks with the standard lifecycle
tasks.named("check") {
  dependsOn(tasks.withType<JacocoReport>())
  dependsOn(tasks.withType<JacocoCoverageVerification>())
}
