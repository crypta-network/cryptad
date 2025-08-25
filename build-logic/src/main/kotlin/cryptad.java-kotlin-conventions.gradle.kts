import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  java
  id("org.jetbrains.kotlin.jvm")
}

java {
  sourceCompatibility = JavaVersion.VERSION_21
  targetCompatibility = JavaVersion.VERSION_21
}

repositories { mavenCentral() }

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

tasks.withType<JavaCompile>().configureEach { options.encoding = "UTF-8" }

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
  // Open JDK internals used by tests
  if (JavaVersion.current() >= JavaVersion.VERSION_1_9) {
    jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.io=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util.zip=ALL-UNNAMED")
  }
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
