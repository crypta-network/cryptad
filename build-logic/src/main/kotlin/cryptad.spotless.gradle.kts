plugins { id("com.diffplug.spotless") }

spotless {
  java {
    googleJavaFormat("1.28.0").reflowLongStrings()
    target("src/**/*.java")
    removeUnusedImports()
  }
  kotlin {
    target("**/*.kt")
    targetExclude("**/Version.kt")
    ktfmt().googleStyle()
    trimTrailingWhitespace()
    endWithNewline()
  }
  kotlinGradle {
    target("**/*.gradle.kts")
    ktfmt().googleStyle()
  }
}

// Format on Java compilation to keep sources tidy locally
tasks.named("compileJava") { dependsOn("spotlessApply") }
