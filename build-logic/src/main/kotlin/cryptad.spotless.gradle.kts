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
    ktfmt("0.58").googleStyle()
    trimTrailingWhitespace()
    endWithNewline()
  }
  kotlinGradle {
    target("**/*.gradle.kts")
    ktfmt("0.58").googleStyle()
  }
}

// Format on Java compilation to keep sources tidy locally
tasks.named("compileJava") { dependsOn("spotlessApply") }
