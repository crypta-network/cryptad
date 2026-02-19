import cryptad.SonarS8445ImportOrderFormatter

plugins { id("com.diffplug.spotless") }

spotless {
  java {
    googleJavaFormat("1.28.0").reflowLongStrings()
    target("src/**/*.java")
    removeUnusedImports()
    importOrder("module ", "", "\\#").wildcardsLast(false)
    // Enforce Sonar java:S8445 grouping globally:
    // module, on-demand package, single-type, static on-demand, single-static.
    custom("sonarS8445ImportOrder", SonarS8445ImportOrderFormatter)
  }
  kotlin {
    // Restrict to source trees rather than scanning entire repo to avoid special FS entries
    // created by Flatpak builder (e.g., .flatpak-builder/**/host/proc/**/map_files).
    target("src/**/*.kt")
    targetExclude("**/Version.kt")
    ktfmt("0.58").googleStyle()
    trimTrailingWhitespace()
    endWithNewline()
  }
  kotlinGradle {
    target("**/*.gradle.kts")
    // Avoid scanning generated build output (including Spotless' own working directories) and IDE
    // metadata which may contain non-UTF8 content or filenames.
    targetExclude("**/build/**")
    targetExclude("**/.gradle/**")
    targetExclude("**/.idea/**")
    ktfmt("0.58").googleStyle()
  }
}

// Format on Java compilation to keep sources tidy locally
tasks.named("compileJava") { dependsOn("spotlessApply") }
