import java.net.URI
import java.nio.file.Files
import java.nio.file.StandardCopyOption

plugins { java }

val wrapperVersion = "3.6.2"
val wrapperDeltaPack = "wrapper-delta-pack-$wrapperVersion.tar.gz"
val wrapperBaseUrl =
  "https://sourceforge.net/projects/wrapper/files/wrapper/Wrapper_3.6.2_20250605/$wrapperDeltaPack/download"

val wrapperWorkDir = layout.buildDirectory.dir("wrapper")
val wrapperExtractDir = layout.buildDirectory.dir("wrapper/extracted")
val wrapperDistDir = layout.buildDirectory.dir("cryptad-dist")

// Seednodes generation settings
val seedrefsZipUrl = "https://codeload.github.com/hyphanet/seedrefs/zip/refs/heads/master"
val seedrefsWorkDir = layout.buildDirectory.dir("seedrefs")
val seedrefsZip = seedrefsWorkDir.map { it.file("seedrefs.zip") }
val seedrefsExtracted = seedrefsWorkDir.map { it.dir("extracted") }
val seednodesOut = layout.buildDirectory.file("generated/seednodes/seednodes.fref")

// Download the Wrapper delta pack
val downloadWrapper by
  tasks.registering {
    group = "distribution"
    description = "Downloads Tanuki Java Service Wrapper delta pack"
    val outFile = wrapperWorkDir.map { it.file(wrapperDeltaPack) }
    outputs.file(outFile)
    doLast {
      val target = outFile.get().asFile
      target.parentFile.mkdirs()
      val url = URI(wrapperBaseUrl).toURL()
      println("Downloading $wrapperBaseUrl -> " + target.absolutePath)
      url.openStream().use { input ->
        Files.copy(input, target.toPath(), StandardCopyOption.REPLACE_EXISTING)
      }
    }
  }

// Extract the delta pack
val extractWrapper by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts the Tanuki Wrapper delta pack"
    dependsOn(downloadWrapper)
    val tarFile = wrapperWorkDir.map { it.file(wrapperDeltaPack) }
    from(tarTree(resources.gzip(tarFile)))
    into(wrapperExtractDir)
  }

// Download seedrefs (zip of repo)
val downloadSeedrefs by
  tasks.registering {
    group = "distribution"
    description = "Downloads hyphanet/seedrefs repository as a zip"
    outputs.file(seedrefsZip)
    doLast {
      val out = seedrefsZip.get().asFile
      out.parentFile.mkdirs()
      val url = URI(seedrefsZipUrl).toURL()
      println("Downloading $seedrefsZipUrl -> " + out.absolutePath)
      url.openStream().use { input ->
        Files.copy(input, out.toPath(), StandardCopyOption.REPLACE_EXISTING)
      }
    }
  }

// Extract seedrefs
val extractSeedrefs by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts seedrefs zip"
    dependsOn(downloadSeedrefs)
    from(zipTree(seedrefsZip.get().asFile))
    into(seedrefsExtracted)
  }

// Concatenate all seedrefs files into one seednodes.fref
val generateSeednodesFile by
  tasks.registering {
    group = "distribution"
    description = "Generates seednodes.fref from hyphanet/seedrefs"
    dependsOn(extractSeedrefs)
    outputs.file(seednodesOut)
    doLast {
      val root = seedrefsExtracted.get().asFile
      val outFile = seednodesOut.get().asFile
      outFile.parentFile.mkdirs()
      val files = root.walkTopDown().filter { it.isFile }.sortedBy { it.name.lowercase() }.toList()
      if (files.isEmpty()) throw GradleException("No files found in extracted seedrefs")
      outFile.printWriter().use { pw ->
        files.forEach { f ->
          val content = f.readText()
          pw.println(content.trim())
          pw.println()
        }
      }
      println(
        "Generated seednodes file at " + outFile.absolutePath + " with " + files.size + " entries"
      )
    }
  }

// Copy platform wrapper binaries and helper files under bin/
val copyWrapperBinaries by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Copies Wrapper binaries into distribution bin/"
    dependsOn(extractWrapper)
    into(wrapperDistDir.map { it.dir("bin") })
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/bin") }) {
      include("*")
      // Drop unsupported platforms and demos
      exclude("*aix*", "*hpux*", "*linux-ppcle*", "*solaris*", "*freebsd*", "*windows*")
      exclude("**/*.bat", "README.txt", "demoapp*", "testwrapper*")
      exclude("Install*", "Uninstall*", "Start*", "Stop*", "Pause*", "Resume*", "Query*")
      // Drop 32-bit binaries
      exclude("*-x86-32*", "*-universal-32*", "*-armel-32*", "*-armhf-32*")
    }
  }

// Copy runtime jars into lib/ and build a classpath list for wrapper.conf
val prepareWrapperLibs by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Copies runtime jars to lib/ for the wrapper distribution"
    dependsOn(tasks.named("buildJar"), extractWrapper)
    into(wrapperDistDir.map { it.dir("lib") })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath) { exclude("**/wrapper*.jar") }
    from(tasks.named("buildJar")) { rename { "cryptad.jar" } }
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/lib") }) {
      include("*")
      exclude(
        "**/*.dll",
        "**/*aix*",
        "**/*hpux*",
        "**/*solaris*",
        "**/*freebsd*",
        "**/*windows*",
        "**/*-ppcle-*",
      )
      exclude("**/*demo*.*", "**/*test*.*")
      exclude(
        "**/*-x86-32.*",
        "**/*-universal-32.*",
        "**/*-armel-32.*",
        "**/*-armhf-32.*",
        "**/*-32.*",
      )
    }
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/lib") }) {
      include("wrapper*.jar")
      rename { "wrapper.jar" }
    }
  }

// Generate conf/wrapper.conf from template
val generateWrapperConf by
  tasks.registering {
    group = "distribution"
    description = "Generates conf/wrapper.conf from template"
    dependsOn(prepareWrapperLibs)
    val confDir = wrapperDistDir.map { it.dir("conf") }
    outputs.file(confDir.map { it.file("wrapper.conf") })
    doLast {
      val confDirFile = confDir.get().asFile
      confDirFile.mkdirs()
      val template = file("src/main/templates/wrapper.conf.tpl").readText()
      val confFile = confDirFile.resolve("wrapper.conf")
      confFile.writeText(template)
      println("Generated " + confFile.absolutePath)
    }
  }

// Generate bin/cryptad launcher from template
val generateWrapperLaunchers by
  tasks.registering {
    group = "distribution"
    description = "Generates launch scripts from templates"
    dependsOn(copyWrapperBinaries)
    val binDir = wrapperDistDir.map { it.dir("bin") }
    outputs.files(binDir.map { it.file("cryptad") })
    doLast {
      val bin = binDir.get().asFile
      bin.mkdirs()
      val unix = bin.resolve("cryptad")
      val templateL = file("src/main/templates/cryptad.sh.tpl").readText()
      unix.writeText(templateL)
      // Ensure executable for all, plus readable for all
      unix.setReadable(true, false)
      unix.setExecutable(true, false)
    }
  }

// Top-level task to assemble the distribution tree
val assembleCryptadDist by
  tasks.registering {
    group = "distribution"
    description = "Assembles a portable Cryptad distribution under build/cryptad-dist"
    dependsOn(
      copyWrapperBinaries,
      prepareWrapperLibs,
      generateWrapperConf,
      generateWrapperLaunchers,
    )
    doLast {
      println("Cryptad distribution assembled at: ${wrapperDistDir.get().asFile.absolutePath}")
    }
  }

val cleanCryptadDist by
  tasks.registering(Delete::class) {
    group = "distribution"
    description = "Cleans the Cryptad distribution directory"
    delete(wrapperDistDir)
    delete(layout.buildDirectory.dir("wrapper-dist"))
  }

tasks.named("assembleCryptadDist") { dependsOn(cleanCryptadDist) }

copyWrapperBinaries { dependsOn(cleanCryptadDist) }

prepareWrapperLibs { dependsOn(cleanCryptadDist) }

generateWrapperConf { dependsOn(cleanCryptadDist) }

generateWrapperLaunchers { dependsOn(cleanCryptadDist) }

// Package the distribution as tar.gz with a clean, portable name
tasks.register<Tar>("distTarCryptad") {
  group = "distribution"
  description = "Packages the Cryptad distribution as a tar.gz"
  dependsOn(assembleCryptadDist)
  compression = Compression.GZIP
  // Produce cryptad-<version>.tar.gz (avoid the previous -dist suffix)
  archiveBaseName.set("cryptad")
  // Prefix version with 'v' in the filename
  archiveVersion.set("v${project.version}")
  // Ensure .tar.gz extension across Gradle versions
  archiveFileName.set("cryptad-v${project.version}.tar.gz")
  from(wrapperDistDir)
  destinationDirectory.set(layout.buildDirectory.dir("distributions"))
  isPreserveFileTimestamps = true
  isReproducibleFileOrder = true
}

// Package the same distribution as a ZIP for broad platform compatibility
tasks.register<Zip>("distZipCryptad") {
  group = "distribution"
  description = "Packages the Cryptad distribution as a zip"
  dependsOn(assembleCryptadDist)
  archiveBaseName.set("cryptad")
  // Prefix version with 'v' in the filename
  archiveVersion.set("v${project.version}")
  archiveFileName.set("cryptad-v${project.version}.zip")
  from(wrapperDistDir)
  destinationDirectory.set(layout.buildDirectory.dir("distributions"))
  isPreserveFileTimestamps = true
  isReproducibleFileOrder = true
}

// Aggregate distribution lifecycle task
val dist by
  tasks.registering {
    group = "distribution"
    description = "Builds all Cryptad distribution artifacts (tar.gz and zip)"
    dependsOn("distTarCryptad", "distZipCryptad")
  }

// Ensure standard build also produces the distribution archives
tasks.named("build") { dependsOn(dist) }

// Diagnostic: print resolved directories
tasks.register<JavaExec>("printDirs") {
  group = "help"
  description = "Print resolved Cryptad directories (config, data, cache, run, logs)"
  dependsOn("classes")
  mainClass.set("network.crypta.tools.PrintDirsKt")
  classpath = sourceSets.main.get().runtimeClasspath
  systemProperties(gradle.startParameter.systemPropertiesArgs)
}

// Resource copies required by legacy tests and runtime expectations
val copyResourcesToClasses2 by
  tasks.registering {
    inputs.files(sourceSets["main"].allSource)
    outputs.dir(layout.buildDirectory.dir("classes/java/main/"))
    dependsOn(tasks.named("generateVersionSource"))
    doLast {
      copy {
        from(sourceSets["main"].allSource)
        into(layout.buildDirectory.dir("classes/java/main/"))
        include("network/crypta/l10n/*properties")
        include("network/crypta/l10n/iso-*.tab")
        include("network/crypta/clients/http/staticfiles/**")
        include("network/crypta/clients/http/templates/**")
        include("../dependencies.properties")
      }
      copy {
        from(projectDir)
        into(layout.buildDirectory.dir("classes/java/main/"))
        include("dependencies.properties")
      }
    }
  }

tasks.processResources {
  dependsOn(copyResourcesToClasses2)
  dependsOn(generateSeednodesFile)
  from(seednodesOut) {
    into("seednodes")
    rename { "seednodes.fref" }
  }
}

val copyTestResourcesToClasses2 by
  tasks.registering {
    inputs.files(sourceSets["test"].allSource)
    outputs.dir(layout.buildDirectory.dir("classes/java/test/"))
    doLast {
      copy {
        from(sourceSets["test"].allSource)
        into(layout.buildDirectory.dir("classes/java/test/"))
        include("network/crypta/client/filter/*/**")
        include("network/crypta/crypt/ciphers/rijndael-gladman-test-data/**")
        include("network/crypta/l10n/*properties")
        include("network/crypta/clients/http/templates/**")
      }
    }
  }

tasks.compileTestJava { dependsOn(copyResourcesToClasses2, copyTestResourcesToClasses2) }

// Build a source release, excluding build directories
tasks.register<Tar>("tar") {
  group = "distribution"
  description = "Build a source release, excluding build directories and Gradle caches"
  compression = Compression.BZIP2
  archiveBaseName.set("freenet-sources")
  from(project.rootDir) { exclude("**/build", "build", ".gradle") }
  into(archiveBaseName.get())
  isPreserveFileTimestamps = true
  isReproducibleFileOrder = true
  destinationDirectory.set(layout.buildDirectory)
  archiveFileName.set("${archiveBaseName.get()}.tgz")
  doLast {
    ant.invokeMethod(
      "checksum",
      mapOf("file" to "${destinationDirectory.get()}/${archiveFileName.get()}"),
    )
  }
}
