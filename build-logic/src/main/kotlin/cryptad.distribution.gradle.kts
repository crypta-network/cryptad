import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

plugins { java }

val wrapperVersion = "3.6.2"
val wrapperDeltaPack = "wrapper-delta-pack-$wrapperVersion.tar.gz"
val wrapperBaseUrl =
  "https://sourceforge.net/projects/wrapper/files/wrapper/Wrapper_3.6.2_20250605/$wrapperDeltaPack/download"

val wrapperWorkDir = layout.buildDirectory.dir("wrapper")
val wrapperExtractDir = layout.buildDirectory.dir("wrapper/extracted")
val wrapperDistDir = layout.buildDirectory.dir("cryptad-dist")

// Windows wrapper binaries are not present in the delta pack. We fetch them from the latest
// release of crypta-network/wrapper-windows-build.
val wrapperWindowsRepo = "crypta-network/wrapper-windows-build"
val wrapperWindowsApiLatest =
  providers
    .gradleProperty("wrapperWinApiUrl")
    .orElse("https://api.github.com/repos/$wrapperWindowsRepo/releases/latest")
val wrapperWindowsWorkDir = layout.buildDirectory.dir("wrapper/windows")
val wrapperWindowsAmd64Zip = wrapperWindowsWorkDir.map { it.file("windows-amd64.tar.gz") }
val wrapperWindowsArm64Zip = wrapperWindowsWorkDir.map { it.file("windows-arm64.tar.gz") }
val wrapperWindowsAmd64Extract = wrapperWindowsWorkDir.map { it.dir("extracted-amd64") }
val wrapperWindowsArm64Extract = wrapperWindowsWorkDir.map { it.dir("extracted-arm64") }

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

// --- Windows wrapper: locate asset URLs (newest GitHub release) and download ---

abstract class DownloadWindowsWrapper @Inject constructor() : DefaultTask() {
  @get:Input abstract val apiUrl: Property<String>
  @get:Input @get:Optional abstract val amd64UrlOverride: Property<String>
  @get:Input @get:Optional abstract val arm64UrlOverride: Property<String>
  @get:OutputFile abstract val amd64Zip: RegularFileProperty
  @get:OutputFile abstract val arm64Zip: RegularFileProperty

  @TaskAction
  fun run() {
    amd64Zip.get().asFile.parentFile.mkdirs()
    arm64Zip.get().asFile.parentFile.mkdirs()

    val amd64Url =
      amd64UrlOverride.orNull?.takeIf { it.isNotBlank() }
        ?: findAssetUrl(apiUrl.get(), setOf("amd64", "x86_64", "x64"))
    val arm64Url =
      arm64UrlOverride.orNull?.takeIf { it.isNotBlank() }
        ?: findAssetUrl(apiUrl.get(), setOf("arm64", "aarch64"))

    download(amd64Url, amd64Zip.get().asFile)
    download(arm64Url, arm64Zip.get().asFile)
  }

  private fun httpGet(url: String): String {
    val conn = URL(url).openConnection() as HttpURLConnection
    // Optional: use GITHUB_TOKEN when present to raise rate limits
    val token = System.getenv("GITHUB_TOKEN")
    if (!token.isNullOrBlank()) conn.setRequestProperty("Authorization", "Bearer $token")
    conn.setRequestProperty("Accept", "application/vnd.github+json")
    conn.connectTimeout = 30_000
    conn.readTimeout = 30_000
    conn.inputStream.bufferedReader().use { br ->
      return br.readText()
    }
  }

  private fun findAssetUrl(apiUrl: String, archHints: Set<String>): String {
    val json = httpGet(apiUrl)
    // Very small JSON picker: find the first browser_download_url for Windows and the arch hints
    // We avoid adding a JSON parser dependency here.
    val re = Regex("""\"browser_download_url\"\s*:\s*\"([^\"]+)\"""", RegexOption.IGNORE_CASE)
    val all = re.findAll(json).map { it.groupValues[1] }.toList()
    val candidate =
      all.firstOrNull { u ->
        val l = u.lowercase()
        (l.endsWith(".zip") || l.endsWith(".tar.gz")) &&
          l.contains("win") &&
          archHints.any { hint -> l.contains(hint) }
      }
    if (candidate == null)
      throw GradleException("Could not find Windows asset for $archHints in $apiUrl")
    return candidate
  }

  private fun download(url: String, out: File) {
    val u = URL(url)
    println("Downloading $url -> ${out.absolutePath}")
    u.openStream().use { input ->
      Files.copy(input, out.toPath(), StandardCopyOption.REPLACE_EXISTING)
    }
  }
}

val downloadWindowsWrapper by
  tasks.registering(DownloadWindowsWrapper::class) {
    group = "distribution"
    description = "Downloads Windows wrapper (amd64 + arm64) from latest GitHub release"
    apiUrl.set(wrapperWindowsApiLatest)
    amd64UrlOverride.set(providers.gradleProperty("wrapperWinAmd64Url").orNull)
    arm64UrlOverride.set(providers.gradleProperty("wrapperWinArm64Url").orNull)
    amd64Zip.set(wrapperWindowsAmd64Zip)
    arm64Zip.set(wrapperWindowsArm64Zip)
  }

val extractWindowsWrapperAmd64 by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts Windows amd64 wrapper archive"
    dependsOn(downloadWindowsWrapper)
    from(tarTree(resources.gzip(wrapperWindowsAmd64Zip.get().asFile)))
    into(wrapperWindowsAmd64Extract)
  }

val extractWindowsWrapperArm64 by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts Windows arm64 wrapper archive"
    dependsOn(downloadWindowsWrapper)
    from(tarTree(resources.gzip(wrapperWindowsArm64Zip.get().asFile)))
    into(wrapperWindowsArm64Extract)
  }

// Copy Windows wrapper binaries into dist:
//  - bin/wrapper-windows-x86-64.exe and bin/wrapper-windows-arm-64.exe
//  - lib/wrapper-windows-x86-64.dll and lib/wrapper-windows-arm-64.dll
val copyWindowsWrapperBinaries by
  tasks.registering {
    group = "distribution"
    description = "Copies Windows wrapper executables and DLLs into the distribution"
    dependsOn(extractWindowsWrapperAmd64, extractWindowsWrapperArm64)
    doLast {
      val binDir = wrapperDistDir.get().dir("bin").asFile
      val libDir = wrapperDistDir.get().dir("lib").asFile
      binDir.mkdirs()
      libDir.mkdirs()

      fun pickExe(root: java.io.File): java.io.File? {
        val files =
          root.walkTopDown().filter { it.isFile && it.name.lowercase().endsWith(".exe") }.toList()
        // Prefer names starting with wrapper
        val preferred = files.firstOrNull { it.name.lowercase().startsWith("wrapper") }
        return preferred ?: files.firstOrNull()
      }

      fun pickDll(root: java.io.File): java.io.File? {
        val files =
          root.walkTopDown().filter { it.isFile && it.name.equals("wrapper.dll", true) }.toList()
        return files.firstOrNull()
      }

      // x86_64 (amd64)
      run {
        val from = wrapperWindowsAmd64Extract.get().asFile
        val exe = pickExe(from) ?: throw GradleException("No .exe found in $from")
        val dll = pickDll(from) ?: throw GradleException("No wrapper.dll found in $from")
        exe.copyTo(binDir.resolve("wrapper-windows-x86-64.exe"), overwrite = true)
        dll.copyTo(libDir.resolve("wrapper-windows-x86-64.dll"), overwrite = true)
      }

      // arm64
      run {
        val from = wrapperWindowsArm64Extract.get().asFile
        val exe = pickExe(from) ?: throw GradleException("No .exe found in $from")
        val dll = pickDll(from) ?: throw GradleException("No wrapper.dll found in $from")
        exe.copyTo(binDir.resolve("wrapper-windows-arm-64.exe"), overwrite = true)
        dll.copyTo(libDir.resolve("wrapper-windows-arm-64.dll"), overwrite = true)
      }
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
    // Capture template file at configuration time to avoid Task.project access at execution
    val confTemplate = layout.projectDirectory.file("src/main/templates/wrapper.conf.tpl")
    doLast {
      val confDirFile = confDir.get().asFile
      confDirFile.mkdirs()
      val template = confTemplate.asFile.readText()
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
    outputs.files(binDir.map { it.file("cryptad") }, binDir.map { it.file("cryptad.bat") })
    // Resolve inputs up front (configuration time) to be config-cache friendly
    val launcherTemplateUnix =
      layout.projectDirectory.file("src/main/templates/cryptad-launcher.sh.tpl")
    val launcherTemplateBat =
      layout.projectDirectory.file("src/main/templates/cryptad-launcher.bat.tpl")
    val mainScriptTemplate = layout.projectDirectory.file("src/main/templates/cryptad.sh.tpl")
    val mainScriptBatTemplate = layout.projectDirectory.file("src/main/templates/cryptad.bat.tpl")
    val dummyCryptad = layout.projectDirectory.file("tools/cryptad-dummy.sh")
    val useDummy = providers.gradleProperty("useDummyCryptad").map { it.toBoolean() }.orElse(false)
    doLast {
      val bin = binDir.get().asFile
      bin.mkdirs()
      val unix = bin.resolve("cryptad")
      val templateL = mainScriptTemplate.asFile.readText()
      unix.writeText(templateL)
      // Ensure executable for all, plus readable for all
      unix.setReadable(true, false)
      unix.setExecutable(true, false)

      // Windows main script
      val winBat = bin.resolve("cryptad.bat")
      val tmplBatMain = mainScriptBatTemplate.asFile
      if (!tmplBatMain.isFile) throw GradleException("Missing template: ${tmplBatMain.path}")
      winBat.writeText(tmplBatMain.readText())

      // --- Generate Swing launcher start scripts (Unix + Windows) ---
      val launcherUnix = bin.resolve("cryptad-launcher")
      val launcherBat = bin.resolve("cryptad-launcher.bat")

      val tmplUnix = launcherTemplateUnix.asFile
      val tmplBat = launcherTemplateBat.asFile
      if (!tmplUnix.isFile) throw GradleException("Missing template: ${tmplUnix.path}")
      if (!tmplBat.isFile) throw GradleException("Missing template: ${tmplBat.path}")

      launcherUnix.writeText(tmplUnix.readText())
      launcherUnix.setReadable(true, false)
      launcherUnix.setExecutable(true, false)
      launcherBat.writeText(tmplBat.readText())

      // Templates are authoritative; no inline fallbacks remain.

      // Optional dev aid: override cryptad with a dummy script when -PuseDummyCryptad=true
      if (useDummy.get()) {
        val dummy = dummyCryptad.asFile
        if (dummy.isFile) {
          println("Overriding bin/cryptad with tools/cryptad-dummy.sh for testing")
          unix.writeText(dummy.readText())
          unix.setReadable(true, false)
          unix.setExecutable(true, false)
        } else {
          println("WARNING: -PuseDummyCryptad was set but tools/cryptad-dummy.sh not found")
        }
      }
    }
  }

// Top-level task to assemble the distribution tree
val assembleCryptadDist by
  tasks.registering {
    group = "distribution"
    description = "Assembles a portable Cryptad distribution under build/cryptad-dist"
    dependsOn(
      copyWrapperBinaries,
      copyWindowsWrapperBinaries,
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
