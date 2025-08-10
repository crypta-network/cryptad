import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.io.IOException
import java.security.MessageDigest

plugins {
    java
    `maven-publish`
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.nebulaRelease)
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

val provided by configurations.creating
val compile by configurations.creating

val versionBuildDir = file("$projectDir/build/tmp/compileVersion/")
val versionSrc = "network/crypta/node/Version.kt"

repositories {
    flatDir { dirs(uri("${projectDir}/lib")) }
    maven(url = "https://mvn.freenetproject.org") {
        metadataSources { artifact() }
    }
    mavenCentral()
}

sourceSets {
    val main by getting {
        // Rely on Gradle's default directories (src/main/java, src/main/resources)
        // Exclude the templated Version.kt from direct compilation
        java.exclude("network/crypta/node/Version.kt")
        kotlin.exclude("**/Version.kt")
        // Preserve provided configuration on classpaths
        compileClasspath += configurations["provided"]
    }
    val test by getting {
        // Rely on Gradle's default directories (src/test/java, src/test/resources)
        compileClasspath += configurations["provided"]
    }
}

tasks.withType<JavaCompile> { options.encoding = "UTF-8" }
tasks.withType<Javadoc> { options.encoding = "UTF-8" }
tasks.withType<KotlinCompile>().configureEach {
    compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
}

val gitrev: String = try {
    val cmd = "git describe --always --abbrev=4 --dirty"
    Runtime.getRuntime().exec(cmd, null, rootDir).inputStream.bufferedReader().readText().trim()
} catch (e: IOException) {
    "@unknown@"
}

/**
 * Converts a version string from the internal "YYI+SemVer" format to a
 * consumer-friendly version string.
 *
 * The conversion follows these rules:
 * 1. The YYI major version (e.g., `251`) is always converted to a four-digit
 *    year and an index (e.g., `2025.1`).
 * 2. If the original minor version is `0`, it is omitted from the output.
 * 3. If the minor version is not `0`, it is included.
 * 4. If the patch version is `0` or if the minor version was `0`, the patch
 *    version is omitted from the output. Otherwise, it is included.
 *
 * @param version The source version string in "YYI.minor.patch" format (e.g., "251.1.0").
 * @return The converted, consumer-friendly version string.
 *         Returns the original input string if it cannot be parsed.
 */
fun convertYyiToPublic(version: String): String {
    try {
        val parts = version.split('.')
        if (parts.size != 3) {
            return version // Not a valid SemVer format
        }

        val yyiStr = parts[0]
        val minor = parts[1].toInt()
        val patch = parts[2].toInt()

        if (yyiStr.length < 3) {
            return version // YYI string is too short
        }

        // Extract YY (e.g., "25") and I (e.g., "1") from YYI ("251")
        val yy = yyiStr.substring(0, 2).toInt()
        val i = yyiStr.substring(2).toInt()

        val year = 2000 + yy
        val baseVersion = "$year.$i"

        // Apply the final, refined rules
        return when {
            minor == 0 -> baseVersion // If minor is 0, ignore minor and patch
            patch == 0 -> "$baseVersion.$minor" // If minor != 0 but patch is 0, ignore patch
            else -> "$baseVersion.$minor.$patch" // If neither are 0, include everything
        }
    } catch (e: Exception) {
        // Catch parsing errors (NumberFormatException, IndexOutOfBoundsException)
        return version
    }
}

val generateVersionSource by tasks.registering(Copy::class) {
    from(sourceSets["main"].java.srcDirs) {
        include(versionSrc)
        filter { line: String ->
            line.replace("@node_ver@", project.version.toString())
                .replace("@pub_ver@", convertYyiToPublic(project.version.toString()))
                .replace("@git_rev@", gitrev)
        }
    }
    into(versionBuildDir)
}

tasks.named<KotlinCompile>("compileKotlin") {
    dependsOn(generateVersionSource)
    source(versionBuildDir)
}

val buildJar by tasks.registering(Jar::class) {
    // Ensure both Java and Kotlin compilation have run
    dependsOn(
        tasks.processResources,
        tasks.compileJava,
        tasks.named("compileKotlin")
    )

    // Include compiled classes (Java + Kotlin) and resources explicitly to avoid duplicates
    from(sourceSets.main.get().output.classesDirs)
    from(sourceSets.main.get().resources)

    archiveFileName.set("cryptad.jar")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    // Some resources may appear in multiple outputs; exclude duplicates deterministically
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes(
            "Permissions" to "all-permissions",
            "Application-Name" to "Crypta Daemon",
            "Required-Ext-Version" to 29,
            "Recommended-Ext-Version" to 29,
            "Compiled-With" to "${System.getProperty("java.version")} (${System.getProperty("java.vendor")})",
            "Specification-Title" to "Crypta",
            "Specification-Version" to project.version.toString(),
            "Specification-Vendor" to "crypta.network",
            "Implementation-Title" to "Crypta",
            "Implementation-Version" to "${project.version} $gitrev",
            "Implementation-Vendor" to "crypta.network"
        )
    }
}

tasks.named<Jar>("jar") {
    enabled = false
    dependsOn(buildJar)
}

val jars = mutableListOf<File>()

gradle.addListener(object : TaskExecutionListener {
    override fun afterExecute(task: Task, state: TaskState) {
        if (task is AbstractArchiveTask && task.enabled) {
            jars.add(task.outputs.files.singleFile)
        }
    }

    override fun beforeExecute(task: Task) {}
})

gradle.addBuildListener(object : BuildAdapter() {
    override fun buildFinished(result: BuildResult) {
        if (jars.isNotEmpty()) {
            fun hash(file: File) {
                val sha256 = MessageDigest.getInstance("SHA-256")
                file.inputStream().use { input ->
                    val buffer = ByteArray(4096)
                    while (true) {
                        val read = input.read(buffer)
                        if (read == -1) break
                        sha256.update(buffer, 0, read)
                    }
                }
                println("SHA-256 of ${file.name}: " + sha256.digest().joinToString("") { "%02x".format(it) })
            }
            jars.forEach { hash(it) }
        }
    }
})

tasks.test {
    // Point tests expecting old layout to new standard resource locations
    systemProperty("test.l10npath_test", "src/test/resources/network/crypta/l10n/")
    systemProperty("test.l10npath_main", "src/main/resources/network/crypta/l10n/")
}

val copyResourcesToClasses2 by tasks.registering {
    inputs.files(sourceSets["main"].allSource)
    outputs.dir(layout.buildDirectory.dir("classes/java/main/"))
    dependsOn(generateVersionSource)
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

tasks.processResources { dependsOn(copyResourcesToClasses2) }

val copyTestResourcesToClasses2 by tasks.registering {
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

tasks.test {
    if (JavaVersion.current() >= JavaVersion.VERSION_1_9) {
        jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
        jvmArgs("--add-opens=java.base/java.util=ALL-UNNAMED")
        jvmArgs("--add-opens=java.base/java.io=ALL-UNNAMED")
        jvmArgs("--add-opens=java.base/java.util.zip=ALL-UNNAMED")
    }
    minHeapSize = "128m"
    maxHeapSize = "512m"
    include("network/crypta/**/*Test.class")
    exclude("network/crypta/**/*${'$'}*Test.class")
    systemProperties.putAll(mapOf<String, Any>())
}

tasks.withType<Test> { enableAssertions = false }

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = "org.freenetproject"
            artifactId = "fred"
            version = gitrev
            from(components["java"])
        }
    }
    repositories {
        maven {
            url = uri("s3://mvn.freenetproject.org/")
            credentials(AwsCredentials::class) {
                accessKey = System.getenv("AWS_ACCESS_KEY_ID")
                secretKey = System.getenv("AWS_SECRET_ACCESS_KEY")
            }
        }
    }
}

val copyRuntimeLibs by tasks.registering(Copy::class) {
    into("${'$'}{buildDir}/output/")
    from(configurations.runtimeClasspath)
    from(tasks.jar)
}

copyRuntimeLibs { dependsOn(tasks.jar) }

dependencies {
    implementation(libs.bcprov)
    implementation(libs.bcpkix)
    implementation(libs.jna)
    implementation(libs.jnaPlatform)
    implementation(libs.freenetExt)
    implementation(libs.pebble)
    implementation(libs.unbescape)
    implementation(libs.slf4jApi)

    testImplementation(libs.junit4)
    testImplementation(libs.mockitoCore)
    testImplementation(libs.hamcrest)
    testImplementation(libs.objenesis)
}

val tar by tasks.registering(Tar::class) {
    description = "Build a source release, specifically excluding the build directories and gradle wrapper files"
    compression = Compression.BZIP2
    archiveBaseName.set("freenet-sources")
    from(project.rootDir) {
        exclude("**/build")
        exclude("build")
        exclude(".gradle")
    }
    into(archiveBaseName.get())
    isPreserveFileTimestamps = true
    isReproducibleFileOrder = true
    destinationDirectory.set(file("${'$'}{project.buildDir}"))
    archiveFileName.set("${'$'}{archiveBaseName.get()}.tgz")
    doLast {
        ant.invokeMethod(
            "checksum",
            mapOf("file" to "${'$'}{destinationDirectory.get()}/${'$'}{archiveFileName.get()}")
        )
    }
}

tasks.javadoc {
    isFailOnError = false
}
