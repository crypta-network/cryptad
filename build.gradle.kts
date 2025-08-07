import org.apache.tools.ant.filters.ReplaceTokens
import java.io.IOException
import java.security.MessageDigest

plugins {
    java
    `maven-publish`
    kotlin("jvm") version "2.2.0"
    id("nebula.release") version "21.0.0"
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:0.9.+")
    }
}

val provided by configurations.creating
val compile by configurations.creating

repositories {
    flatDir { dirs(uri("${projectDir}/lib")) }
    maven(url = "https://mvn.freenetproject.org") {
        metadataSources { artifact() }
    }
    mavenCentral()
}

sourceSets {
    val main by getting {
        java.srcDir("src/")
        kotlin.srcDir("src/")
        compileClasspath += configurations["provided"]
    }
    val test by getting {
        java.srcDir("test/")
        kotlin.srcDir("test/")
        compileClasspath += configurations["provided"]
    }
}

tasks.withType<JavaCompile> { options.encoding = "UTF-8" }
tasks.withType<Javadoc> { options.encoding = "UTF-8" }
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile>().configureEach {
    compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
}

val versionBuildDir = file("$projectDir/build/tmp/compileVersion/")
val versionSrc = "network/crypta/node/Version.java"

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
        filter<ReplaceTokens>(
            "tokens" to mapOf(
                "node_ver" to project.version.toString(),
                "pub_ver" to convertYyiToPublic(project.version.toString()),
                "git_rev" to gitrev,
            )
        )
    }
    into(versionBuildDir)
}

val compileVersion by tasks.registering(JavaCompile::class) {
    dependsOn(generateVersionSource, tasks.compileJava)
    setSource(versionBuildDir)
    include(versionSrc)
    classpath = files(sourceSets["main"].compileClasspath, sourceSets["main"].output.classesDirs)
    destinationDirectory.set(layout.buildDirectory.dir("java/version/"))
    sourceCompatibility = "21"
    targetCompatibility = "21"
}

val buildJar by tasks.registering(Jar::class) {
    // Ensure both Java and Kotlin compilation have run
    dependsOn(
        compileVersion,
        tasks.processResources,
        tasks.compileJava,
        tasks.named("compileKotlin")
    )

    // Include all compiled classes (Java + Kotlin) and processed resources
    from(sourceSets.main.get().output) {
        exclude("network/crypta/node/Version.class")
        exclude("network/crypta/node/Version$1.class")
    }

    from(compileVersion.get().destinationDirectory)

    archiveFileName.set("cryptad.jar")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    duplicatesStrategy = DuplicatesStrategy.FAIL
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

val copyResourcesToClasses2 by tasks.registering {
    inputs.files(sourceSets["main"].allSource)
    outputs.dir(layout.buildDirectory.dir("classes/java/main/"))
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
compileVersion { dependsOn(copyResourcesToClasses2) }

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
    implementation("org.bouncycastle:bcprov-jdk15on:1.59")
    implementation("net.java.dev.jna:jna:5.17.0")
    implementation("net.java.dev.jna:jna-platform:5.17.0")
    implementation("org.freenetproject:freenet-ext:29")
    implementation("io.pebbletemplates:pebble:3.1.5")
    implementation("org.unbescape:unbescape:1.1.6.RELEASE")
    implementation("org.slf4j:slf4j-api:1.7.25")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:1.9.5")
    testImplementation("org.hamcrest:hamcrest:3.0")
    testImplementation("org.objenesis:objenesis:1.0")
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
